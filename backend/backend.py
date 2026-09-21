import asyncio
import hashlib
import re
import threading
import time
from pathlib import Path

import serial
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel


# ============================================================
# CIPHER-M BACKEND
# ESP32 USB SERIAL <-> PYTHON <-> REACT DASHBOARD
# ============================================================

SERIAL_PORT = "COM8"
BAUD_RATE = 115200

# IMPORTANT:
# Keep this exactly consistent with the working ESP32 AES implementation.
# This is a DEMO/session master key, not production key management.
AES_MASTER_KEY = b"CIPHER_M_AES_MASTER_2026"

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"

serial_connection = None
serial_lock = threading.Lock()
serial_running = False
serial_thread = None

event_loop = None
websocket_clients = set()
state_lock = threading.Lock()

backend_started_at = time.time()

system_state = {
    "esp32": "OFFLINE",
    "blue_pill": "UNKNOWN",
    "uart": "DISCONNECTED",

    "packet_id": 0,
    "authenticated": "UNKNOWN",
    "threat": "UNKNOWN",
    "policy": "UNKNOWN",

    "algorithm": "UNKNOWN",
    "key_version": 0,
    "key_fingerprint": "",

    "gas": None,
    "gas_status": "UNKNOWN",

    "iv": "",
    "encrypted_data": "",
    "decrypted_data": "",

    "packets_total": 0,
    "packets_verified": 0,
    "packets_rejected": 0,
    "attacks": 0,

    "crypto_status": "IDLE",
    "action": "WAITING",

    "system_banner": "SYSTEM STARTING",
    "key_rotated": False,

    "uptime_seconds": 0,

    "traffic": [],
    "events": [],
}


class AttackRequest(BaseModel):
    level: int


# ============================================================
# STATE / EVENTS
# ============================================================

def add_event(message: str, event_type: str = "info"):
    event = {
        "time": time.strftime("%H:%M:%S"),
        "message": message,
        "type": event_type,
    }

    with state_lock:
        system_state["events"].insert(0, event)
        system_state["events"] = system_state["events"][:100]

    notify_dashboard()


def notify_dashboard():
    if event_loop is None:
        return

    try:
        asyncio.run_coroutine_threadsafe(
            broadcast_state(),
            event_loop,
        )
    except Exception:
        pass


def get_state():
    with state_lock:
        state = dict(system_state)
        state["traffic"] = [dict(x) for x in system_state["traffic"]]
        state["events"] = [dict(x) for x in system_state["events"]]
        return state


async def broadcast_state():
    if not websocket_clients:
        return

    payload = get_state()
    dead = []

    for websocket in list(websocket_clients):
        try:
            await websocket.send_json(payload)
        except Exception:
            dead.append(websocket)

    for websocket in dead:
        websocket_clients.discard(websocket)


def upsert_traffic(packet_id: int, **updates):
    with state_lock:
        found = None

        for packet in system_state["traffic"]:
            if packet["id"] == packet_id:
                found = packet
                break

        if found is None:
            found = {
                "id": packet_id,
                "received_at": time.time(),
                "authenticated": "UNKNOWN",
                "threat": "UNKNOWN",
                "policy": "UNKNOWN",
                "algorithm": "UNKNOWN",
                "key_version": 0,
                "gas": None,
                "gas_status": "UNKNOWN",
                "encrypted": False,
                "action": "WAITING",
            }
            system_state["traffic"].insert(0, found)

        found.update(updates)
        system_state["traffic"] = system_state["traffic"][:60]


# ============================================================
# AES
# ============================================================

def derive_aes_key(policy: str, key_version: int, key_length: int) -> bytes:
    material = (
        AES_MASTER_KEY.decode()
        + "|"
        + policy
        + "|V="
        + str(key_version)
    ).encode()

    return hashlib.sha256(material).digest()[:key_length]


def remove_pkcs7_padding(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty plaintext")

    padding = data[-1]

    if padding < 1 or padding > 16:
        raise ValueError("Invalid PKCS#7 padding")

    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-padding]


def decrypt_aes(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )

    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    return remove_pkcs7_padding(padded)


# ============================================================
# PARSERS
# ============================================================

def parse_security_response(line: str):
    match = re.search(
        r"SECURITY,PKT=(\d+),(VALID|INVALID),"
        r"(LOW|MEDIUM|HIGH|CRITICAL),"
        r"(LIGHTWEIGHT|NORMAL|ENHANCED|PARANOID)",
        line,
    )

    if not match:
        return None

    return {
        "packet_id": int(match.group(1)),
        "authenticated": match.group(2),
        "threat": match.group(3),
        "policy": match.group(4),
    }


def parse_packet(packet: str):
    packet_match = re.search(
        r"PKT,1\.0,MAIN_01,(\d+),(\d+)",
        packet,
    )

    gas_match = re.search(r"GAS=(\d+)", packet)
    gas_status_match = re.search(r"GAS_STATUS=([A-Z]+)", packet)

    return {
        "packet_id": int(packet_match.group(1)) if packet_match else 0,
        "uptime_ms": int(packet_match.group(2)) if packet_match else 0,
        "gas": int(gas_match.group(1)) if gas_match else None,
        "gas_status": gas_status_match.group(1) if gas_status_match else "UNKNOWN",
    }


def parse_encrypted_frame(line: str):
    if not line.startswith("ENCRYPTED,"):
        return None

    values = {}

    for field in line.strip().split(",")[1:]:
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        values[key] = value

    required = ["PKT", "POLICY", "ALG", "KEYVER", "IV", "DATA"]

    for field in required:
        if field not in values:
            raise ValueError(f"Missing encrypted field: {field}")

    return values


# ============================================================
# SERIAL MESSAGE PROCESSING
# ============================================================

def process_security_response(line: str):
    result = parse_security_response(line)

    if result is None:
        return

    packet_id = result["packet_id"]
    authenticated = result["authenticated"]
    threat = result["threat"]
    policy = result["policy"]

    with state_lock:
        previous_auth = system_state["authenticated"]

        system_state["packet_id"] = packet_id
        system_state["authenticated"] = authenticated
        system_state["threat"] = threat
        system_state["policy"] = policy

        system_state["blue_pill"] = "ONLINE"
        system_state["uart"] = "CONNECTED"

        system_state["packets_total"] += 1

    upsert_traffic(
        packet_id,
        authenticated=authenticated,
        threat=threat,
        policy=policy,
        action="ACCEPTED" if authenticated == "VALID" else "REJECTED",
    )

    if authenticated == "VALID":
        recovered = previous_auth == "INVALID"

        with state_lock:
            system_state["action"] = "ACCEPTED"
            system_state["crypto_status"] = "AUTHENTICATED"
            system_state["system_banner"] = (
                "SYSTEM RECOVERED" if recovered else "SYSTEM SECURE"
            )

        add_event(
            (
                f"PKT {packet_id} | {threat} | {policy} | "
                f"AUTHENTICATED | RECOVERY"
                if recovered
                else
                f"PKT {packet_id} | {threat} | {policy} | AUTHENTICATED"
            ),
            "success",
        )

    else:
        with state_lock:
            system_state["packets_rejected"] += 1
            system_state["attacks"] += 1
            system_state["action"] = "REJECTED"
            system_state["crypto_status"] = "BLOCKED"
            system_state["system_banner"] = "SECURITY EVENT DETECTED"

            # Prevent stale ciphertext/decryption from looking like
            # the rejected packet was encrypted.
            system_state["encrypted_data"] = ""
            system_state["decrypted_data"] = ""
            system_state["iv"] = ""
            system_state["algorithm"] = "BLOCKED"

        upsert_traffic(
            packet_id,
            algorithm="BLOCKED",
            encrypted=False,
        )

        add_event(
            f"PKT {packet_id} | {threat} | {policy} | HMAC INVALID | REJECTED",
            "danger",
        )

    notify_dashboard()


def process_raw_packet(line: str):
    if "[TX] PACKET:" not in line:
        return

    packet = line.split("[TX] PACKET:", 1)[1].strip()
    telemetry = parse_packet(packet)

    packet_id = telemetry["packet_id"]

    with state_lock:
        system_state["packet_id"] = packet_id
        system_state["gas"] = telemetry["gas"]
        system_state["gas_status"] = telemetry["gas_status"]
        system_state["esp32"] = "ONLINE"
        system_state["uart"] = "CONNECTED"
        system_state["uptime_seconds"] = telemetry["uptime_ms"] // 1000

    upsert_traffic(
        packet_id,
        gas=telemetry["gas"],
        gas_status=telemetry["gas_status"],
    )

    notify_dashboard()


def process_encrypted_frame(line: str):
    try:
        frame = parse_encrypted_frame(line)

        if frame is None:
            return

        packet_id = int(frame["PKT"])
        policy = frame["POLICY"]
        algorithm = frame["ALG"]
        key_version = int(frame["KEYVER"])

        iv = bytes.fromhex(frame["IV"])
        ciphertext = bytes.fromhex(frame["DATA"])

        if algorithm == "AES-128":
            key_length = 16
        elif algorithm == "AES-256":
            key_length = 32
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if len(iv) != 16:
            raise ValueError("Invalid IV length")

        if not ciphertext or len(ciphertext) % 16 != 0:
            raise ValueError("Invalid ciphertext length")

        key = derive_aes_key(
            policy,
            key_version,
            key_length,
        )

        plaintext = decrypt_aes(
            ciphertext,
            iv,
            key,
        )

        plaintext_text = plaintext.decode("utf-8")
        telemetry = parse_packet(plaintext_text)

        with state_lock:
            previous_key = system_state["key_version"]

            system_state["packet_id"] = packet_id
            system_state["algorithm"] = algorithm
            system_state["key_version"] = key_version
            system_state["key_fingerprint"] = hashlib.sha256(key).hexdigest()[-12:].upper()

            system_state["iv"] = frame["IV"]
            system_state["encrypted_data"] = frame["DATA"]
            system_state["decrypted_data"] = plaintext_text

            system_state["gas"] = telemetry["gas"]
            system_state["gas_status"] = telemetry["gas_status"]

            system_state["packets_verified"] += 1
            system_state["crypto_status"] = "DECRYPTED"
            system_state["action"] = "ACCEPTED"
            system_state["esp32"] = "ONLINE"

            system_state["key_rotated"] = (
                previous_key != 0 and previous_key != key_version
            )

        upsert_traffic(
            packet_id,
            algorithm=algorithm,
            key_version=key_version,
            encrypted=True,
            action="ACCEPTED",
        )

        if system_state["key_rotated"]:
            add_event(
                f"KEY ROTATED → K-{key_version} | {algorithm} | {policy}",
                "command",
            )

        add_event(
            f"PKT {packet_id} | {algorithm} | K-{key_version} | DECRYPTED",
            "success",
        )

        notify_dashboard()

    except Exception as exc:
        with state_lock:
            system_state["crypto_status"] = "DECRYPTION ERROR"
            system_state["action"] = "ERROR"

        add_event(
            f"Decryption error: {exc}",
            "error",
        )

        notify_dashboard()


def process_serial_line(line: str):
    if not line:
        return

    if "ESP32 MAIN NODE" in line:
        with state_lock:
            system_state["esp32"] = "ONLINE"
            system_state["uart"] = "CONNECTED"
        notify_dashboard()

    if "[TX] PACKET:" in line:
        process_raw_packet(line)

    if "[RX] SECURITY:" in line:
        process_security_response(
            line.split("[RX] SECURITY:", 1)[1].strip()
        )

    if line.startswith("ENCRYPTED,"):
        process_encrypted_frame(line)


# ============================================================
# SERIAL
# ============================================================

def serial_reader():
    global serial_connection
    global serial_running

    try:
        serial_connection = serial.Serial(
            SERIAL_PORT,
            BAUD_RATE,
            timeout=1,
        )

        serial_running = True
        time.sleep(2)

        with state_lock:
            system_state["esp32"] = "ONLINE"
            system_state["uart"] = "CONNECTED"
            system_state["system_banner"] = "SYSTEM SECURE"

        add_event(
            f"ESP32 connected on {SERIAL_PORT}",
            "success",
        )

        while serial_running:
            raw = serial_connection.readline()

            if not raw:
                continue

            line = raw.decode(
                "utf-8",
                errors="ignore",
            ).strip()

            if line:
                process_serial_line(line)

    except Exception as exc:
        with state_lock:
            system_state["esp32"] = "OFFLINE"
            system_state["uart"] = "DISCONNECTED"
            system_state["system_banner"] = "SERIAL DISCONNECTED"

        add_event(
            f"Serial error: {exc}",
            "error",
        )

    finally:
        serial_running = False

        if serial_connection is not None:
            try:
                serial_connection.close()
            except Exception:
                pass

        serial_connection = None
        notify_dashboard()


def send_command(command: str):
    if serial_connection is None:
        raise RuntimeError("ESP32 serial connection is not available")

    with serial_lock:
        serial_connection.write((command + "\n").encode())
        serial_connection.flush()

    add_event(f"COMMAND → {command}", "command")


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(title="CIPHER-M Security Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    global event_loop, serial_thread

    event_loop = asyncio.get_running_loop()

    serial_thread = threading.Thread(
        target=serial_reader,
        daemon=True,
    )

    serial_thread.start()


@app.on_event("shutdown")
async def shutdown():
    global serial_running
    serial_running = False


@app.get("/api/state")
async def api_state():
    return get_state()


@app.post("/api/attack")
async def api_attack(request: AttackRequest):
    commands = {
        1: "ATTACK,LOW",
        2: "ATTACK,MEDIUM",
        3: "ATTACK,HIGH",
        4: "ATTACK,TAMPER",
    }

    if request.level not in commands:
        raise HTTPException(
            status_code=400,
            detail="Attack level must be 1, 2, 3 or 4",
        )

    try:
        send_command(commands[request.level])
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return {
        "success": True,
        "level": request.level,
        "command": commands[request.level],
    }


@app.post("/api/normal")
async def api_normal():
    try:
        send_command("NORMAL")
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    return {"success": True}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    websocket_clients.add(websocket)

    try:
        await websocket.send_json(get_state())

        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        websocket_clients.discard(websocket)

    except Exception:
        websocket_clients.discard(websocket)


# ============================================================
# OPTIONAL PRODUCTION MODE:
# AFTER `npm run build`, FastAPI can serve the React app.
# ============================================================

if FRONTEND_DIST.exists():
    from fastapi.staticfiles import StaticFiles

    assets_dir = FRONTEND_DIST / "assets"

    if assets_dir.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=assets_dir),
            name="assets",
        )

    @app.get("/")
    async def production_dashboard():
        return FileResponse(FRONTEND_DIST / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
