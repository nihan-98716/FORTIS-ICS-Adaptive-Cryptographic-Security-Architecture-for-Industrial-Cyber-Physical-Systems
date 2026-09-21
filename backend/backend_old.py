import asyncio
import hashlib
import re
import threading
import time
from pathlib import Path

import serial
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ============================================================
# CONFIGURATION
# ============================================================

SERIAL_PORT = "COM8"
BAUD_RATE = 115200

AES_MASTER_KEY = b"CIPHER_M_AES_MASTER_2026"

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"


# ============================================================
# GLOBAL STATE
# ============================================================

serial_connection = None
serial_lock = threading.Lock()

event_loop = None
serial_thread = None
serial_running = False

websocket_clients = set()

state_lock = threading.Lock()

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

    "last_event": "System starting...",
    "events": []
}


# ============================================================
# API MODELS
# ============================================================

class AttackRequest(BaseModel):
    level: int


# ============================================================
# STATE HELPERS
# ============================================================

def add_event(message: str, event_type: str = "info"):
    event = {
        "time": time.strftime("%H:%M:%S"),
        "message": message,
        "type": event_type
    }

    with state_lock:
        system_state["events"].insert(0, event)

        if len(system_state["events"]) > 100:
            system_state["events"] = system_state["events"][:100]

        system_state["last_event"] = message


def get_state():
    with state_lock:
        return {
            **system_state,
            "events": list(system_state["events"])
        }


# ============================================================
# WEBSOCKET BROADCAST
# ============================================================

async def broadcast_state():
    if not websocket_clients:
        return

    data = get_state()

    dead_clients = []

    for websocket in list(websocket_clients):
        try:
            await websocket.send_json(data)
        except Exception:
            dead_clients.append(websocket)

    for websocket in dead_clients:
        websocket_clients.discard(websocket)


def notify_dashboard():
    if event_loop is None:
        return

    try:
        asyncio.run_coroutine_threadsafe(
            broadcast_state(),
            event_loop
        )
    except Exception:
        pass


# ============================================================
# AES KEY DERIVATION
# MUST MATCH ESP32
# ============================================================

def derive_aes_key(
    policy: str,
    key_version: int,
    key_length: int
) -> bytes:

    material = (
        AES_MASTER_KEY.decode()
        + "|"
        + policy
        + "|V="
        + str(key_version)
    ).encode()

    digest = hashlib.sha256(material).digest()

    return digest[:key_length]


# ============================================================
# PKCS#7
# ============================================================

def remove_pkcs7_padding(data: bytes) -> bytes:

    if not data:
        raise ValueError("Empty plaintext")

    padding = data[-1]

    if padding < 1 or padding > 16:
        raise ValueError("Invalid PKCS#7 padding")

    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-padding]


# ============================================================
# AES CBC DECRYPTION
# ============================================================

def decrypt_aes(
    ciphertext: bytes,
    iv: bytes,
    key: bytes
) -> bytes:

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    decryptor = cipher.decryptor()

    plaintext_padded = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    return remove_pkcs7_padding(plaintext_padded)


# ============================================================
# PARSE ENCRYPTED FRAME
# ============================================================

def parse_encrypted_frame(line: str):

    if not line.startswith("ENCRYPTED,"):
        return None

    fields = line.strip().split(",")

    values = {}

    for field in fields[1:]:

        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        values[key] = value

    required = [
        "PKT",
        "POLICY",
        "ALG",
        "KEYVER",
        "IV",
        "DATA"
    ]

    for field in required:

        if field not in values:
            raise ValueError(
                f"Missing encrypted field: {field}"
            )

    return values


# ============================================================
# PARSE SECURITY RESPONSE
# ============================================================

def parse_security_response(line: str):

    match = re.search(
        r"SECURITY,PKT=(\d+),(VALID|INVALID),"
        r"(LOW|MEDIUM|HIGH|CRITICAL),"
        r"(LIGHTWEIGHT|NORMAL|ENHANCED|PARANOID)",
        line
    )

    if not match:
        return None

    packet_id = int(match.group(1))
    auth = match.group(2)
    threat = match.group(3)
    policy = match.group(4)

    return {
        "packet_id": packet_id,
        "authenticated": auth,
        "threat": threat,
        "policy": policy
    }


# ============================================================
# PARSE RAW TELEMETRY
# ============================================================

def parse_packet(packet: str):

    gas_match = re.search(
        r"GAS=(\d+)",
        packet
    )

    gas_status_match = re.search(
        r"GAS_STATUS=([A-Z]+)",
        packet
    )

    packet_match = re.search(
        r"PKT,1\.0,MAIN_01,(\d+)",
        packet
    )

    return {
        "packet_id": (
            int(packet_match.group(1))
            if packet_match else 0
        ),

        "gas": (
            int(gas_match.group(1))
            if gas_match else None
        ),

        "gas_status": (
            gas_status_match.group(1)
            if gas_status_match else "UNKNOWN"
        )
    }


# ============================================================
# PROCESS ENCRYPTED PACKET
# ============================================================

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
            raise ValueError(
                f"Unsupported algorithm: {algorithm}"
            )

        if len(iv) != 16:
            raise ValueError("Invalid IV length")

        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            raise ValueError("Invalid ciphertext length")

        key = derive_aes_key(
            policy,
            key_version,
            key_length
        )

        plaintext = decrypt_aes(
            ciphertext,
            iv,
            key
        )

        plaintext_text = plaintext.decode(
            "utf-8"
        )

        telemetry = parse_packet(
            plaintext_text
        )

        with state_lock:

            system_state["packet_id"] = packet_id

            system_state["algorithm"] = algorithm
            system_state["key_version"] = key_version

            system_state["iv"] = frame["IV"]

            system_state["encrypted_data"] = frame["DATA"]

            system_state["decrypted_data"] = plaintext_text

            system_state["gas"] = telemetry["gas"]
            system_state["gas_status"] = telemetry["gas_status"]

            system_state["packets_verified"] += 1

            system_state["crypto_status"] = "DECRYPTED"
            system_state["action"] = "ACCEPTED"

            system_state["esp32"] = "ONLINE"
            system_state["uart"] = "CONNECTED"

        add_event(
            f"PKT {packet_id} | "
            f"{system_state['threat']} | "
            f"{policy} | "
            f"{algorithm} | "
            f"DECRYPTED",
            "success"
        )

        notify_dashboard()

    except Exception as exc:

        with state_lock:
            system_state["crypto_status"] = "DECRYPTION ERROR"
            system_state["action"] = "ERROR"

        add_event(
            f"Decryption error: {exc}",
            "error"
        )

        notify_dashboard()


# ============================================================
# PROCESS SECURITY RESPONSE
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

        system_state["packet_id"] = packet_id

        system_state["authenticated"] = authenticated
        system_state["threat"] = threat
        system_state["policy"] = policy

        system_state["blue_pill"] = "ONLINE"
        system_state["uart"] = "CONNECTED"

        system_state["packets_total"] += 1

    if authenticated == "VALID":

        with state_lock:
            system_state["action"] = "ACCEPTED"
            system_state["crypto_status"] = "AUTHENTICATED"

        add_event(
            f"PKT {packet_id} | "
            f"{threat} | "
            f"{policy} | AUTHENTICATED",
            "success"
        )

    else:

        with state_lock:

            system_state["packets_rejected"] += 1

            system_state["attacks"] += 1

            system_state["action"] = "REJECTED"

            system_state["crypto_status"] = "BLOCKED"

            system_state["algorithm"] = "—"

        add_event(
            f"PKT {packet_id} | "
            f"{threat} | "
            f"{policy} | "
            f"HMAC INVALID | REJECTED",
            "danger"
        )

    notify_dashboard()


# ============================================================
# PROCESS RAW ESP32 LINE
# ============================================================

def process_serial_line(line: str):

    line = line.strip()

    if not line:
        return

    # ESP32 startup / general traffic
    if "ESP32 MAIN NODE" in line:

        with state_lock:
            system_state["esp32"] = "ONLINE"

        notify_dashboard()

    # Raw telemetry
    if "[TX] PACKET:" in line:

        packet = line.split(
            "[TX] PACKET:",
            1
        )[1].strip()

        telemetry = parse_packet(packet)

        with state_lock:

            system_state["packet_id"] = telemetry["packet_id"]

            system_state["gas"] = telemetry["gas"]

            system_state["gas_status"] = telemetry["gas_status"]

            system_state["esp32"] = "ONLINE"

        notify_dashboard()

    # Blue Pill decision
    if "[RX] SECURITY:" in line:

        security = line.split(
            "[RX] SECURITY:",
            1
        )[1].strip()

        process_security_response(
            security
        )

    # Encrypted packet
    if line.startswith("ENCRYPTED,"):

        process_encrypted_frame(line)


# ============================================================
# SEND COMMAND TO ESP32
# ============================================================

def send_command(command: str):

    global serial_connection

    if serial_connection is None:
        raise RuntimeError(
            "ESP32 serial connection is not available"
        )

    with serial_lock:

        serial_connection.write(
            (command + "\n").encode()
        )

        serial_connection.flush()

    add_event(
        f"COMMAND → {command}",
        "command"
    )

    notify_dashboard()


# ============================================================
# SERIAL READER
# ============================================================

def serial_reader():

    global serial_connection
    global serial_running

    try:

        serial_connection = serial.Serial(
            SERIAL_PORT,
            BAUD_RATE,
            timeout=1
        )

        serial_running = True

        time.sleep(2)

        with state_lock:

            system_state["esp32"] = "ONLINE"
            system_state["uart"] = "CONNECTED"

        add_event(
            f"ESP32 connected on {SERIAL_PORT}",
            "success"
        )

        notify_dashboard()

        while serial_running:

            raw = serial_connection.readline()

            if not raw:
                continue

            line = raw.decode(
                "utf-8",
                errors="ignore"
            ).strip()

            if line:
                process_serial_line(line)

    except Exception as exc:

        with state_lock:

            system_state["esp32"] = "OFFLINE"
            system_state["uart"] = "DISCONNECTED"

        add_event(
            f"Serial error: {exc}",
            "error"
        )

        notify_dashboard()

    finally:

        serial_running = False

        if serial_connection is not None:

            try:
                serial_connection.close()
            except Exception:
                pass

        serial_connection = None


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="CIPHER-M Security Dashboard"
)


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global event_loop
    global serial_thread

    event_loop = asyncio.get_running_loop()

    serial_thread = threading.Thread(
        target=serial_reader,
        daemon=True
    )

    serial_thread.start()


# ============================================================
# SHUTDOWN
# ============================================================

@app.on_event("shutdown")
async def shutdown():

    global serial_running

    serial_running = False


# ============================================================
# DASHBOARD PAGE
# ============================================================

@app.get("/")
async def dashboard():

    return FileResponse(
        DASHBOARD_DIR / "index.html"
    )


# ============================================================
# STATIC FILES
# ============================================================

from fastapi.staticfiles import StaticFiles

app.mount(
    "/static",
    StaticFiles(directory=DASHBOARD_DIR),
    name="static"
)


# ============================================================
# CURRENT STATE
# ============================================================

@app.get("/api/state")
async def api_state():

    return get_state()


# ============================================================
# ATTACK COMMAND
# ============================================================

@app.post("/api/attack")
async def api_attack(request: AttackRequest):

    level = request.level

    commands = {
        1: "ATTACK,LOW",
        2: "ATTACK,MEDIUM",
        3: "ATTACK,HIGH",
        4: "ATTACK,TAMPER"
    }

    if level not in commands:

        raise HTTPException(
            status_code=400,
            detail="Attack level must be 1, 2, 3 or 4"
        )

    command = commands[level]

    try:

        send_command(command)

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )

    return {
        "success": True,
        "level": level,
        "command": command
    }


# ============================================================
# NORMAL MODE
# ============================================================

@app.post("/api/normal")
async def api_normal():

    try:

        send_command("NORMAL")

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )

    return {
        "success": True
    }


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    websocket_clients.add(websocket)

    try:

        await websocket.send_json(
            get_state()
        )

        while True:

            await websocket.receive_text()

    except WebSocketDisconnect:

        websocket_clients.discard(
            websocket
        )

    except Exception:

        websocket_clients.discard(
            websocket
        )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )