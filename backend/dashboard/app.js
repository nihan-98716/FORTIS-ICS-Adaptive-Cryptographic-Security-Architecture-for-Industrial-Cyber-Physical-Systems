let socket = null;

let trafficPackets = [];


// ============================================================
// WEBSOCKET
// ============================================================

function connectWebSocket() {

    const protocol =
        window.location.protocol === "https:"
            ? "wss:"
            : "ws:";

    socket = new WebSocket(
        `${protocol}//${window.location.host}/ws`
    );


    socket.onopen = () => {

        console.log(
            "[DASHBOARD] WebSocket connected"
        );
    };


    socket.onmessage = (event) => {

        const state =
            JSON.parse(event.data);

        updateDashboard(state);
    };


    socket.onclose = () => {

        console.log(
            "[DASHBOARD] WebSocket disconnected"
        );

        setTimeout(
            connectWebSocket,
            2000
        );
    };
}


// ============================================================
// UPDATE DASHBOARD
// ============================================================

function updateDashboard(state) {

    setText(
        "esp32Status",
        state.esp32
    );

    setText(
        "bluePillStatus",
        state.blue_pill
    );

    setText(
        "uartStatus",
        state.uart
    );


    setText(
        "threat",
        state.threat
    );

    setText(
        "policy",
        state.policy
    );

    setText(
        "algorithm",
        state.algorithm
    );

    setText(
        "keyVersion",
        state.key_version
            ? `K-${String(state.key_version).padStart(2, "0")}`
            : "K-00"
    );


    setText(
        "authentication",
        state.authenticated
    );

    setText(
        "action",
        state.action
    );


    setText(
        "cryptoStatus",
        state.crypto_status
    );

    setText(
        "decryptStatus",
        state.crypto_status
    );


    setText(
        "packetId",
        state.packet_id
    );

    setText(
        "gas",
        state.gas ?? "—"
    );

    setText(
        "gasStatus",
        state.gas_status
    );


    setText(
        "verified",
        state.packets_verified
    );

    setText(
        "rejected",
        state.packets_rejected
    );

    setText(
        "attacks",
        state.attacks
    );


    setText(
        "iv",
        state.iv || "—"
    );


    document.getElementById(
        "encryptedData"
    ).textContent =
        state.encrypted_data || "—";


    document.getElementById(
        "decryptedData"
    ).textContent =
        state.decrypted_data ||
        "Waiting for encrypted telemetry...";


    updateThreatColor(
        state.threat
    );

    updateTraffic(
        state
    );

    updateEvents(
        state.events
    );
}


// ============================================================
// TRAFFIC
// ============================================================

function updateTraffic(state) {

    if (!state.packet_id) {
        return;
    }


    const packet = {

        id: state.packet_id,

        threat: state.threat,

        policy: state.policy,

        algorithm: state.algorithm,

        authenticated:
            state.authenticated,

        gas: state.gas,

        gasStatus:
            state.gas_status,

        action:
            state.action
    };


    const existing =
        trafficPackets.findIndex(
            p => p.id === packet.id
        );


    if (existing >= 0) {

        trafficPackets[existing] =
            packet;

    } else {

        trafficPackets.unshift(
            packet
        );
    }


    trafficPackets =
        trafficPackets.slice(
            0,
            30
        );


    const container =
        document.getElementById(
            "traffic"
        );


    container.innerHTML =
        trafficPackets
            .map(renderTrafficPacket)
            .join("");
}


function renderTrafficPacket(packet) {

    const invalid =
        packet.authenticated === "INVALID";

    return `
        <div class="traffic-card ${invalid ? "invalid" : ""}">

            <div class="packet-title">

                <span>
                    PKT #${packet.id}
                </span>

                <span>
                    ${packet.policy}
                </span>

            </div>

            <div class="packet-row">
                GAS: ${packet.gas ?? "—"}
            </div>

            <div class="packet-row">
                GAS STATUS:
                ${packet.gasStatus}
            </div>

            <div class="packet-row">
                THREAT:
                ${packet.threat}
            </div>

            <div class="packet-row">
                ALGORITHM:
                ${packet.algorithm}
            </div>

            <div class="
                ${invalid
                    ? "packet-invalid"
                    : "packet-valid"}
            ">

                ${invalid
                    ? "✕ INTEGRITY FAILED — REJECTED"
                    : "✓ INTEGRITY OK — AUTHENTICATED"}

            </div>

        </div>
    `;
}


// ============================================================
// EVENT LOG
// ============================================================

function updateEvents(events) {

    const container =
        document.getElementById(
            "eventLog"
        );


    if (!events || events.length === 0) {

        container.innerHTML =
            `<div class="empty">
                No security events yet.
            </div>`;

        return;
    }


    container.innerHTML =
        events
            .slice(0, 40)
            .map(event => {

                return `
                    <div class="event ${event.type}">
                        [${event.time}]
                        ${escapeHtml(event.message)}
                    </div>
                `;

            })
            .join("");
}


// ============================================================
// ATTACK
// ============================================================

async function executeAttack() {

    const input =
        document.getElementById(
            "attackLevel"
        );

    const level =
        parseInt(input.value);


    if (
        Number.isNaN(level) ||
        level < 1 ||
        level > 4
    ) {

        alert(
            "Enter an attack level from 1 to 4."
        );

        return;
    }


    try {

        const response =
            await fetch(
                "/api/attack",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        level: level
                    })
                }
            );


        if (!response.ok) {

            const error =
                await response.json();

            alert(
                error.detail ||
                "Attack command failed."
            );

            return;
        }


        console.log(
            `[DASHBOARD] Attack ${level} sent`
        );

    } catch (error) {

        alert(
            "Backend connection failed."
        );
    }
}


// ============================================================
// NORMAL
// ============================================================

async function normalMode() {

    try {

        await fetch(
            "/api/normal",
            {
                method: "POST"
            }
        );

    } catch (error) {

        alert(
            "Backend connection failed."
        );
    }
}


// ============================================================
// HELPERS
// ============================================================

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value ?? "—";
    }
}


function updateThreatColor(threat) {

    const element =
        document.getElementById(
            "threat"
        );

    if (!element) {
        return;
    }


    element.style.color =
        "#75d8ff";


    if (threat === "CRITICAL") {

        element.style.color =
            "#ff6464";

    } else if (threat === "HIGH") {

        element.style.color =
            "#ffb45c";

    } else if (threat === "MEDIUM") {

        element.style.color =
            "#ffe066";

    } else if (threat === "LOW") {

        element.style.color =
            "#55d88a";
    }
}


function escapeHtml(text) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        text;

    return div.innerHTML;
}


// ============================================================
// START
// ============================================================

connectWebSocket();
