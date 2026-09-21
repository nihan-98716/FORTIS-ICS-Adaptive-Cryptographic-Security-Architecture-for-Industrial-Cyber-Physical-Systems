import React, { useEffect, useMemo, useRef, useState } from "react";

const API = "http://127.0.0.1:8000";

const EMPTY = {
  esp32: "OFFLINE",
  blue_pill: "UNKNOWN",
  uart: "DISCONNECTED",
  packet_id: 0,
  authenticated: "UNKNOWN",
  threat: "UNKNOWN",
  policy: "UNKNOWN",
  algorithm: "UNKNOWN",
  key_version: 0,
  key_fingerprint: "",
  gas: null,
  gas_status: "UNKNOWN",
  iv: "",
  encrypted_data: "",
  decrypted_data: "",
  packets_total: 0,
  packets_verified: 0,
  packets_rejected: 0,
  attacks: 0,
  crypto_status: "IDLE",
  action: "WAITING",
  system_banner: "SYSTEM STARTING",
  key_rotated: false,
  uptime_seconds: 0,
  traffic: [],
  events: [],
};

function App() {
  const [state, setState] = useState(EMPTY);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const socketRef = useRef(null);

  useEffect(() => {
    let stopped = false;
    let retry;

    const connect = () => {
      if (stopped) return;

      const ws = new WebSocket("ws://127.0.0.1:8000/ws");
      socketRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onmessage = (event) => {
        try {
          setState(JSON.parse(event.data));
        } catch {}
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stopped) retry = setTimeout(connect, 1500);
      };
      ws.onerror = () => ws.close();
    };

    connect();

    return () => {
      stopped = true;
      clearTimeout(retry);
      socketRef.current?.close();
    };
  }, []);

  const sendAttack = async (level) => {
    setBusy(true);
    try {
      await fetch(`${API}/api/attack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ level }),
      });
    } finally {
      setBusy(false);
    }
  };

  const normal = async () => {
    setBusy(true);
    try {
      await fetch(`${API}/api/normal`, { method: "POST" });
    } finally {
      setBusy(false);
    }
  };

  const latest = state.traffic?.[0];
  const secure =
    state.authenticated === "VALID" &&
    state.action === "ACCEPTED";

  const bannerClass =
    state.system_banner === "SECURITY EVENT DETECTED"
      ? "danger"
      : state.system_banner === "SYSTEM RECOVERED"
        ? "recovered"
        : "secure";

  const uptime = useMemo(() => {
    const s = Number(state.uptime_seconds || 0);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  }, [state.uptime_seconds]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">◆</div>
          <div>
            <h1>CIPHER-M</h1>
            <p>Adaptive Runtime Cryptographic Security for Embedded IoT Systems</p>
          </div>
        </div>

        <div className="device-strip">
          <StatusChip label="ESP32 MAIN" value={state.esp32} />
          <StatusChip label="BLUE PILL" value={state.blue_pill} />
          <StatusChip label="UART" value={state.uart} />
          <StatusChip label="DASHBOARD" value={connected ? "CONNECTED" : "OFFLINE"} />
        </div>
      </header>

      <main>
        <section className={`security-banner ${bannerClass}`}>
          <div>
            <span className="banner-dot" />
            <strong>{state.system_banner}</strong>
          </div>
          <span>
            PKT #{state.packet_id || "—"} · {state.threat} · {state.policy}
          </span>
        </section>

        <section className="top-grid">
          <TrafficPanel
            traffic={state.traffic || []}
            busy={busy}
            sendAttack={sendAttack}
            normal={normal}
          />

          <CryptoPanel state={state} secure={secure} />

          <DecryptionPanel state={state} />
        </section>

        <section className="stats-grid">
          <Stat label="TOTAL PACKETS" value={state.packets_total} />
          <Stat label="VERIFIED" value={state.packets_verified} tone="green" />
          <Stat label="REJECTED" value={state.packets_rejected} tone="red" />
          <Stat label="ATTACK EVENTS" value={state.attacks} tone="orange" />
          <Stat label="MQ-2 GAS" value={state.gas ?? "—"} />
          <Stat label="GAS STATUS" value={state.gas_status} />
          <Stat label="KEY VERSION" value={state.key_version ? `K-${state.key_version}` : "—"} />
          <Stat label="UPTIME" value={uptime} />
        </section>

        <section className="bottom-grid">
          <Pipeline state={state} />
          <EventLog events={state.events || []} />
        </section>
      </main>
    </div>
  );
}

function StatusChip({ label, value }) {
  const ok = ["ONLINE", "CONNECTED"].includes(value);
  return (
    <div className="status-chip">
      <span>{label}</span>
      <b className={ok ? "ok" : "muted"}>{value}</b>
    </div>
  );
}

function TrafficPanel({ traffic, busy, sendAttack, normal }) {
  return (
    <section className="panel traffic-panel">
      <PanelTitle title="LIVE INCOMING TRAFFIC" right="● STREAMING" />
      <div className="traffic-scroll">
        {traffic.length === 0 ? (
          <Empty text="Waiting for telemetry..." />
        ) : (
          traffic.map((p) => <TrafficCard key={p.id} packet={p} />)
        )}
      </div>

      <div className="attack-console">
        <div className="section-kicker">CONTROLLED SECURITY TEST</div>
        <h3>Simulate Attack</h3>
        <p>
          Commands are sent to the ESP32. The Blue Pill remains the authority
          that authenticates the packet and selects the security policy.
        </p>

        <div className="attack-buttons">
          <button disabled={busy} onClick={() => sendAttack(1)}>
            <span>01</span> LOW THREAT
          </button>
          <button disabled={busy} onClick={() => sendAttack(2)}>
            <span>02</span> MEDIUM THREAT
          </button>
          <button disabled={busy} onClick={() => sendAttack(3)}>
            <span>03</span> HIGH THREAT
          </button>
          <button className="danger-btn" disabled={busy} onClick={() => sendAttack(4)}>
            <span>04</span> PACKET TAMPER
          </button>
        </div>

        <button className="normal-btn" disabled={busy} onClick={normal}>
          RETURN TO NORMAL OPERATION
        </button>
      </div>
    </section>
  );
}

function TrafficCard({ packet }) {
  const invalid = packet.authenticated === "INVALID";
  return (
    <div className={`traffic-card ${invalid ? "invalid" : ""}`}>
      <div className="traffic-head">
        <strong>PKT #{packet.id}</strong>
        <span>{packet.policy}</span>
      </div>

      <div className="traffic-data">
        <span>GAS <b>{packet.gas ?? "—"}</b></span>
        <span>GAS STATUS <b>{packet.gas_status}</b></span>
        <span>THREAT <b>{packet.threat}</b></span>
        <span>ALGORITHM <b>{packet.algorithm}</b></span>
        <span>KEY <b>{packet.key_version ? `K-${packet.key_version}` : "—"}</b></span>
      </div>

      <div className={invalid ? "integrity bad" : "integrity good"}>
        {invalid ? "✕ HMAC INVALID · PACKET REJECTED" : "✓ HMAC VERIFIED · AUTHENTICATED"}
      </div>
    </div>
  );
}

function CryptoPanel({ state, secure }) {
  const threatClass = (state.threat || "").toLowerCase();
  const blocked = state.authenticated === "INVALID";

  return (
    <section className="panel crypto-panel">
      <PanelTitle title="ADAPTIVE CRYPTOGRAPHIC ENGINE" right={state.crypto_status} />

      <div className="decision-grid">
        <Metric label="THREAT LEVEL" value={state.threat} className={`threat-${threatClass}`} />
        <Metric label="SECURITY POLICY" value={state.policy} />
        <Metric label="ALGORITHM" value={blocked ? "BLOCKED" : state.algorithm} />
        <Metric label="KEY VERSION" value={state.key_version ? `K-${state.key_version}` : "—"} />
      </div>

      <div className="key-section">
        <div className="section-kicker">SESSION KEY</div>
        <div className="key-display">
          <span className="lock">⌁</span>
          <span>DERIVED SESSION KEY</span>
          <span className="key-fingerprint">
            {state.key_fingerprint ? `…${state.key_fingerprint}` : "PROTECTED"}
          </span>
        </div>
        <div className="key-note">
          Secret key material is retained by the backend; only cryptographic state is exposed.
        </div>

        <div className="iv-row">
          <span>INITIALIZATION VECTOR</span>
          <code>{state.iv || "—"}</code>
        </div>

        {state.key_rotated && (
          <div className="rotation-badge">↻ KEY ROTATED</div>
        )}
      </div>

      <div className="crypto-flow">
        <FlowNode label="PLAINTEXT" active={secure} />
        <FlowArrow />
        <FlowNode label={blocked ? "HMAC FAILED" : "HMAC VERIFIED"} danger={blocked} active={!blocked} />
        <FlowArrow />
        <FlowNode label={blocked ? "ENCRYPTION BLOCKED" : state.algorithm || "AES ENCRYPTION"} danger={blocked} active={!blocked} />
        <FlowArrow />
        <FlowNode label={blocked ? "REJECTED" : "CIPHERTEXT"} danger={blocked} />
      </div>

      <div className="decision-box">
        <div>
          <span>AUTHENTICATION</span>
          <b className={state.authenticated === "VALID" ? "good-text" : state.authenticated === "INVALID" ? "bad-text" : ""}>
            {state.authenticated}
          </b>
        </div>
        <div>
          <span>ACTION</span>
          <b>{state.action}</b>
        </div>
      </div>
    </section>
  );
}

function DecryptionPanel({ state }) {
  const decrypted = Boolean(state.decrypted_data);
  return (
    <section className="panel decrypt-panel">
      <PanelTitle title="END-TO-END DECRYPTION" right={decrypted ? "DECRYPTED" : "WAITING"} />

      <div className="decrypt-flow">
        <div>ENCRYPTED PAYLOAD</div>
        <span>↓</span>
        <div>AES KEY + IV</div>
        <span>↓</span>
        <div className={decrypted ? "active-decrypt" : ""}>AES DECRYPTION</div>
        <span>↓</span>
        <div className={decrypted ? "active-decrypt success-border" : ""}>PLAINTEXT TELEMETRY</div>
      </div>

      <DataBox label="ENCRYPTED PAYLOAD" value={state.encrypted_data} />
      <DataBox label="DECRYPTED TELEMETRY" value={state.decrypted_data} success />
    </section>
  );
}

function Pipeline({ state }) {
  const stages = [
    ["01", "MQ-2 / RUNTIME TELEMETRY", "ESP32"],
    ["02", "HMAC-SHA256", state.authenticated === "VALID" ? "VERIFIED" : state.authenticated === "INVALID" ? "FAILED" : "WAITING"],
    ["03", "THREAT ASSESSMENT", state.threat],
    ["04", "POLICY SELECTION", state.policy],
    ["05", "KEY ROTATION", state.key_version ? `K-${state.key_version}` : "WAITING"],
    ["06", "AES ENCRYPTION", state.algorithm],
    ["07", "USB SERIAL", "CIPHERTEXT"],
    ["08", "PYTHON DECRYPTION", state.decrypted_data ? "SUCCESS" : "WAITING"],
  ];

  return (
    <section className="panel pipeline-panel">
      <PanelTitle title="CIPHER-M RUNTIME PIPELINE" right="LIVE" />
      <div className="pipeline-list">
        {stages.map(([n, title, value]) => (
          <div className="pipeline-row" key={n}>
            <span className="pipeline-num">{n}</span>
            <span className="pipeline-title">{title}</span>
            <b className={value === "FAILED" ? "bad-text" : value === "VERIFIED" || value === "SUCCESS" ? "good-text" : ""}>
              {value || "—"}
            </b>
          </div>
        ))}
      </div>
    </section>
  );
}

function EventLog({ events }) {
  return (
    <section className="panel event-panel">
      <PanelTitle title="SECURITY EVENT LOG" right={`${events.length} EVENTS`} />
      <div className="event-scroll">
        {events.length === 0 ? (
          <Empty text="No security events yet." />
        ) : (
          events.slice(0, 50).map((e, i) => (
            <div className={`event ${e.type}`} key={`${e.time}-${i}`}>
              <span>[{e.time}]</span>
              <b>{e.message}</b>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function PanelTitle({ title, right }) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      <span>{right}</span>
    </div>
  );
}

function Metric({ label, value, className = "" }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <b className={className}>{value || "—"}</b>
    </div>
  );
}

function Stat({ label, value, tone = "" }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <b className={tone}>{value}</b>
    </div>
  );
}

function FlowNode({ label, active, danger }) {
  return <div className={`flow-node ${active ? "active" : ""} ${danger ? "danger-node" : ""}`}>{label}</div>;
}

function FlowArrow() {
  return <div className="flow-arrow">↓</div>;
}

function DataBox({ label, value, success }) {
  return (
    <div className="data-box">
      <span>{label}</span>
      <pre className={success && value ? "success-data" : ""}>{value || "Waiting for packet..."}</pre>
    </div>
  );
}

function Empty({ text }) {
  return <div className="empty">{text}</div>;
}

export default App;
