# FORTIS-ICS — System Architecture

## 1. Architecture Overview

FORTIS-ICS implements a dual-controller adaptive security architecture.

The **ESP32 DevKit V1** operates as the primary application and telemetry node, while the **STM32F103C8T6 Blue Pill** functions as an independent security coprocessor.

The system separates application processing from security verification and adaptive cryptographic policy selection.

---

## 2. System Components

### ESP32 DevKit V1 — Application Node

Responsible for:

- Sensor and runtime telemetry collection
- Telemetry packet generation
- HMAC-SHA256 generation
- AES-128 / AES-256 encryption
- Key rotation
- Communication with the security coprocessor

### STM32F103C8T6 Blue Pill — Security Coprocessor

Responsible for:

- Independent HMAC verification
- Packet authentication
- Tamper detection
- Threat-level classification
- Adaptive security-policy selection
- Returning security decisions to the ESP32

### Python Backend

Responsible for:

- Serial communication with the ESP32
- Processing encrypted telemetry
- AES decryption
- Security event processing
- REST API
- WebSocket-based dashboard communication

### CIPHER-M Dashboard

React-based monitoring interface providing:

- Live telemetry
- Authentication status
- Threat level
- Active security policy
- Encryption algorithm
- Key version and rotation status
- IV and ciphertext information
- Decrypted telemetry
- Attack simulation controls
- Security event history

---

## 3. Data Flow

```text
Sensor / Runtime Data
        |
        v
ESP32 Application Node
        |
        | HMAC-SHA256
        v
STM32 Blue Pill
        |
        | HMAC Verification
        | Threat Classification
        | Policy Selection
        v
ESP32 Cryptographic Engine
        |
        | AES-128 / AES-256
        | Key Rotation
        v
Python Backend
        |
        | AES Decryption
        v
CIPHER-M Dashboard
````

---

## 4. Adaptive Security Model

| Threat Level | Policy      | Cryptography           | Action                        |
| ------------ | ----------- | ---------------------- | ----------------------------- |
| LOW          | LIGHTWEIGHT | AES-128                | Accept                        |
| MEDIUM       | NORMAL      | AES-128 + Key Rotation | Accept                        |
| HIGH         | ENHANCED    | AES-256 + Key Rotation | Accept                        |
| CRITICAL     | PARANOID    | Strongest protection   | Reject unauthenticated packet |

A packet that fails HMAC verification is rejected before cryptographic processing.

---

## 5. Communication Interfaces

| Interface | Connection          | Purpose                |
| --------- | ------------------- | ---------------------- |
| UART      | ESP32 ↔ Blue Pill   | Security communication |
| Serial    | ESP32 ↔ Backend     | Telemetry transport    |
| REST API  | Dashboard ↔ Backend | Control commands       |
| WebSocket | Backend ↔ Dashboard | Real-time updates      |

---

## 6. Security Pipeline

The implemented security pipeline is:

```text
Telemetry
   ↓
HMAC Generation
   ↓
Independent HMAC Verification
   ↓
Threat Assessment
   ↓
Security Policy Selection
   ↓
AES Encryption
   ↓
Protected Transmission
   ↓
Backend Decryption
   ↓
Dashboard Visualization
```

For a tampered packet:

```text
Tampered Telemetry
        ↓
HMAC Verification Failure
        ↓
CRITICAL / PARANOID
        ↓
Packet Rejected
        ↓
Encryption Blocked
```

---

## 7. Hardware Communication

The ESP32 communicates with the Blue Pill using UART at **115200 baud, 8N1**.

```text
ESP32 GPIO17 (TX) ───────> Blue Pill PA10 (RX)

ESP32 GPIO16 (RX) <─────── Blue Pill PA9  (TX)

ESP32 GND ──────────────── Blue Pill GND
```

The Blue Pill is independently powered and programmed using ST-Link.

---

## 8. Architecture Summary

FORTIS-ICS combines:

* Edge telemetry processing
* Independent hardware-based security verification
* HMAC-SHA256 authentication
* Adaptive AES encryption
* Runtime key rotation
* Tamper detection
* Python-based secure processing
* Real-time React visualization

This separation creates a clear security boundary between the application node and the dedicated security coprocessor.

```
