#include <Arduino.h>
#include "mbedtls/md.h"

// ============================================================
// ESP32 UART2 → BLUE PILL
// ============================================================

#define ESP32_RX 16
#define ESP32_TX 17

HardwareSerial SecuritySerial(2);


// ============================================================
// GAS SENSOR
// ============================================================

// MQ-2 analog output connected to GPIO34
#define GAS_SENSOR_PIN 34

// Demo threshold.
// This MUST be calibrated according to your actual sensor.
#define GAS_ALERT_THRESHOLD 1800


// ============================================================
// TELEMETRY SETTINGS
// ============================================================

#define PACKET_INTERVAL 2000

const char *HMAC_KEY = "BLUEPILL_SECRET_KEY_2026";


// ============================================================
// GLOBAL VARIABLES
// ============================================================

uint32_t packetCounter = 1;

bool tamperNextPacket = false;

unsigned long lastPacketTime = 0;


// ============================================================
// CONVERT BYTES TO HEX
// ============================================================

String bytesToHex(const unsigned char *data, size_t len)
{
    String result;

    for (size_t i = 0; i < len; i++)
    {
        if (data[i] < 0x10)
        {
            result += "0";
        }

        result += String(data[i], HEX);
    }

    result.toUpperCase();

    return result;
}


// ============================================================
// CALCULATE HMAC-SHA256
// ============================================================

String calculateHMAC(const String &message)
{
    unsigned char output[32];

    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 1) != 0)
    {
        mbedtls_md_free(&ctx);

        return "";
    }

    mbedtls_md_hmac_starts(
        &ctx,
        (const unsigned char *)HMAC_KEY,
        strlen(HMAC_KEY)
    );

    mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char *)message.c_str(),
        message.length()
    );

    mbedtls_md_hmac_finish(
        &ctx,
        output
    );

    mbedtls_md_free(&ctx);

    return bytesToHex(output, 32);
}


// ============================================================
// READ GAS SENSOR
// ============================================================

int readGasSensor()
{
    return analogRead(GAS_SENSOR_PIN);
}


// ============================================================
// DETERMINE GAS STATUS
// ============================================================

String getGasStatus(int gasValue)
{
    if (gasValue >= GAS_ALERT_THRESHOLD)
    {
        return "ALERT";
    }

    return "NORMAL";
}


// ============================================================
// SEND TELEMETRY
// ============================================================

void sendTelemetry()
{
    // --------------------------------------------------------
    // RUNTIME METRICS
    // --------------------------------------------------------

    unsigned long uptime = millis();

    unsigned long microseconds = micros();

    uint32_t freeHeap = ESP.getFreeHeap();


    // --------------------------------------------------------
    // GAS SENSOR
    // --------------------------------------------------------

    int gasValue = readGasSensor();

    String gasStatus = getGasStatus(gasValue);


    // --------------------------------------------------------
    // CREATE ORIGINAL PACKET
    // --------------------------------------------------------

    String packet =
        "PKT,1.0,MAIN_01," +
        String(packetCounter) + "," +
        String(uptime) + "," +
        String(microseconds) + "," +
        String(freeHeap) +
        ",GAS=" + String(gasValue) +
        ",GAS_STATUS=" + gasStatus +
        ",RUNNING";


    // --------------------------------------------------------
    // CALCULATE HMAC
    //
    // IMPORTANT:
    //
    // HMAC is calculated BEFORE any simulated tampering.
    // --------------------------------------------------------

    String hmac = calculateHMAC(packet);


    // --------------------------------------------------------
    // SIMULATED ATTACK
    // --------------------------------------------------------

    if (tamperNextPacket)
    {
        Serial.println();

        Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        Serial.println("[ATTACK] SIMULATING PACKET TAMPERING");
        Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        Serial.println("[ATTACK] Original packet authenticated");
        Serial.println("[ATTACK] Modifying packet AFTER HMAC");
        Serial.println("[ATTACK] Original HMAC retained");


        // ----------------------------------------------------
        // MODIFY GAS VALUE AFTER HMAC
        //
        // This simulates an attacker changing sensor data.
        // ----------------------------------------------------

        int fakeGasValue = 4095;

        String fakeGasStatus = "ALERT";


        packet =
            "PKT,1.0,MAIN_01," +
            String(packetCounter) + "," +
            String(uptime) + "," +
            String(microseconds) + "," +
            String(freeHeap) +
            ",GAS=" + String(fakeGasValue) +
            ",GAS_STATUS=" + fakeGasStatus +
            ",RUNNING";


        tamperNextPacket = false;
    }


    // ========================================================
    // DISPLAY PACKET
    // ========================================================

    Serial.println();

    Serial.println("========================================");
    Serial.println("           ESP32 MAIN NODE");
    Serial.println("----------------------------------------");

    Serial.print("[TX] PACKET: ");
    Serial.println(packet);

    Serial.print("[TX] HMAC: ");
    Serial.println(hmac);


    // ========================================================
    // SEND DATA TO BLUE PILL
    // ========================================================

    SecuritySerial.print("VERIFY|");
    SecuritySerial.print(packet);
    SecuritySerial.print("|");
    SecuritySerial.print(hmac);
    SecuritySerial.print("\r\n");


    // ========================================================
    // WAIT FOR SECURITY DECISION
    // ========================================================

    unsigned long startTime = millis();

    String response = "";


    while (millis() - startTime < 1500)
    {
        if (SecuritySerial.available())
        {
            char c = SecuritySerial.read();

            if (c == '\n')
            {
                break;
            }

            if (c != '\r')
            {
                response += c;
            }
        }
    }


    // ========================================================
    // DISPLAY SECURITY RESPONSE
    // ========================================================

    if (response.length() > 0)
    {
        Serial.print("[RX] SECURITY: ");
        Serial.println(response);
    }
    else
    {
        Serial.println("[RX] SECURITY: NO RESPONSE");
    }


    // ========================================================
    // PACKET COUNTER
    // ========================================================

    packetCounter++;
}


// ============================================================
// PROCESS COMMANDS
// ============================================================

void processCommand()
{
    if (!Serial.available())
    {
        return;
    }


    String command = Serial.readStringUntil('\n');

    command.trim();


    if (command.length() == 0)
    {
        return;
    }


    // ========================================================
    // ATTACK COMMAND
    // ========================================================

    if (command.equalsIgnoreCase("ATTACK,TAMPER"))
    {
        tamperNextPacket = true;

        Serial.println();

        Serial.println(">>> ATTACK MODE ARMED <<<");

        Serial.println(
            "Next telemetry packet will be tampered."
        );

        Serial.println();
    }


    // ========================================================
    // NORMAL COMMAND
    // ========================================================

    else if (command.equalsIgnoreCase("NORMAL"))
    {
        tamperNextPacket = false;

        Serial.println();

        Serial.println(">>> NORMAL MODE <<<");

        Serial.println(
            "Packet tampering disabled."
        );

        Serial.println();
    }


    // ========================================================
    // STATUS COMMAND
    // ========================================================

    else if (command.equalsIgnoreCase("STATUS"))
    {
        int gasValue = readGasSensor();

        String gasStatus = getGasStatus(gasValue);


        Serial.println();

        Serial.println("=========== ESP32 STATUS ===========");

        Serial.print("Packet Counter : ");
        Serial.println(packetCounter);

        Serial.print("Attack Armed   : ");
        Serial.println(
            tamperNextPacket ? "YES" : "NO"
        );

        Serial.print("Gas Raw Value  : ");
        Serial.println(gasValue);

        Serial.print("Gas Status     : ");
        Serial.println(gasStatus);

        Serial.print("Free Heap      : ");
        Serial.println(ESP.getFreeHeap());

        Serial.println(
            "===================================="
        );

        Serial.println();
    }
}


// ============================================================
// SETUP
// ============================================================

void setup()
{
    // --------------------------------------------------------
    // USB SERIAL
    // --------------------------------------------------------

    Serial.begin(115200);


    // --------------------------------------------------------
    // ESP32 → BLUE PILL UART
    // --------------------------------------------------------

    SecuritySerial.begin(
        115200,
        SERIAL_8N1,
        ESP32_RX,
        ESP32_TX
    );


    // --------------------------------------------------------
    // GAS SENSOR ADC
    // --------------------------------------------------------

    pinMode(GAS_SENSOR_PIN, INPUT);

    analogReadResolution(12);


    // --------------------------------------------------------
    // STARTUP DELAY
    // --------------------------------------------------------

    delay(1000);


    // ========================================================
    // STARTUP MESSAGE
    // ========================================================

    Serial.println();

    Serial.println(
        "========================================"
    );

    Serial.println(
        "           ESP32 MAIN NODE"
    );

    Serial.println(
        "========================================"
    );

    Serial.println(
        "[SYSTEM] ESP32 INITIALIZED"
    );

    Serial.println(
        "[SYSTEM] UART2 INITIALIZED"
    );

    Serial.println(
        "[SYSTEM] SECURITY LINK READY"
    );

    Serial.println(
        "[SYSTEM] MQ-2 GAS SENSOR READY"
    );

    Serial.println(
        "[SYSTEM] HMAC-SHA256 READY"
    );

    Serial.println(
        "[SYSTEM] PHASE 3 READY"
    );


    // ========================================================
    // COMMAND HELP
    // ========================================================

    Serial.println();

    Serial.println("Commands:");

    Serial.println(
        "  ATTACK,TAMPER"
    );

    Serial.println(
        "  NORMAL"
    );

    Serial.println(
        "  STATUS"
    );

    Serial.println();
}


// ============================================================
// LOOP
// ============================================================

void loop()
{
    // --------------------------------------------------------
    // CHECK COMMANDS
    // --------------------------------------------------------

    processCommand();


    // --------------------------------------------------------
    // PERIODIC TELEMETRY
    // --------------------------------------------------------

    if (millis() - lastPacketTime >= PACKET_INTERVAL)
    {
        lastPacketTime = millis();

        sendTelemetry();
    }
}