#include <Arduino.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

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
const char *AES_MASTER_KEY = "CIPHER_M_AES_MASTER_2026";

// ============================================================
// GLOBAL VARIABLES
// ============================================================

uint32_t packetCounter = 1;

bool tamperNextPacket = false;

String testThreatLevel = "LOW";

unsigned long lastPacketTime = 0;

enum CryptoPolicy
{
    CRYPTO_LIGHTWEIGHT,
    CRYPTO_NORMAL,
    CRYPTO_ENHANCED,
    CRYPTO_PARANOID
};

CryptoPolicy currentPolicy = CRYPTO_LIGHTWEIGHT;

uint32_t keyVersion = 1;
uint32_t packetsSinceRotation = 0;

CryptoPolicy parsePolicy(const String &response)
{
    if (response.indexOf(",LIGHTWEIGHT") != -1)
        return CRYPTO_LIGHTWEIGHT;

    if (response.indexOf(",NORMAL") != -1)
        return CRYPTO_NORMAL;

    if (response.indexOf(",ENHANCED") != -1)
        return CRYPTO_ENHANCED;

    if (response.indexOf(",PARANOID") != -1)
        return CRYPTO_PARANOID;

    return CRYPTO_PARANOID;
}

const char *policyToString(CryptoPolicy policy)
{
    switch (policy)
    {
        case CRYPTO_LIGHTWEIGHT:
            return "LIGHTWEIGHT";

        case CRYPTO_NORMAL:
            return "NORMAL";

        case CRYPTO_ENHANCED:
            return "ENHANCED";

        case CRYPTO_PARANOID:
            return "PARANOID";

        default:
            return "UNKNOWN";
    }
}

const char *policyToAlgorithm(CryptoPolicy policy)
{
    switch (policy)
    {
        case CRYPTO_LIGHTWEIGHT:
        case CRYPTO_NORMAL:
            return "AES-128";

        case CRYPTO_ENHANCED:
        case CRYPTO_PARANOID:
            return "AES-256";

        default:
            return "AES-256";
    }
}

uint32_t getRotationInterval(CryptoPolicy policy)
{
    switch (policy)
    {
        case CRYPTO_LIGHTWEIGHT:
            return 0;

        case CRYPTO_NORMAL:
            return 10;

        case CRYPTO_ENHANCED:
            return 5;

        case CRYPTO_PARANOID:
            return 1;

        default:
            return 1;
    }
}

void deriveAESKey(
    CryptoPolicy policy,
    uint32_t version,
    uint8_t *key,
    size_t keyLength
)
{
    uint8_t hash[32];

    char material[128];

    snprintf(
        material,
        sizeof(material),
        "%s|%s|V=%lu",
        AES_MASTER_KEY,
        policyToString(policy),
        (unsigned long)version
    );

    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0)
    {
        memset(key, 0, keyLength);
        mbedtls_md_free(&ctx);
        return;
    }

    mbedtls_md_starts(&ctx);

    mbedtls_md_update(
        &ctx,
        (const unsigned char *)material,
        strlen(material)
    );

    mbedtls_md_finish(&ctx, hash);

    mbedtls_md_free(&ctx);

    memcpy(key, hash, keyLength);
}

// ============================================================
// CONVERT BYTES TO HEX
// ============================================================

bool aesEncrypt(
    const uint8_t *input,
    size_t inputLen,
    const uint8_t iv[16],
    const uint8_t *key,
    unsigned int keyBits,
    uint8_t *output,
    size_t &outputLen
)
{
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(
            &aes,
            key,
            keyBits) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    size_t padding = 16 - (inputLen % 16);

    outputLen = inputLen + padding;

    uint8_t *paddedInput =
        new uint8_t[outputLen];

    if (!paddedInput)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    memcpy(
        paddedInput,
        input,
        inputLen
    );

    for (size_t i = inputLen;
         i < outputLen;
         i++)
    {
        paddedInput[i] =
            (uint8_t)padding;
    }

    uint8_t ivCopy[16];

    memcpy(ivCopy, iv, 16);

    int result =
        mbedtls_aes_crypt_cbc(
            &aes,
            MBEDTLS_AES_ENCRYPT,
            outputLen,
            ivCopy,
            paddedInput,
            output
        );

    delete[] paddedInput;

    mbedtls_aes_free(&aes);

    return result == 0;
}

void updateKeyRotation(CryptoPolicy policy)
{
    bool policyChanged =
        (policy != currentPolicy);

    if (policyChanged)
    {
        currentPolicy = policy;

        keyVersion++;

        packetsSinceRotation = 0;

        Serial.println(
            "[KEY] POLICY CHANGE -> KEY ROTATED"
        );

        return;
    }

    uint32_t interval =
        getRotationInterval(policy);

    if (interval == 0)
        return;

    if (packetsSinceRotation >= interval)
    {
        keyVersion++;

        packetsSinceRotation = 0;

        Serial.println(
            "[KEY] ROTATION EVENT"
        );
    }
}

bool encryptTelemetryPacket(
    const String &packet,
    CryptoPolicy policy,
    String &ivHex,
    String &ciphertextHex,
    String &algorithm,
    uint32_t &usedKeyVersion
)
{
    updateKeyRotation(policy);

    size_t keyLength =
        (policy == CRYPTO_ENHANCED ||
         policy == CRYPTO_PARANOID)
        ? 32
        : 16;

    unsigned int keyBits =
        (keyLength == 32)
        ? 256
        : 128;

    uint8_t derivedKey[32];

    deriveAESKey(
        policy,
        keyVersion,
        derivedKey,
        keyLength
    );

    uint8_t iv[16];

    for (int i = 0; i < 16; i++)
    {
        iv[i] =
            (uint8_t)esp_random();
    }

    uint8_t ciphertext[512];

    size_t ciphertextLen = 0;

    bool success =
        aesEncrypt(
            (const uint8_t *)packet.c_str(),
            packet.length(),
            iv,
            derivedKey,
            keyBits,
            ciphertext,
            ciphertextLen
        );

    if (!success)
        return false;

    ivHex =
        bytesToHex(iv, 16);

    ciphertextHex =
        bytesToHex(
            ciphertext,
            ciphertextLen
        );

    algorithm =
        (keyBits == 256)
        ? "AES-256"
        : "AES-128";

    usedKeyVersion =
        keyVersion;

    packetsSinceRotation++;

    return true;
}

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

    // Add controlled security test condition.
    // This does NOT modify the real MQ-2 value.
    if (testThreatLevel != "LOW")
    {
        packet += ",THREAT_TEST=" + testThreatLevel;
    }


    // --------------------------------------------------------
    // CALCULATE HMAC
    // --------------------------------------------------------

    String hmac = calculateHMAC(packet);


    // --------------------------------------------------------
    // SIMULATED CRITICAL ATTACK
    // --------------------------------------------------------
    // HMAC is calculated BEFORE tampering.
    // The modified packet therefore has an invalid HMAC.

    if (tamperNextPacket)
    {
        Serial.println();
        Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        Serial.println("[ATTACK] SIMULATING PACKET TAMPERING");
        Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        Serial.println("[ATTACK] Original packet authenticated");
        Serial.println("[ATTACK] Modifying packet AFTER HMAC");
        Serial.println("[ATTACK] Original HMAC retained");

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


    // --------------------------------------------------------
    // DISPLAY PACKET
    // --------------------------------------------------------

    Serial.println();
    Serial.println("========================================");
    Serial.println("           ESP32 MAIN NODE");
    Serial.println("----------------------------------------");

    Serial.print("[TX] PACKET: ");
    Serial.println(packet);

    Serial.print("[TX] HMAC: ");
    Serial.println(hmac);


    // --------------------------------------------------------
    // SEND DATA TO BLUE PILL
    // --------------------------------------------------------

    SecuritySerial.print("VERIFY|");
    SecuritySerial.print(packet);
    SecuritySerial.print("|");
    SecuritySerial.print(hmac);
    SecuritySerial.print("\r\n");


    // --------------------------------------------------------
    // WAIT FOR SECURITY DECISION
    // --------------------------------------------------------

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


    // --------------------------------------------------------
    // SECURITY DECISION
    // --------------------------------------------------------

    if (response.length() > 0)
    {
        Serial.print("[RX] SECURITY: ");
        Serial.println(response);


        // ====================================================
        // VALID PACKET
        // ====================================================

        if (response.indexOf(",VALID,") != -1)
        {
            Serial.println(
                "[PHASE 4] AUTHENTICATION VALID"
            );

            Serial.println(
                "[PHASE 4] AES ENCRYPTION AUTHORIZED"
            );


            // ------------------------------------------------
            // GET POLICY FROM BLUE PILL
            // ------------------------------------------------

            CryptoPolicy policy =
                parsePolicy(response);


            // ------------------------------------------------
            // AES ENCRYPTION
            // ------------------------------------------------

            String ivHex;
            String ciphertextHex;
            String algorithm;

            uint32_t usedKeyVersion = 0;

            bool encrypted =
                encryptTelemetryPacket(
                    packet,
                    policy,
                    ivHex,
                    ciphertextHex,
                    algorithm,
                    usedKeyVersion
                );


            // ------------------------------------------------
            // ENCRYPTION RESULT
            // ------------------------------------------------

            if (encrypted)
            {
                Serial.println(
                    "[AES] ENCRYPTION SUCCESS"
                );

                Serial.print(
                    "[AES] POLICY: "
                );

                Serial.println(
                    policyToString(policy)
                );

                Serial.print(
                    "[AES] ALGORITHM: "
                );

                Serial.println(
                    algorithm
                );

                Serial.print(
                    "[AES] KEY VERSION: "
                );

                Serial.println(
                    usedKeyVersion
                );

                Serial.print(
                    "[AES] IV: "
                );

                Serial.println(
                    ivHex
                );

                Serial.print(
                    "[AES] CIPHERTEXT: "
                );

                Serial.println(
                    ciphertextHex
                );


                // --------------------------------------------
                // FINAL ENCRYPTED FRAME
                // --------------------------------------------

                Serial.print(
                    "ENCRYPTED,PKT="
                );

                Serial.print(
                    packetCounter
                );

                Serial.print(
                    ",POLICY="
                );

                Serial.print(
                    policyToString(policy)
                );

                Serial.print(
                    ",ALG="
                );

                Serial.print(
                    algorithm
                );

                Serial.print(
                    ",KEYVER="
                );

                Serial.print(
                    usedKeyVersion
                );

                Serial.print(
                    ",IV="
                );

                Serial.print(
                    ivHex
                );

                Serial.print(
                    ",DATA="
                );

                Serial.println(
                    ciphertextHex
                );
            }
            else
            {
                Serial.println(
                    "[AES] ENCRYPTION FAILED"
                );
            }
        }


        // ====================================================
        // INVALID PACKET
        // ====================================================

        else if (response.indexOf(",INVALID,") != -1)
        {
            /*
             * IMPORTANT:
             *
             * Nothing cryptographic happens here.
             *
             * No parsePolicy()
             * No updateKeyRotation()
             * No AES
             * No encrypted transmission.
             */

            Serial.println(
                "[SECURITY] PACKET REJECTED"
            );

            Serial.println(
                "[SECURITY] AES ENCRYPTION BLOCKED"
            );
        }


        // ====================================================
        // UNKNOWN SECURITY RESPONSE
        // ====================================================

        else
        {
            Serial.println(
                "[SECURITY] UNKNOWN SECURITY RESPONSE"
            );

            Serial.println(
                "[SECURITY] AES ENCRYPTION BLOCKED"
            );
        }
    }
    else
    {
        Serial.println(
            "[RX] SECURITY: NO RESPONSE"
        );

        Serial.println(
            "[SECURITY] AES ENCRYPTION BLOCKED"
        );
    }


    // --------------------------------------------------------
    // PACKET COUNTER
    // --------------------------------------------------------

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
    // LOW SECURITY TEST
    // ========================================================

    if (command.equalsIgnoreCase("ATTACK,LOW"))
    {
        testThreatLevel = "LOW";
        tamperNextPacket = false;

        Serial.println();
        Serial.println(">>> LOW SECURITY MODE <<<");
        Serial.println("Next packet will be evaluated as LOW.");
        Serial.println();
    }


    // ========================================================
    // MEDIUM SECURITY TEST
    // ========================================================

    else if (command.equalsIgnoreCase("ATTACK,MEDIUM"))
    {
        testThreatLevel = "MEDIUM";
        tamperNextPacket = false;

        Serial.println();
        Serial.println(">>> MEDIUM ATTACK MODE <<<");
        Serial.println("Next packet will carry a MEDIUM test condition.");
        Serial.println();
    }


    // ========================================================
    // HIGH SECURITY TEST
    // ========================================================

    else if (command.equalsIgnoreCase("ATTACK,HIGH"))
    {
        testThreatLevel = "HIGH";
        tamperNextPacket = false;

        Serial.println();
        Serial.println(">>> HIGH ATTACK MODE <<<");
        Serial.println("Next packet will carry a HIGH test condition.");
        Serial.println();
    }


    // ========================================================
    // CRITICAL SECURITY TEST
    // ========================================================

    else if (command.equalsIgnoreCase("ATTACK,CRITICAL"))
    {
        testThreatLevel = "CRITICAL";
        tamperNextPacket = true;

        Serial.println();
        Serial.println(">>> CRITICAL ATTACK MODE <<<");
        Serial.println("Next packet will be tampered after HMAC.");
        Serial.println();
    }


    // ========================================================
    // OLD ATTACK COMMAND — KEEP AS ALIAS
    // ========================================================

    else if (command.equalsIgnoreCase("ATTACK,TAMPER"))
    {
        testThreatLevel = "CRITICAL";
        tamperNextPacket = true;

        Serial.println();
        Serial.println(">>> CRITICAL ATTACK MODE <<<");
        Serial.println("Next packet will be tampered after HMAC.");
        Serial.println();
    }


    // ========================================================
    // NORMAL
    // ========================================================

    else if (command.equalsIgnoreCase("NORMAL"))
    {
        testThreatLevel = "LOW";
        tamperNextPacket = false;

        Serial.println();
        Serial.println(">>> NORMAL MODE <<<");
        Serial.println("Adaptive security test disabled.");
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
    Serial.println("  ATTACK,LOW");
    Serial.println("  ATTACK,MEDIUM");
    Serial.println("  ATTACK,HIGH");
    Serial.println("  ATTACK,CRITICAL");
    Serial.println("  NORMAL");
    Serial.println("  STATUS");
    Serial.println();

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