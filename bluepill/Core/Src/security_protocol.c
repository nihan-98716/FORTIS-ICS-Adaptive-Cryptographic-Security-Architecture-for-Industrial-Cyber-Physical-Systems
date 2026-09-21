#include "security_protocol.h"
#include "security.h"

#include <string.h>

static const uint8_t secretKey[] = SECURITY_KEY;

const char* Threat_ToString(ThreatLevel threat)
{
    switch (threat)
    {
        case THREAT_LOW:
            return "LOW";

        case THREAT_MEDIUM:
            return "MEDIUM";

        case THREAT_HIGH:
            return "HIGH";

        case THREAT_CRITICAL:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}

const char* Policy_ToString(SecurityPolicy policy)
{
    switch (policy)
    {
        case POLICY_LIGHTWEIGHT:
            return "LIGHTWEIGHT";

        case POLICY_NORMAL:
            return "NORMAL";

        case POLICY_ENHANCED:
            return "ENHANCED";

        case POLICY_PARANOID:
            return "PARANOID";

        default:
            return "UNKNOWN";
    }
}

void Security_ProcessPacket(
    uint8_t *packet,
    uint8_t *expected_hmac,
    SecurityDecision *decision)
{
    uint8_t calculated_hmac[HMAC_SHA256_SIZE];

    size_t packetLength = strlen((char *)packet);

    HMAC_SHA256(
        secretKey,
        strlen((char *)secretKey),
        packet,
        packetLength,
        calculated_hmac
    );

    decision->authenticated =
        HMAC_Verify(
            secretKey,
            strlen((char *)secretKey),
            packet,
            packetLength,
            expected_hmac
        );

    if (!decision->authenticated)
    {
        decision->threat = THREAT_CRITICAL;
        decision->policy = POLICY_PARANOID;
    }
    else
    {
        /*
         * Phase 2 baseline:
         * Valid packets operate at LOW/NORMAL.
         *
         * Later phases will use actual runtime
         * and sensor conditions to dynamically
         * escalate this decision.
         */
        decision->threat = THREAT_LOW;
        decision->policy = POLICY_NORMAL;
    }
}
