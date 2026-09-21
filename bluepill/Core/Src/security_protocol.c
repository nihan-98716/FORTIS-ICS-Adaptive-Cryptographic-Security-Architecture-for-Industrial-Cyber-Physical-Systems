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

ThreatLevel Threat_FromPacket(const uint8_t *packet)
{
    const char *marker =
        strstr((const char *)packet, "THREAT_TEST=");

    if (marker == NULL)
    {
        return THREAT_LOW;
    }

    marker += strlen("THREAT_TEST=");

    if (strncmp(marker, "MEDIUM", 6) == 0)
    {
        return THREAT_MEDIUM;
    }

    if (strncmp(marker, "HIGH", 4) == 0)
    {
        return THREAT_HIGH;
    }

    if (strncmp(marker, "CRITICAL", 8) == 0)
    {
        return THREAT_CRITICAL;
    }

    return THREAT_LOW;
}


SecurityPolicy Policy_FromThreat(ThreatLevel threat)
{
    switch (threat)
    {
        case THREAT_LOW:
            return POLICY_LIGHTWEIGHT;

        case THREAT_MEDIUM:
            return POLICY_NORMAL;

        case THREAT_HIGH:
            return POLICY_ENHANCED;

        case THREAT_CRITICAL:
            return POLICY_PARANOID;

        default:
            return POLICY_PARANOID;
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
