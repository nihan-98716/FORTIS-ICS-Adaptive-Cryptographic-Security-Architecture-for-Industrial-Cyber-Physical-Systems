#ifndef SECURITY_PROTOCOL_H
#define SECURITY_PROTOCOL_H

#include <stdint.h>

#define SECURITY_KEY "BLUEPILL_SECRET_KEY_2026"

#define MAX_PACKET_SIZE 256

typedef enum
{
    THREAT_LOW = 0,
    THREAT_MEDIUM,
    THREAT_HIGH,
    THREAT_CRITICAL
} ThreatLevel;

typedef enum
{
    POLICY_LIGHTWEIGHT = 0,
    POLICY_NORMAL,
    POLICY_ENHANCED,
    POLICY_PARANOID
} SecurityPolicy;

typedef struct
{
    ThreatLevel threat;
    SecurityPolicy policy;
    uint8_t authenticated;
} SecurityDecision;

void Security_ProcessPacket(
    uint8_t *packet,
    uint8_t *expected_hmac,
    SecurityDecision *decision
);

const char* Threat_ToString(ThreatLevel threat);

const char* Policy_ToString(SecurityPolicy policy);

#endif
