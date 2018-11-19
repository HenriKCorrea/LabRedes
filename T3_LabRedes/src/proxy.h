#
#if !defined(PROXY_HH)
#define PROXY_HH

#include <stdint.h>
#include "socketSetup.h"
#include "raw.h"

#define PROXY_TUNNEL_NAME "tun0"

#define ICMP_ECHO_REPLY_TYPE 0x00
#define ICMP_ECHO_REPLY_CODE 0x00

#define ICMP_ECHO_REQUEST_TYPE 0x08
#define ICMP_ECHO_REQUEST_CODE 0x00

#define ICMP_NO_CEHCKSUM 0x00


typedef enum returnStatus
{
    PROXY_OP_ERROR,
    PROXY_OP_OK
}retStatus;

void proxy_createICMPSocket(); //OK

retStatus proxy_bindTunnel(); //OK

void initPacket(union eth_buffer* packet, uint8_t* src_mac, uint8_t* dst_mac, int whoAmI);

void proxy_sendRawPacket();

void proxy_parseReceivedPacket();

void proxy_startProxy();

uint16_t icmpchecksum(uint16_t *buffer, uint32_t size);

#endif // PROXY_HH