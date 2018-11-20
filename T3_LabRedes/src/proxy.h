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

void initPacket(union eth_buffer* packet, uint8_t* src_mac, uint8_t* dst_mac, int isClient, int isServer);

void proxy_sendRawPacket(int sock_fd, union eth_buffer *packet, int dataLength, socket_aux *socketInfo);

int proxy_receivePacket(int sock_fd, union eth_buffer *packet);

void proxy_startProxy();

uint32_t ipchksum(uint8_t *packet);

uint16_t icmpchecksum(uint16_t *buffer, uint32_t size);

void clean_data_buffer(union eth_buffer* packet);

void setSrcIP(union eth_buffer* packet, uint8_t* ip);

void setDstIP(union eth_buffer* packet, uint8_t* ip);

int validateICMPPacket(union eth_buffer* packet);

int getPacketDataLength(union eth_buffer* packet);

#endif // PROXY_HH