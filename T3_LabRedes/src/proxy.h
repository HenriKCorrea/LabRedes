
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

void mountClientSendPacket();

void proxy_parseReceivedPacket();

void proxy_startProxy();