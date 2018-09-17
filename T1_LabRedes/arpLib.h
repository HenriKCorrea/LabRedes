#if !defined(ARPLIB_HH)
#define ARPLIB_HH

#include "arp.h"
#include "socketSetup.h"

enum arpPkt
{
    REQUEST,
    REPLY,
    RECEIVED
};

static union eth_buffer arpReqPacket;
static union eth_buffer arpRepPacket;
static union eth_buffer arpRcvPacket;

// Function to fill ARP packets headers
void initPackets(socket_aux *socketInfo);

// Calls printARPPacket according to pkt
int printPacket(enum arpPkt pkt);

// Send ARP Request Packet
ssize_t sendARPRequestPacket(socket_aux *socketInfo, uint8_t *targetIP);

// Send ARP Reply Packet
ssize_t sendARPReplyPacket(socket_aux *socketInfo, uint8_t *targetIP, uint8_t *targetMAC, uint8_t *poisonIP);

// Receive ARP packet
ssize_t rcvARPPacket(socket_aux *socketInfo, union eth_buffer *arpRcvPacket);

#endif //ARP_LIB