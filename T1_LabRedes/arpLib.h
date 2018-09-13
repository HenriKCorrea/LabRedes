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

//TODO: create function to get my own IP

// Print ARP packet fields
void printARPPacket(union eth_buffer *arpPacket);

// Calls printARPPacket according to pkt
int printPacket(enum arpPkt pkt);

// Send ARP Request Packet
int sendARPRequestPacket(socket_aux *socketInfo, uint8_t *targetIP);

// Send ARP Reply Packet
int sendARPReplyPacket(socket_aux *socketInfo, uint8_t *targetIP, uint8_t *targetMAC, uint8_t *poisonIP);

// Receive ARP packet
int rcvARPPacket(union eth_buffer *arpPacket);

#endif //ARP_LIB