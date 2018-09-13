#if !defined(ARPLIB_HH)
#define ARPLIB_HH

#include "arp.h"
#include "socketSetup.h"

// for prior test
uint8_t victim_mac[6]   = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};
uint8_t victim_ip[4]    = {0x10, 0x00, 0x00, 0x20};

static union eth_buffer arpReqPacket;
static union eth_buffer arpRepPacket;

// Function to fill ARP packets headers
int initPackets(socket_aux *socketInfo);

//TODO: create function to get my own IP

// Function that prints in the console the header fields
// related to ARP procotol
void printARPPacket(union eth_buffer *arpPacket);

// Send ARP Request Packet
int sendARPRequestPacket(socket_aux *socketInfo, uint8_t *targetIP);

// Send ARP Reply Packet
int sendARPReplyPacket(socket_aux *socketInfo, uint8_t *targetIP, uint8_t *targetMAC, uint8_t *poisonIP);

// Receive ARP packet
int rcvARPPacket(union eth_buffer *arpPacket);

#endif //ARP_LIB