#if !defined(ARPLIB_HH)
#define ARPLIB_HH

#include "arp.h"

// Function that prints in the console the header fields
// related to ARP procotol
void printARPPacket(union eth_buffer *arpPacket);

// Send ARP packet
int sendARPPacket(union eth_buffer *arpPacket);

// Receive ARP packet
int rcvARPPacket(union eth_buffer *arpPacket);

#endif //ARP_LIB