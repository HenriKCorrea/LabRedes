#if !defined(ARPLIB_HH)
#define ARPLIB_HH

#include "arp.h"

// TODO: colocar estaticamente endereços MAC e IP
// da máquina vitima e do roteador
uint8_t src_hwaddr[6];
uint8_t src_paddr[4];
uint8_t tgt_hwaddr[6];
uint8_t tgt_paddr[4];


// Function that prints in the console the header fields
// related to ARP procotol
void printARPPacket(union eth_buffer *arpPacket);

// Send ARP packet
int sendARPPacket(union eth_buffer *arpPacket);

// Receive ARP packet
int rcvARPPacket(union eth_buffer *arpPacket);

#endif //ARP_LIB