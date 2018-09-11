#include "arpLib.h"

void printARPPacket(union eth_buffer *arpPacket)
{
    printf("HW Type: %d\n", arpPacket->cooked_data.payload.arp.hw_type);
    printf("Protocol Type: %d\n", arpPacket->cooked_data.payload.arp.prot_type);
    printf("Header Lenght: %d\n", arpPacket->cooked_data.payload.arp.hlen);
    printf("Data Lenght: %d\n", arpPacket->cooked_data.payload.arp.plen);
    printf("Operation: %d\n", arpPacket->cooked_data.payload.arp.operation);
    printf("Sender HA: %d.%d.%d.%d.%d.%d\n", arpPacket->cooked_data.payload.arp.src_hwaddr[0],
                                             arpPacket->cooked_data.payload.arp.src_hwaddr[1],
                                             arpPacket->cooked_data.payload.arp.src_hwaddr[2],
                                             arpPacket->cooked_data.payload.arp.src_hwaddr[3],
                                             arpPacket->cooked_data.payload.arp.src_hwaddr[4],
                                             arpPacket->cooked_data.payload.arp.src_hwaddr[5]);
    printf("Sender IP: %d.%d.%d.%d\n", arpPacket->cooked_data.payload.arp.src_paddr[0],
                                       arpPacket->cooked_data.payload.arp.src_paddr[1],
                                       arpPacket->cooked_data.payload.arp.src_paddr[2],
                                       arpPacket->cooked_data.payload.arp.src_paddr[3]);
    printf("Target HA: %d.%d.%d.%d.%d.%d\n", arpPacket->cooked_data.payload.arp.tgt_hwaddr[0],
                                             arpPacket->cooked_data.payload.arp.tgt_hwaddr[1],
                                             arpPacket->cooked_data.payload.arp.tgt_hwaddr[2],
                                             arpPacket->cooked_data.payload.arp.tgt_hwaddr[3],
                                             arpPacket->cooked_data.payload.arp.tgt_hwaddr[4],
                                             arpPacket->cooked_data.payload.arp.tgt_hwaddr[5]);
    printf("Target IP: %d.%d.%d.%d\n", arpPacket->cooked_data.payload.arp.tgt_paddr[0],
                                       arpPacket->cooked_data.payload.arp.tgt_paddr[1],
                                       arpPacket->cooked_data.payload.arp.tgt_paddr[2],
                                       arpPacket->cooked_data.payload.arp.tgt_paddr[3]);
}

int sendARPPacket(union eth_buffer *arpPacket, socket_aux *srcSocketInfo, socket_aux *dstSocketInfo)
{
    //TODO: continuar
    //sendto(srcSocketInfo->sockfd, arpPacket, strlen(arpPacket), 0, dstSocketInfo->sockfd, );
}

int rcvARPPacket(union eth_buffer *arpPacket)
{

}