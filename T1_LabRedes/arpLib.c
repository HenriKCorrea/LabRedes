#include "arpLib.h"

int initPackets(socket_aux *socketInfo)
{
    // ARP Request Packet
    /* fill payload data (incomplete ARP request example) */
    arpReqPacket.cooked_data.payload.arp.hw_type    = htons(1);	        //Hardware type: 1(Ethernet)
    arpReqPacket.cooked_data.payload.arp.prot_type  = htons(ETH_P_IP);	//Protocol type: IPV4(0x0800)
    arpReqPacket.cooked_data.payload.arp.hlen       = 6;	            //Hardware Length: MAC address length (6 bytes)
    arpReqPacket.cooked_data.payload.arp.plen       = 4;	            //Protocol Length: Length (in octets) of IPV4 address field (4 bytes)
    arpReqPacket.cooked_data.payload.arp.operation  = htons(1);	        //Operation: 1 for Request; 2 for reply
    memcpy(arpReqPacket.cooked_data.payload.arp.src_hwaddr, socketInfo->this_mac, ETH_ALEN);
    //TODO: fill arp.src_paddr
    memset(arpReqPacket.cooked_data.payload.arp.tgt_hwaddr, 0xff, 6);

    // Ethernet Header (victim MAC will be filled in sendARPReplyPacket function)
    arpReqPacket.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);
    memcpy(arpReqPacket.cooked_data.ethernet.src_addr, socketInfo->this_mac, ETH_ALEN);

    
    // ARP Reply Packet
    /* fill payload data (incomplete ARP request example) */
    arpRepPacket.cooked_data.payload.arp.hw_type    = htons(1);	        //Hardware type: 1(Ethernet)
    arpRepPacket.cooked_data.payload.arp.prot_type  = htons(ETH_P_IP);	//Protocol type: IPV4(0x0800)
    arpRepPacket.cooked_data.payload.arp.hlen       = 6;	            //Hardware Length: MAC address length (6 bytes)
    arpRepPacket.cooked_data.payload.arp.plen       = 4;	            //Protocol Length: Length (in octets) of IPV4 address field (4 bytes)
    arpRepPacket.cooked_data.payload.arp.operation  = htons(2);	        //Operation: 1 for Request; 2 for reply
    memcpy(arpReqPacket.cooked_data.payload.arp.src_hwaddr, socketInfo->this_mac, ETH_ALEN);
    //TODO: fill arp.src_paddr

    // Ethernet Header (victim MAC will be filled in sendARPReplyPacket function)
    arpRepPacket.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);
    memcpy(arpRepPacket.cooked_data.ethernet.src_addr, socketInfo->this_mac, ETH_ALEN);
}

void printARPPacket(union eth_buffer *arpPacket)
{
    printf("HW Type: %d\n",         arpPacket->cooked_data.payload.arp.hw_type);
    printf("Protocol Type: %d\n",   arpPacket->cooked_data.payload.arp.prot_type);
    printf("Header Lenght: %d\n",   arpPacket->cooked_data.payload.arp.hlen);
    printf("Data Lenght: %d\n",     arpPacket->cooked_data.payload.arp.plen);
    printf("Operation: %d\n",       arpPacket->cooked_data.payload.arp.operation);
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

int sendARPRequestPacket(socket_aux *socketInfo, uint8_t *targetIP)
{
    memcpy(arpReqPacket.cooked_data.payload.arp.tgt_paddr, targetIP, 4);
    printARPPacket(&arpReqPacket); // debug
    //sendto
}

int sendARPReplyPacket(socket_aux *socketInfo, uint8_t *targetIP, uint8_t *targetMAC, uint8_t *poisonIP)
{
    memcpy(arpReqPacket.cooked_data.payload.arp.src_paddr, poisonIP, 4);
    memcpy(arpReqPacket.cooked_data.payload.arp.tgt_hwaddr, targetMAC, 6);
    memcpy(arpReqPacket.cooked_data.payload.arp.tgt_paddr, targetIP, 4);
    printARPPacket(&arpReqPacket); // debug
    //sendto
}

int rcvARPPacket(union eth_buffer *arpPacket)
{

}