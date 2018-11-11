#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0xaa, 0x00, 0x01};	//Router R2 MAC address
char src_mac[6] =	{0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};	//Client MAC address

//TCP SYN packet from Client to Service (Doesn't contain Ethernet frame)
//Port: 4444
char packet_bytes[] = {
  0x45, 0x00, 0x00, 0x3c, 0xe9, 0x05, 0x40, 0x00,
  0x3d, 0x06, 0x12, 0x75, 0x16, 0x00, 0x00, 0x16,
  0x2c, 0x00, 0x00, 0x2c, 0xbf, 0xb6, 0x11, 0x5c,
  0xca, 0x12, 0xbd, 0x84, 0x00, 0x00, 0x00, 0x00,
  0xa0, 0x02, 0x72, 0x10, 0x42, 0x70, 0x00, 0x00,
  0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
  0x6c, 0x59, 0x4c, 0x2d, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x03, 0x03, 0x07
};

//route | grep 33.0.0.33 | awk '{print $2}'
//arping 22.0.0.1 -f -w 1 |  egrep -o '\[.*?\]' | tr -d []

union eth_buffer buffer_u;

uint32_t ipchksum(uint8_t *packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

uint16_t icmpchecksum(uint16_t *buffer, uint32_t size) 
{
    unsigned long cksum=0;
    while(size >1) 
    {
        cksum+=*buffer++;
        size -=sizeof(uint16_t);
    }
    if(size ) 
    {
        cksum += *(uint8_t*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;

	/* Get interface name */
	strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */

	/* Fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dst_mac, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, src_mac, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_IP);	//IPV4 packet

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	buffer_u.cooked_data.payload.ip.ver = 0x45;
	buffer_u.cooked_data.payload.ip.tos = 0x00;
	buffer_u.cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(packet_bytes));
	buffer_u.cooked_data.payload.ip.id = htons(0x00);
	buffer_u.cooked_data.payload.ip.off = htons(0x00);
	buffer_u.cooked_data.payload.ip.ttl = 50;
	buffer_u.cooked_data.payload.ip.proto = 1;			//ICMP (1)
	buffer_u.cooked_data.payload.ip.sum = htons(0x0000);
	buffer_u.cooked_data.payload.ip.src[0] = 22;
	buffer_u.cooked_data.payload.ip.src[1] = 0;
	buffer_u.cooked_data.payload.ip.src[2] = 0;
	buffer_u.cooked_data.payload.ip.src[3] = 22;
	buffer_u.cooked_data.payload.ip.dst[0] = 33;
	buffer_u.cooked_data.payload.ip.dst[1] = 0;
	buffer_u.cooked_data.payload.ip.dst[2] = 0;
	buffer_u.cooked_data.payload.ip.dst[3] = 33;
	buffer_u.cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff));

	//Fill ICMP header data.
	buffer_u.cooked_data.payload.icmp.type = 8;	//(8) echo request
	buffer_u.cooked_data.payload.icmp.code = 0; //(0) echo request / reply
	buffer_u.cooked_data.payload.icmp.checksum = 0;
	buffer_u.cooked_data.payload.icmp.identifier = htons(0x17);	//set an random value per transmission (not by packet sent)
	buffer_u.cooked_data.payload.icmp.sequenceNumber = htons(0x01);	//Increment sequence for each echo request packet sent

	/* Fill ICMP payload */
	memcpy(buffer_u.raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), packet_bytes, sizeof(packet_bytes));

	//Calculate ICMP checksum
	buffer_u.cooked_data.payload.icmp.checksum = icmpchecksum((uint16_t *)&buffer_u.cooked_data.payload.icmp, sizeof(struct icmp_hdr) + sizeof(packet_bytes));	

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(packet_bytes), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

	return 0;
}