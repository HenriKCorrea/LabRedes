#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

#include "proxy.h"

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

void initPacket(union eth_buffer* packet, uint8_t* src_mac, uint8_t* dst_mac, int isClient, int isServer)
{
	/* Fill the Ethernet frame header */
	memcpy(packet->cooked_data.ethernet.dst_addr, dst_mac, 6);
	memcpy(packet->cooked_data.ethernet.src_addr, src_mac, 6);
	packet->cooked_data.ethernet.eth_type = htons(ETH_P_IP);	//IPV4 packet

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	packet->cooked_data.payload.ip.ver = 0x45;
	packet->cooked_data.payload.ip.tos = 0x00;
	//packet->cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(packet_bytes));
	packet->cooked_data.payload.ip.id = htons(0x00);
	packet->cooked_data.payload.ip.off = htons(0x00);
	packet->cooked_data.payload.ip.ttl = 50;
	packet->cooked_data.payload.ip.proto = 1;			//ICMP (1)

	packet->cooked_data.payload.ip.sum = htons(0x0000);
	// packet->cooked_data.payload.ip.src[0] = 22;
	// packet->cooked_data.payload.ip.src[1] = 0;
	// packet->cooked_data.payload.ip.src[2] = 0;
	// packet->cooked_data.payload.ip.src[3] = 22;
	// packet->cooked_data.payload.ip.dst[0] = 33;
	// packet->cooked_data.payload.ip.dst[1] = 0;
	// packet->cooked_data.payload.ip.dst[2] = 0;
	// packet->cooked_data.payload.ip.dst[3] = 33;
	//packet->cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&packet->cooked_data.payload.ip) & 0xffff));     

	//Fill ICMP header data.

	//Set type according to host
	if(isClient == 1)
	{
		packet->cooked_data.payload.icmp.type = ICMP_ECHO_REQUEST_TYPE; // 0x08 ECHO REQUEST
	}
	else if(isServer == 1)
	{
		packet->cooked_data.payload.icmp.type = ICMP_ECHO_REPLY_TYPE; // 0x00 ECHO REPLY
	}
	else
	{
		packet->cooked_data.payload.icmp.type = 66; 	//Invalid type
	}
	

	packet->cooked_data.payload.icmp.code = 0;	//Code: (0) echo request / reply
	packet->cooked_data.payload.icmp.checksum = 0;
	packet->cooked_data.payload.icmp.identifier = htons(0x17);	//set an random value per transmission (not by packet sent)
	packet->cooked_data.payload.icmp.sequenceNumber = htons(0x01);	//Increment sequence for each echo request packet sent

	/* Fill ICMP payload */
	//memcpy(packet->raw_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), packet_bytes, sizeof(packet_bytes));

	//Calculate ICMP checksum
	//packet->cooked_data.payload.icmp.checksum = icmpchecksum((uint16_t *)&packet->cooked_data.payload.icmp, sizeof(struct icmp_hdr) + sizeof(packet_bytes));	    

	/* Send it.. */
	// memcpy(socket_address.sll_addr, dst_mac, 6);
	// if (sendto(sockfd, packet->raw_data, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(packet_bytes), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	// 	printf("Send failed\n");

	// return 0;
}

void proxy_sendRawPacket(int sock_fd, union eth_buffer *packet, int dataLength, socket_aux *socketInfo)
{	
	//IP Header: set packet length and checksum
	packet->cooked_data.payload.ip.len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + dataLength);
	packet->cooked_data.payload.ip.sum = 0x0000;
	packet->cooked_data.payload.ip.sum = htons((~ipchksum((uint8_t *)&packet->cooked_data.payload.ip) & 0xffff));

	//Calculate ICMP header checksum
	packet->cooked_data.payload.icmp.checksum = 0;
	packet->cooked_data.payload.icmp.checksum = icmpchecksum((uint16_t *)&packet->cooked_data.payload.icmp, sizeof(struct icmp_hdr) + dataLength);

	//Send data
	memcpy(socketInfo->socket_address.sll_addr, packet->cooked_data.ethernet.dst_addr, 6);
	if(sendto(sock_fd, packet->raw_data, FRAME_HEADER_SIZE + dataLength, 0, (struct sockaddr*)&socketInfo->socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("ERROR when sending ICMP packet!");
}

int getDefaultGateway(uint8_t* defaultGatewayMAC, char* destination)
{
	int result = 1;	//Operation result
    char program[100] = {0};    //Instruction to be executed
    char IPAddress[20] = {0};    //program output
	FILE *fp;		//Pipe output

    //get destination IP
    sprintf(program, "route | grep %s | awk '{print $2}'", destination);

	//Create pipe to get program response
	fp = popen(program, "r");	
	
	if (fp == NULL) 
	{
		//Fail to execute command
		printf("Fail to execute command %s\n", program);
		result = -1;
	}
	else
	{
		//Extract program returned IP address
		if(fscanf(fp, "%s", IPAddress) != 1)
			printf("ERROR reading IP Address!\n");
		pclose(fp);

		//Terminate application if IP is invalid
		if ((strlen(IPAddress) < 7) || (strlen(IPAddress) > 15)) 
		{
			result = -1;
			printf("Invalid output of command %s\n", program);
            printf("Returned: %s\n", IPAddress);
		}
	}

    
    //Execute arping command only if previous command has been executed successfully
    if (result == 1) 
    {
        //clear program buffer
        memset(program, 0, 100);

        //query default gateway MAC address
        sprintf(program, "arping %s -f -w 1 |  egrep -o \'\\[.*?\\]\' | tr -d []", IPAddress);

        //Create pipe to get program response
        fp = popen(program, "r");	
        
        if (fp == NULL) 
        {
            //Fail to execute command
            printf("Fail to execute command %s\n", program);
            result = -1;
        }
        else
        {
            //Extract program output
            char MACAddress[20] = {0};    //program output
            if(fscanf(fp, "%s", MACAddress) != 1)
				printf("ERROR reading MAC Address!\n");
            pclose(fp);
            
            //Terminate application if output is invalid
            if (strlen(MACAddress) != 17) 
            {
                result = -1;
                printf("Invalid output of command %s\n", program);
                printf("Returned: %s\n", MACAddress);
            }
            else
            {
                //Scan Gateway MAC
		        if(sscanf(MACAddress, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &defaultGatewayMAC[0], &defaultGatewayMAC[1], &defaultGatewayMAC[2], &defaultGatewayMAC[3], &defaultGatewayMAC[4], &defaultGatewayMAC[5]) != 6)
				{
                	result = -1;
                	printf("Error during attempt to parse MAC Address");
				}
            }
        }
    }

	return result;
}

void clean_data_buffer(union eth_buffer* packet)
{
	memset(packet->raw_data, 0, ETH_LEN);
}

void setSrcIP(union eth_buffer* packet, uint8_t* ip)
{
	packet->cooked_data.payload.ip.src[0] = ip[0];
	packet->cooked_data.payload.ip.src[1] = ip[1];
	packet->cooked_data.payload.ip.src[2] = ip[2];
	packet->cooked_data.payload.ip.src[3] = ip[3];	
}

void setDstIP(union eth_buffer* packet, uint8_t* ip)
{
	packet->cooked_data.payload.ip.dst[0] = ip[0];
	packet->cooked_data.payload.ip.dst[1] = ip[1];
	packet->cooked_data.payload.ip.dst[2] = ip[2];
	packet->cooked_data.payload.ip.dst[3] = ip[3];	
}

int proxy_receivePacket(int sock_fd, union eth_buffer* packet)
{
	return recvfrom(sock_fd, packet->raw_data, ETH_LEN, 0, NULL, NULL);
}

int validateICMPPacket(union eth_buffer* packet)
{
	int result = 1;	//Validation final result

	//Link layer frame validation
	if (ntohs(packet->cooked_data.ethernet.eth_type) != ETH_P_IP) 
	{
		result = 0;
	}
	
	//IP layer frame validation
	if ((result != 1) || 
		(packet->cooked_data.payload.ip.ver != 0x45) || 
		(packet->cooked_data.payload.ip.tos != 0x00) ||
		(packet->cooked_data.payload.ip.proto != 1)) 
	{
		result = 0;
	}

	//ICMP layer validation
	if ((packet->cooked_data.payload.icmp.type != ICMP_ECHO_REQUEST_TYPE) &&
		(packet->cooked_data.payload.icmp.type != ICMP_ECHO_REPLY_TYPE)) 
	{
		result = 0;
	}

	return result;
}

int getPacketDataLength(union eth_buffer* packet)
{
	return (ntohs(packet->cooked_data.payload.ip.len) - (sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)));
}