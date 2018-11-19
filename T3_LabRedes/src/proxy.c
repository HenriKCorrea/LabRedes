#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

#include "proxy.h"


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

void initPacket(union eth_buffer* packet, uint8_t* src_mac, uint8_t* dst_mac, int whoAmI)
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
	if(whoAmI == 1)
	{
		packet->cooked_data.payload.icmp.code = ICMP_ECHO_REQUEST_TYPE; // 0x00 ECHO REQUEST
	}
	if(whoAmI == 2)
	{
		packet->cooked_data.payload.icmp.code = ICMP_ECHO_REPLY_TYPE; // 0x08 ECHO REPLY
	}	

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

void proxy_sendRawPacket(int sock_fd, union eth_buffer *packet, int lenght, socket_aux *socketInfo)
{
	sendto(sock_fd, packet->raw_data, lenght, 0, (struct sockaddr*)&socketInfo->socket_address, sizeof(struct sockaddr_ll));
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
	fp = popen(destination, "r");	
	
	if (fp == NULL) 
	{
		//Fail to execute command
		printf("Fail to execute command %s\n", program);
		result = -1;
	}
	else
	{
		//Extract program returned IP address
		fscanf(fp, "%s", IPAddress);
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
        sprintf(program, "arping %s -f -w 1 |  egrep -o '\\[.*?\\]' | tr -d []", IPAddress);

        //Create pipe to get program response
        fp = popen(destination, "r");	
        
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
            fscanf(fp, "%s", MACAddress);
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
		        sscanf(MACAddress, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &defaultGatewayMAC[0], &defaultGatewayMAC[1], &defaultGatewayMAC[2], &defaultGatewayMAC[3], &defaultGatewayMAC[4], &defaultGatewayMAC[5]);
            }
        }
    }

	return result;
}

void clean_data_buffer(union eth_buffer* packet)
{
	int frame = FRAME_HEADER_SIZE;
	int packet_size = PACKET_DATA_BUFFER_SIZE;

	memset(packet->raw_data + FRAME_HEADER_SIZE, 0, PACKET_DATA_BUFFER_SIZE);
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