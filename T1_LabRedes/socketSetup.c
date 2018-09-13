#include "socketSetup.h"

//Create a RAW socket, set interface to promiscuous mode and get the interface MAC Address
//Returns int(1) if operation was a success
//The argument char* argv[1] shall contain the interface name to be used
//All socket related information is returned by the socket_data pointer
int socketSetup(int argc, char* argv[], socket_aux* socket_data)
{
	int result = 1;	//Operation result: 1 = success
	struct ifreq if_idx, if_mac, ifopts, if_ip;	//struct used for interface related system calls
	char ifName[IFNAMSIZ];

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((socket_data->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		result = -1;
		perror("Fail to open socket (SOCK_RAW)");
	}
		
	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Set interface to promiscuous mode */
		strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
		if(ioctl(socket_data->sockfd, SIOCGIFFLAGS, &ifopts) < 0)
		{
			result = -2;
			perror("Fail to get interface data (SIOCGIFFLAGS)");
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		else
		{
			ifopts.ifr_flags |= IFF_PROMISC;
			if(ioctl(socket_data->sockfd, SIOCSIFFLAGS, &ifopts) < 0)
			{
				result = -3;
				perror("Fail to set interface to promiscuous mode (SIOCSIFFLAGS)");
                shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
			}		
		}
		
	}

	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the index of the interface */
		memset(&if_idx, 0, sizeof(struct ifreq));
		strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFINDEX, &if_idx) < 0)
		{
			result = -4;
			perror("Fail to get the interface index (SIOCGIFINDEX)");
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		socket_data->socket_address.sll_ifindex = if_idx.ifr_ifindex;
		socket_data->socket_address.sll_halen = ETH_ALEN;
	}


	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the MAC address of the interface */
		memset(&if_mac, 0, sizeof(struct ifreq));
		strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		{
			result = -5;
			perror("Fail to get the interface MAC Address (SIOCGIFHWADDR)");	
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		//Copy the MAC address to the sockaddr member
		memcpy(socket_data->this_mac, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
	}

	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the IPV4 address of the interface */
		memset(&if_ip, 0, sizeof(struct ifreq));
		strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFADDR, &if_ip) < 0)
		{
			result = -6;
			perror("Fail to get the interface IP Address (SIOCGIFADDR)");	
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		//Copy the IP address to the sockaddr member
		struct sockaddr_in* ipaddr = (struct sockaddr_in*)&if_ip.ifr_addr;
		memcpy(socket_data->this_ip, (uint8_t*)&ipaddr->sin_addr, 4);
	}

	return result;
}
