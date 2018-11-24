/**
 *  tunnel.c
 */

#include "tunnel.h"
#include "raw.h"
#include "socketSetup.h"
#include "proxy.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>


#define DEFAULT_ROUTE   "0.0.0.0"

/**
 * Function to allocate a tunnel
 */
int tun_alloc(char *dev, int flags)
{
  struct ifreq ifr;
  int tun_fd, err;
  char *clonedev = "/dev/net/tun";
  printf("[DEBUG] Allocating tunnel\n");

  tun_fd = open(clonedev, O_RDWR);

  if(tun_fd == -1) {
    perror("Unable to open clone device\n");
    exit(EXIT_FAILURE);
  }
  
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err=ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(tun_fd);
    fprintf(stderr, "Error returned by ioctl(): %s\n", strerror(err));
    perror("Error in tun_alloc()\n");
    exit(EXIT_FAILURE);
  }

  printf("[DEBUG] Allocatating tunnel2");

  printf("[DEBUG] Created tunnel %s\n", dev);

  return tun_fd;
}

/**
 * Function to read from a tunnel
 */
int tun_read(int tun_fd, char *buffer, int length)
{
  int bytes_read;
  printf("[DEBUG] Reading from tunnel\n");
  bytes_read = read(tun_fd, buffer, length);

  if (bytes_read == -1) {
    perror("Unable to read from tunnel\n");
    exit(EXIT_FAILURE);
  }
  else {
    return bytes_read;
  }
}

/**
 * Function to write to a tunnel
 */
int tun_write(int tun_fd, char *buffer, int length)
{
  int bytes_written;
  printf("[DEBUG] Writing to tunnel\n");
  bytes_written = write(tun_fd, buffer, length);

  if (bytes_written == -1) {
    perror("Unable to write to tunnel\n");
    exit(EXIT_FAILURE);
  }
  else {
    return bytes_written;
  }
}

/**
 * Function to run the tunnel
 */
void run_tunnel(uint8_t *dest, int isServer, int isClient)
{
  union eth_buffer packet;
  fd_set fs;  
  int tun_fd = -1;                  //Tunnel interface file descriptor
  int sock_fd = -1;                 //Ethernet interface file descriptor
  //uint8_t dst[4];			            /* destination address */
  uint8_t gateway_mac[6] = {0};     //Default gateway MAC Address
  socket_aux socketInfo;            //Auxiliary struct that holds essential information to send / receive data using raw sockets
  uint8_t *bufferToRead;

  //Open tunnel interface
  tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);
  if (tun_fd == -1) 
  {
    perror("Fail to open tunnel interface.");
    exit(EXIT_FAILURE);
  }
  

  printf("[DEBUG] Starting tunnel - Dest: %s, Server: %d\n", dest, isServer);
  printf("[DEBUG] Opening ICMP socket\n");
  
  //Open ethernet interface
  if (socketSetup("eth0", &socketInfo) == 1) 
  {
    sock_fd = socketInfo.sockfd;
  }
  else
  {
      perror("Fail to open ethernet interface");
      exit(EXIT_FAILURE);
  }

  
  //Set gateway destination name described in acutal host route table
  char gatewayDestination[20] = {0};
  if (isClient == 1) 
  {
    //Gateway is binded to proxy IP
    sprintf(gatewayDestination, "%hhu.%hhu.%hhu.%hhu", dest[0], dest[1], dest[2], dest[3]);
  }
  if (isServer == 1) 
  {
    //Gateway is route table default gateway
    sprintf(gatewayDestination, "default");
  }

  //Get network default gateway MAC address
  if(getDefaultGateway(gateway_mac, gatewayDestination) != 1)
  {
    perror("Fail to get default gateway MAC Address");
    exit(EXIT_FAILURE);
  }  

  int fdRange = 0;  //Holds the highest File Descriptor value (to be used by the select() function)
  if (tun_fd > sock_fd) 
  {
    fdRange = tun_fd + 1;
  }
  else
  {
    fdRange = sock_fd + 1;
  }


  while (1) {
    FD_ZERO(&fs);           //Clean File Descriptor variable 
    FD_SET(tun_fd, &fs);
    FD_SET(sock_fd, &fs);

    //Check which interface (tunnel or ethernet) has new data ready to be read.
    select(fdRange, &fs, NULL, NULL, NULL);

    //If 'fs' flag is set with the tunnel file descriptor value, there's new data available to be read.
    if (FD_ISSET(tun_fd, &fs)) {
      printf("[DEBUG] Data needs to be readed from tun device\n");
      // Reading data from tun device and sending ICMP packet

      printf("[DEBUG] Preparing ICMP packet to be sent\n");

      // Preparing ICMP packet to be sent
      clean_data_buffer(&packet);     //Clean packet buffer

      //mount (init) packet
      initPacket(&packet, socketInfo.this_mac, gateway_mac, isClient, isServer);      

      printf("[DEBUG] Destination address: %s\n", dest);

      /////////////////////////////////////////////////////////////////////////
      //TODO: Set the packet IP source address the default gateway route IP
      /////////////////////////////////////////////////////////////////////////
      setSrcIP(&packet, socketInfo.this_ip);

      /////////////////////////////////////////////////////////////////////////
      //TODO: Set the packet IP destination address the IP given by parameter
      /////////////////////////////////////////////////////////////////////////
      setDstIP(&packet, dest);

      //Get data from tunnel
      int payload_size = tun_read(tun_fd, packet.raw_data + FRAME_HEADER_SIZE /*Pointer to packet data*/, PACKET_DATA_BUFFER_SIZE /*packet data available length*/);

      if(payload_size  == -1) {
        perror("Error while reading from tun device\n");
        exit(EXIT_FAILURE);
      }

      printf("[DEBUG] Sending ICMP packet with payload_size: %d\n", payload_size);

      // Sending ICMP packet
      proxy_sendRawPacket(sock_fd, &packet, FRAME_HEADER_SIZE + payload_size, &socketInfo);
    }

    //If 'fs' flag is set with the ethernet file descriptor value, there's new data available to be read.
    if (FD_ISSET(sock_fd, &fs)) {

      // Getting ICMP packet
      clean_data_buffer(&packet);     //Clean packet buffer
      int payload_size = proxy_receivePacket(sock_fd, &packet); /* CHANGE TO MY FUNCTION */

      //Check if package headers are valid
      if (validateICMPPacket(&packet)) 
      {
        printf("[DEBUG] Read ICMP packet with payload_size: %d\n", payload_size);
        // Writing out to tun device
        tun_write(tun_fd, packet.raw_data + FRAME_HEADER_SIZE, getPacketDataLength(&packet));

        //Overwrite destination address (server) 
        memcpy(dest, packet.cooked_data.payload.ip.src, 4);
      }
    }
  }

}