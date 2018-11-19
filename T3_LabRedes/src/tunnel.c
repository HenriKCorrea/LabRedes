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
 * Function to configure the network
 */
// void configure_network(int server)
// {
//   int pid, status;
//   char path[100];
//   char *const args[] = {path, NULL};

//   if (server) {
//     if (sizeof(SERVER_SCRIPT) > sizeof(path)){
//       perror("Server script path is too long\n");
//       exit(EXIT_FAILURE);
//     }
//     strncpy(path, SERVER_SCRIPT, strlen(SERVER_SCRIPT) + 1);
//   }
//   else {
//     if (sizeof(CLIENT_SCRIPT) > sizeof(path)){
//       perror("Client script path is too long\n");
//       exit(EXIT_FAILURE);
//     }
//     strncpy(path, CLIENT_SCRIPT, strlen(CLIENT_SCRIPT) + 1);
//   }

//   pid = fork();

//   if (pid == -1) {
//     perror("Unable to fork\n");
//     exit(EXIT_FAILURE);
//   }
  
//   if (pid==0) {
//     // Child process, run the script
//     exit(execv(path, args));
//   }
//   else {
//     // Parent process
//     waitpid(pid, &status, 0);
//     if (WEXITSTATUS(status) == 0) {
//       // Script executed correctly
//       printf("[DEBUG] Script ran successfully\n");
//     }
//     else {
//       // Some error
//       printf("[DEBUG] Error in running script\n");
//     }
//   }
// }


/**
 * Function to run the tunnel
 */
void run_tunnel(uint8_t *dest, int isServer, int isClient)
{
  union eth_buffer packet;
  fd_set fs;  
  int tun_fd = -1;    //Tunnel interface file descriptor
  int sock_fd = -1;   //Ethernet interface file descriptor
  //uint8_t dst[4];			/* destination address */
  uint8_t gateway_mac[6] = {0};  //Default gateway MAC Address
  socket_aux socketInfo; //Auxiliary struct that holds essential information to send / receive data using raw sockets

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

  
  //Get network default gateway MAC address
  char gatewayDestination[20] = {0};
  if (isClient == 1) 
  {
    gateway_mac[0] = 0x00;
    gateway_mac[1] = 0x00;
    gateway_mac[2] = 0x00;
    gateway_mac[3] = 0xaa;
    gateway_mac[4] = 0x00;
    gateway_mac[5] = 0x01;
    //sprintf(gatewayDestination, "%hhu.%hhu.%hhu.%hhu", dest[0], dest[1], dest[2], dest[3]);
  }
  if (isServer == 1) 
  {
    gateway_mac[0] = 0x00;
    gateway_mac[1] = 0x00;
    gateway_mac[2] = 0x00;
    gateway_mac[3] = 0xaa;
    gateway_mac[4] = 0x00;
    gateway_mac[5] = 0x05;
    //sprintf(gatewayDestination, "default");
  }
  
  //mount (init) packet
  initPacket(&packet, socketInfo.this_mac, gateway_mac);
  
  // HKC: Não é possível fazer bind quando uma interface é aberta em modo promiscuo.
  // if (server) {
  //   printf("[DEBUG] Binding ICMP socket\n");
  //   bind_icmp_socket(sock_fd); /* CHANGE TO MY FUNCTION */
  // }

  //HKC: Os scripts já devem ser executados automaticamente pelo CORE emulator quando a simulação é inicializada
  //configure_network(server);

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
      memset(packet.raw_data, 0, ETH_LEN);     //Clean packet buffer
      printf("[DEBUG] Destination address: %s\n", dest);

      /////////////////////////////////////////////////////////////////////////
      //TODO: Set the packet IP source address the default gateway route IP
      /////////////////////////////////////////////////////////////////////////
      // if (sizeof(DEFAULT_ROUTE) > sizeof(packet.src_addr)){
      //   perror("Lack of space: size of DEFAULT_ROUTE > size of src_addr\n");
      //   close(tun_fd);
      //   close(sock_fd);
      //   exit(EXIT_FAILURE);
      // }
      //strncpy(packet.src_addr, DEFAULT_ROUTE, strlen(DEFAULT_ROUTE) + 1);
      packet.cooked_data.payload.ip.src[0] = socketInfo.this_ip[0];
      packet.cooked_data.payload.ip.src[1] = socketInfo.this_ip[1];
      packet.cooked_data.payload.ip.src[2] = socketInfo.this_ip[2];
      packet.cooked_data.payload.ip.src[3] = socketInfo.this_ip[3];

      /////////////////////////////////////////////////////////////////////////
      //TODO: Set the packet IP destination address the IP given by parameter
      /////////////////////////////////////////////////////////////////////////
      // if ((strlen(dest) + 1) > sizeof(packet.dest_addr)){
      //   perror("Lack of space for copy size of DEFAULT_ROUTE > size of dest_addr\n");
      //   close(sock_fd);
      //   exit(EXIT_FAILURE);
      // }
      // strncpy(packet.dest_addr, dest, strlen(dest) + 1);
      packet.cooked_data.payload.ip.dst[0] = dest[0];
      packet.cooked_data.payload.ip.dst[1] = dest[1];
      packet.cooked_data.payload.ip.dst[2] = dest[2];
      packet.cooked_data.payload.ip.dst[3] = dest[3];


      if(isServer) 
      {
        //set_reply_type(&packet); /* CHANGE TO MY FUNCTION */
        packet.cooked_data.payload.icmp.type = 0; //Echo reply (0)
      }
      else //isClient
      {
        //set_echo_type(&packet); /* CHANGE TO MY FUNCTION */
        packet.cooked_data.payload.icmp.type = 8; //Echo request (8)
      }

      //HKC: Memory is already allocated in packet variable
      //packet.payload = calloc(MTU, sizeof(uint8_t));
      // if (packet.payload == NULL){
      //   perror("No memory available\n");
      //   exit(EXIT_FAILURE);
      // }

      int payload_size  = tun_read(tun_fd, packet.raw_data + FRAME_HEADER_SIZE /*Pointer to packet data*/, PACKET_DATA_BUFFER_SIZE /*packet data available length*/);

      if(payload_size  == -1) {
        perror("Error while reading from tun device\n");
        exit(EXIT_FAILURE);
      }

      printf("[DEBUG] Sending ICMP packet with payload_size: %d\n", payload_size);
      // Sending ICMP packet
      //send_icmp_packet(sock_fd, &packet); /* CHANGE TO MY FUNCTION */

      //HKC: Malloc is not used by raw packets
      //free(packet.payload);
    }

    //If 'fs' flag is set with the ethernet file descriptor value, there's new data available to be read.
    if (FD_ISSET(sock_fd, &fs)) {
      printf("[DEBUG] Received ICMP packet\n");
      // Reading data from remote socket and sending to tun device

      // Getting ICMP packet
      memset(packet.raw_data, 0, ETH_LEN);
      int payload_size = 0;
      //payload_size = receive_icmp_packet(sock_fd, &packet); /* CHANGE TO MY FUNCTION */

      printf("[DEBUG] Read ICMP packet with payload_size: %d\n", payload_size);
      // Writing out to tun device
      //tun_write(tun_fd, packet.raw_data + FRAME_HEADER_SIZE, payload_size);

      //Overwrite destination address (server) 
      //printf("[DEBUG] Src address being copied: %s\n", packet.src_addr);
      //strncpy(dest, packet.src_addr, strlen(packet.src_addr) + 1);


      //HKC: Malloc is not used by raw packets
      //free(packet.payload);
    }
  }

}