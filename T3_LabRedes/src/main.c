#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "tunnel.h"


void usage(char* programName)
{
  printf("Wrong argument\n");
  printf("usage: %s [--server] | [--client serverip]\n", programName);
}

int main(int argc, char *argv[])
{
    int isClient = 0;
    int isServer = 0;
    int result = 1;
    //char ip_input_arg[15] = "";
    uint8_t ip_arg[4] = {0};

    //check if program has been initialized as a server
    if ((argc == 2) && (strcmp(argv[1], "--server") == 0)) 
    {
        isServer = 1;
    }
    //check if program has been initialized as a client
    else if ((argc == 3) && (strcmp(argv[1], "--client") == 0) && (strlen(argv[2]) <= 15))
    {
        isClient = 1;
		//Scan server IP
		sscanf(argv[2], "%hhu.%hhu.%hhu.%hhu", &ip_arg[0], &ip_arg[1], &ip_arg[2], &ip_arg[3]);        
    }
    //Error: invalid arguments
    else
    {
        usage(argv[0]);
        result = -1;
    }
    
    //Run program if parsing has been completed successfully
    if (result = 1) 
    {
        run_tunnel(ip_arg, isServer, isClient);
    }

    return result;
}