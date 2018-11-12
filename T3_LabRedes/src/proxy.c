#include "socketSetup.h"
#include "raw.h"
#include "proxy.h"

socket_aux stIcmpSocket;
union eth_buffer unionPacket2Send;
union eth_buffer unionPacket2Recv;

retStatus proxy_createSocket()
{
    int result;
    
    result = socketSetup(PROXY_TUNNEL_NAME, &stIcmpSocket);
    
    if(result != PROXY_OP_OK)
    {
        return PROXY_OP_ERROR;
    }
    else
    {
        return PROXY_OP_OK;
    }
}

retStatus proxy_bindTunnel()
{
    int result;
    struct sockaddr_in serverAddr;


    memset(&serverAddr, 0, sizeof(struct sockaddr_in));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    result = bind(stIcmpSocket.sockfd, (struct sockaddr*)&serverAddr, sizeof(struct sockaddr_in));
    if(result == -1)
    {
        return PROXY_OP_ERROR;
    }

    return PROXY_OP_OK;
}

void mountClientSendPacket()
{
    unionPacket2Send.cooked_data.payload.icmp.code = ICMP_ECHO_REQUEST_CODE;
    unionPacket2Send.cooked_data.payload.icmp.type = ICMP_ECHO_REQUEST_TYPE;
    unionPacket2Send.cooked_data.payload.icmp.checksum = ICMP_NO_CEHCKSUM;
}

void mountServerSendPacket()
{
    unionPacket2Send.cooked_data.payload.icmp.code = ICMP_ECHO_REPLY_CODE;
    unionPacket2Send.cooked_data.payload.icmp.type = ICMP_ECHO_REPLY_TYPE;
    unionPacket2Send.cooked_data.payload.icmp.checksum = ICMP_NO_CEHCKSUM;
}

void proxy_sendRawPacket()
{

}

void proxy_parseReceivedPacket()
{

}

void proxy_startProxy();