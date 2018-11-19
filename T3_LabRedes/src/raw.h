#if !defined(RAW_HH)
#define RAW_HH

#include <stdint.h>
#include <stddef.h>

#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct icmp_hdr {
	uint8_t type;	//(8) echo request; (0) echo reply
	uint8_t code;	//(0) echo request / reply
	uint16_t checksum;	//Set (0) to don't calculate any checksum
	uint16_t identifier;			
	uint16_t sequenceNumber;		
};

struct udp_packet {
	struct ip_hdr iphdr;
	struct udp_hdr udphdr;
};

union packet_u {
	struct ip_hdr ip;
	struct udp_packet udp;
};

struct icmp_packet_s {
	struct ip_hdr ip;
	struct icmp_hdr icmp;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	struct icmp_packet_s payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};

//The number of bytes used by all headers in the packet
#define FRAME_HEADER_SIZE sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)

//The available space to be used by the data buffer
#define PACKET_DATA_BUFFER_SIZE ETH_LEN - FRAME_HEADER_SIZE

#endif // RAW_HH