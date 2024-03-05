#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <netinet/in.h>
#include <net/ethernet.h>

#define kPacketMaxLen 4096
#define kEthMaxLen 1514
#define kMaxPayloadSize 1480
#define kArpMaxLen 42
#define kPseudoHeaderLen 12

// ethernet type
#define kEtherTypeIP 0x0800
#define kEtherTypeARP 0x0806

// arp type
#define kArpRequest 0x0001
#define kArpReply 0x0002

#define kIpTypeICMP 0x01
#define kIpTypeTcp 0x06

// ICMP type
#define kIcmpTypeEchoReply 0x00
#define kIcmpTypeUnreachable 0x03
#define kIcmpTypeEchoReq 0x08
#define kIcmpTypeTimeExceeded 0x0B

// IP 헤더 상수
#define kRF 0x8000            /* reserved fragment flag */
#define kDF 0x4000            /* dont fragment flag */
#define kMF 0x2000            /* more fragments flag */
#define kOffMask 0x1fff       /* mask for fragmenting bits */

// TCP 헤더 상수
#define kFIN 0x01
#define kSYN 0x02
#define kRST 0x04
#define kPSH 0x08
#define kACK 0x10
#define kURG 0x20

// SSL Record Type
#define SSL3_RT_CHANGE_CIPHER_SPEC 0x14
#define SSL3_RT_ALERT 0x15
#define SSL3_RT_HANDSHAKE 0x16
#define SSL3_RT_APPLICATION_DATA 0x17
#define TLS1_RT_HEARTBEAT 0x18

// SSL Version
#define TLS1_VERSION 0x0301
#define TLS1_1_VERSION 0x0302
#define TLS1_2_VERSION 0x03030

// SSL Handshake Type
#define CLIENT_HELLO 0x01
#define SERVER_HELLO 0x02
#define CLIENT_KEY_EXCHANGE 0x10

// SSL RSA CipherSuite
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x002F
#define TLS_RSA_WITH_AES_256_CBC_SHA 0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003D
#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009D

#define TLS12_MASTER_SECRET_LENGTH 48
#define TLS12_RANDOM_VALUE_LENGTH 32


struct __attribute__((__packed__)) EtherHdr
{
	uint8_t  etherDhost[6];		/* destination eth addr	*/
	uint8_t  etherShost[6];		/* source ether addr	*/
	uint16_t etherType;		    /* packet type ID field	*/
};

struct __attribute__((__packed__)) ArpHdr 
{
	uint16_t arpHrd;		    // Format of hardware address 
   	uint16_t arpPro;		    // Format of protocol address
   	uint8_t arpHln;				// Length of hardware address 
   	uint8_t arpPln;				// Length of protocol address 
   	uint16_t arpOp;				// ARP opcode (command) 
   	uint8_t arpSha[6];			// Sender hardware address 
   	struct in_addr arpSip;		// Sender IP address 
   	uint8_t arpTha[6];			// Target hardware address 
   	struct in_addr arpTip;		// Target IP address 
};

struct __attribute__((__packed__)) IpHdr
{
    uint8_t ipHl:4;		    		/* header length */
	uint8_t ipV:4;		    		/* version */
	uint8_t ipTos;					/* type of service */
	uint16_t ipLen;		    		/* total length */
	uint16_t ipId;					/* identification */
	uint16_t ipOff;		    		/* fragment offset field */
	uint8_t ipTtl;					/* time to live */
	uint8_t ipP;					/* protocol */
	uint16_t ipSum;		    		/* checksum */
	struct in_addr srcIp, dstIp;	/* source and dest address */
};

struct __attribute__((__packed__)) TcpHdr
{
	uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
	uint8_t reserved:4;
    uint8_t offset:4;
	uint8_t flags;
    uint16_t winSize;
    uint16_t checkSum;
    uint16_t urgPoint;
};

struct __attribute__((__packed__)) IcmpHdr
{
    uint8_t  icmpType;
	uint8_t  icmpCode;
	uint16_t icmpCksum;
	uint16_t icmpId;
	uint16_t icmpSeq;
};

struct __attribute__((__packed__)) TLSRecordHdr
{
	uint8_t contentType;
	uint16_t version;
	uint16_t length;
};

struct __attribute__((__packed__)) TLSHandshakeHdr
{
	uint8_t type;
	uint8_t length[3];
};

struct __attribute__((__packed__)) TLSHandshakeHello
{
	uint16_t version;
	uint8_t random[32];
	uint8_t sessionIDLength;
};


// struct __attribute__((__packed__)) PseudoHdr
// {
//     struct in_addr srcIp, dstIp;
//     uint8_t reserved;
//     uint8_t protocolType;
//     uint16_t tcpTotalLength;
// };

// struct __attribute__((__packed__)) TcpCksumHdr
// {
//     struct PseudoHdr pseudoHdr;
//     struct TcpHdr tcpHdr;
// };

// struct __attribute__((__packed__)) IcmpPacket
// {
//     struct IcmpHdr icmp;
// 	   uint8_t data[10];
// };

#endif