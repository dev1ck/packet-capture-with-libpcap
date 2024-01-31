#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <netinet/in.h>
#include <net/ethernet.h>

#define kPacketMaxLen 4096
#define kEthMaxLen 1514
#define kArpMaxLen 42
#define kEthertypeIp 0x0800
#define kPseudoHeaderLen 12

// IP 헤더 상수
#define kIpRf 0x8000            /* reserved fragment flag */
#define kIpDf 0x4000            /* dont fragment flag */
#define kIpMf 0x2000            /* more fragments flag */
#define kIpOffmask 0x1fff       /* mask for fragmenting bits */

// TCP 헤더 상수
#define kThFin 0x01
#define kThSyn 0x02
#define kThRst 0x04
#define kThPush 0x08
#define kThAck 0x10
#define kThUrg 0x20

struct __attribute__((__packed__)) EtherHdr
{
	uint8_t  etherDhost[6];		/* destination eth addr	*/
	uint8_t  etherShost[6];		/* source ether addr	*/
	uint16_t etherType;		    /* packet type ID field	*/
};

struct __attribute__((__packed__)) ArpHdr 
{
	uint16_t arHrd;		    // Format of hardware address 
   	uint16_t arPro;		    // Format of protocol address
   	uint8_t arHln;			// Length of hardware address 
   	uint8_t arPln;			// Length of protocol address 
   	uint16_t arOp;			// ARP opcode (command) 
   	uint8_t arSha[6];		// Sender hardware address 
   	uint32_t arSip;		    // Sender IP address 
   	uint8_t arTha[6];		// Target hardware address 
   	uint32_t arTip;		    // Target IP address 
};

struct __attribute__((__packed__)) IpHdr
{
    uint8_t ipHl:4;		    /* header length */
	uint8_t ipV:4;		    /* version */
	uint8_t ipTos;			/* type of service */
	uint16_t ipLen;		    /* total length */
	uint16_t ipId;			/* identification */
	uint16_t ipOff;		    /* fragment offset field */
	uint8_t ipTtl;			/* time to live */
	uint8_t ipP;			/* protocol */
	uint16_t ipSum;		    /* checksum */
	struct in_addr srcIp, dstIp;	/* source and dest address */
};

struct __attribute__((__packed__)) TcpHdr
{
	uint16_t thSport;
    uint16_t thDport;
    uint32_t thSeq;
    uint32_t thAck;
    uint8_t thX2:4;
    uint8_t thOff:4;
    uint8_t thFlags;
    uint16_t thWin;
    uint16_t thSum;
    uint16_t thUrp;
};

struct __attribute__((__packed__)) PseudoHdr
{
    struct in_addr srcIp, dstIp;
    uint8_t reserved;
    uint8_t protocolType;
    uint16_t tcpTotalLength;
};

struct __attribute__((__packed__)) TcpPacket
{
    struct IpHdr ipHdr;
    struct TcpHdr tcpHdr;
};

struct __attribute__((__packed__)) TcpCksumHdr
{
    struct PseudoHdr pseudoHdr;
    struct TcpHdr tcpHdr;
};

struct __attribute__((__packed__)) IcmpHdr
{
    uint8_t  icmpType;
	uint8_t  icmpCode;
	uint16_t icmpCksum;
	uint16_t icmpId;
	uint16_t icmpSeq;
};

struct __attribute__((__packed__)) IcmpPacket
{
    struct IcmpHdr icmp;
	uint8_t data[10];
};

#endif // _PROTOCOL_H
