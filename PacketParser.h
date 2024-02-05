#ifndef _PACKET_PARSER_H
#define _PACKET_PARSER_H

#endif

#include <iostream>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <optional>
#include <pcap/pcap.h>
#include <vector>
#include <algorithm> 

#include "Protocol.h"

#define kCaptureALL 0
#define kCaptureTCP 1
#define kCaptureARP 2
#define kUndefined -1

using SessionKey = std::tuple<struct in_addr, uint16_t, struct in_addr, uint16_t>;

struct SessionData
{
    int bodyLength;
    int nowLength = 0;
    int isn;
    std::vector<std::vector<u_char>> vectorPacket;

    SessionData(int isn) : isn(isn) { }
}

std::optional<std::string> parse_tcp_packet(const struct pcap_pkthdr *header, const u_char *packet);
std::optional<std::string> parse_arp_packet(const struct pcap_pkthdr *header, const u_char *packet);
std::optional<std::string> parse_http_packet(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>>*sessions);
int classify_protocol(const u_char *packet);

// int parse_ethernet_packet(const u_char *packet);
// void parse_arp_packet(const u_char *packet, std::string &message);
// void parse_ip_packet(const u_char *packet, std::string &message);
// void parse_tcp_packet(const u_char *packet, std::string &message);

std::string format_timeval(struct timeval tv);
std::string format_mac_address(const uint8_t *mac_addr);
std::string format_ipv4_address(const void *address);
