#ifndef _PACKET_PARSER_H
#define _PACKET_PARSER_H

#endif

#include <iostream>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <optional>
#include <pcap/pcap.h>

#include "Protocol.h"

std::optional<std::string> parse_packet(const struct pcap_pkthdr *header, const u_char *packet);
int parse_ethernet_packet(const u_char *packet);
void parse_arp_packet(const u_char *packet, std::string &message);
void parse_ip_packet(const u_char *packet, std::string &message);

std::string format_timeval(struct timeval tv);
std::string format_mac_address(const uint8_t *mac_addr);
std::string format_ipv4_address(const void *address);
