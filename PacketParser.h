#ifndef _PACKET_PARSER_H
#define _PACKET_PARSER_H

#endif

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <vector>
#include <fstream>

#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "Protocol.h"
#include "SessionData.h"
#include "Gzip.h"

#define kCaptureTCP 1
#define kCaptureARP 2
#define kUndefined -1

using SessionKey = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>;

std::optional<std::string> parse_tcp_hdr(const struct pcap_pkthdr *header, const u_char *packet);
std::optional<std::string> parse_arp_packet(const struct pcap_pkthdr *header, const u_char *packet);
std::optional<std::string> parse_http_packet(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>>*sessions);
std::optional<std::map<std::string, std::string>> parse_http_header(const std::string &buffer);
std::string parse_http_body(const std::map<std::string, std::string> &headers,const std::string &buffer, const struct timeval &tv);
int reassemble_tcp_payload(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>> *sessions, const SessionKey& session_key);
int classify_protocol(const u_char *packet);

std::string format_timeval(struct timeval tv);
std::string format_mac_address(const uint8_t *mac_addr);
std::string format_ipv4_address(const void *address);
