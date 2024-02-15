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

enum CaptureType
{
    UNDEFINED_TYPE = -1,
    ALL_TYPE,
    HTTP_TYPE,
    TCP_TYPE,
    ARP_TYPE,
    ICMP_TYPE,
};

using SessionKey = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>;

class PacketParser
{
private:
    const struct pcap_pkthdr *_header;
    const u_char *_packet;
    std::map<SessionKey, std::shared_ptr<SessionData>> *_sessions;
    SessionKey _session_key;

    std::optional<std::map<std::string, std::string>> parse_http_header(const std::string &buffer);
    std::string parse_http_body(const std::map<std::string, std::string> &http_headers, const std::string &buffer);
    int reassemble_tcp_payload();
    std::string format_timeval(struct timeval tv);
    std::string format_mac_address(const uint8_t *mac_addr);
    std::string format_ipv4_address(const void *address);
    void make_session_key();
public:
    PacketParser(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>> *sessions) : _header(header), _packet(packet), _sessions(sessions){}
    std::optional<std::string> parse_tcp_hdr();
    std::optional<std::string> parse_arp_packet();
    std::optional<std::string> parse_http_packet();
    std::optional<std::string> parse_icmp_packet();
    int classify_protocol();
};




