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
    SessionKey _sessionKey;
    bool _sslMode = false;
    std::string _sslKeyLogFile = "";

    std::optional<std::map<std::string, std::string>> parseHttpHeader(const std::string &buffer);
    std::string parseHttpBody(const std::map<std::string, std::string> &http_headers, const std::string &buffer);
    int reassembleTcpPayload();
    std::string formatTimeval(struct timeval tv);
    std::string formatMacAddress(const uint8_t *macAddr);
    std::string formatIpV4Address(const void *address);
    void makeSessionKey();
    int classifyPayload();
public:
    PacketParser(const struct pcap_pkthdr *header, const u_char *packet) : _header(header), _packet(packet) {}
    void setSessions(std::map<SessionKey, std::shared_ptr<SessionData>> *sessions) {_sessions = sessions;}
    void setSSLKeyLog(std::string keyLogFile)
    {
        _sslKeyLogFile = keyLogFile;
        _sslMode = true;
    };
    std::optional<std::string> parseTcpHdr();
    std::optional<std::string> parseArpPacket();
    std::optional<std::string> parseHttpPacket();
    std::optional<std::string> parseIcmpPacket();
    int classifyProtocol();
    uint32_t getSeqNum();
};




