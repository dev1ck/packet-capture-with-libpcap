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
#include <unordered_map>
#include <unordered_set>

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <cstring>

#include "Protocol.h"
#include "SessionData.h"
#include "Gzip.h"
#include "SSLSessionManager.h"

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

    std::optional<std::string> parseHttpPacket(BufferType bufferType);
    std::optional<std::map<std::string, std::string>> parseHttpHeader(const std::string &buffer);
    std::string parseHttpBody(const std::map<std::string, std::string> &http_headers, const std::string &buffer);

    std::optional<std::string> parseTLSPacket();
    bool parseTLSHandhake();
    bool parseTLSApplicationData();
    
    void makeSessionKey();
    SessionKey peerSessionKey();
    bool reassembleTcpPayload();
    bool isHttpProtocol(BufferType bufferType);
    bool isTLSProtocol(BufferType bufferType);
    bool checkCipherSuite(uint16_t cipherSuite);

    std::string formatTimeval(struct timeval tv);
    std::string formatMacAddress(const uint8_t *macAddr);
    std::string formatIpV4Address(const void *address);
    std::string toStringFromHttp(const struct HttpPacket& httpPacket);

    std::optional<SessionProtocol> classifyPayload();
    HeaderCategory categoryHeader(const std::string& headerName);

    std::unordered_map<std::string, std::unordered_set<std::string>> _headersByCategory =
    {
        {
            "General",     
            {
                "Cache-Control", 
                "Connection", 
                "Date",
                "Pragma",
                "Via",
                "Warning",
                "Content-Length",
                "Content-Type",
                "Transfer-Encoding"
            }},
        {
            "Request", 
            {
                "Host",
                "User-Agent",
                "Accept",
                "Accept-Language",
                "Accept-Encoding",
                "Authorization",
                "Referer",
                "Cookie"
            }
        },
        {
            "Response",
            {
                "Server",
                "Set-Cookie",
                "WWW-Authenticate",
                "Location",
                "Content-Encoding",
                "Content-Language"
            }
        }
    }
public:
    PacketParser(const struct pcap_pkthdr *header, const u_char *packet, bool sslMode) : _header(header), _packet(packet), _sslMode(sslMode) {}
    void setSessions(std::map<SessionKey, std::shared_ptr<SessionData>> *sessions) {_sessions = sessions;}
    std::optional<std::string> parseTcpHdr();
    std::optional<std::string> parseArpPacket();
    std::optional<std::string> parseTcpPayload();
    std::optional<std::string> parseIcmpPacket();
    
    int classifyProtocol();
};




