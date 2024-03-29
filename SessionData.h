#ifndef _SESSION_DATA_H
#define _SESSION_DATA_H

#include <queue>
#include <vector>
#include <pcap/pcap.h>
#include <iostream>
#include <map>
#include "Protocol.h"

enum BufferType
{
    payloadBuffer,
    decryptBuffer
};

enum HeaderCategory
{
    General,
    Request,
    Response,
    Unknown
};

struct RingBuffer
{
private:
    uint32_t head = 0;
    uint32_t tail = 0;
    uint32_t max;
    std::vector<u_char> buffer;
public:
    RingBuffer(uint32_t size = 1048576) : max(size), buffer(size) {}
    std::vector<u_char> getData();
    std::vector<u_char> getData(uint32_t sizeArg);
    std::string getBufferAsString();
    std::string getBufferAsString(uint32_t sizeArg);
    void push(const u_char *data, uint32_t size);
    void pop(uint32_t sizeArg);
    void clear()
    {
        tail = head;
    }
    uint32_t size();
};

struct HttpPacket
{
    std::map<std::string, std::string> headers;
    std::string body = "";
    void clear()
    {
        headers.clear();
        body = "";
    }
};

enum SessionProtocol
{
    UNKNOWN,
    HTTP,
    TLS
};

class SessionData
{
private:
    uint32_t _nextSeq;
    struct timeval _lastPacketTime;
    static bool Compare(const std::pair<uint32_t, std::vector<u_char>>& a, const std::pair<uint32_t, std::vector<u_char>>& b);   
    std::priority_queue<std::pair<uint32_t, std::vector<u_char>>, std::vector<std::pair<uint32_t, std::vector<u_char>>>, decltype(&Compare)> _minHeap;
    RingBuffer _payloadBuffer, _decryptBuffer;
    SessionProtocol _protocol = SessionProtocol::UNKNOWN;
    HttpPacket _httpPacket;
    std::string _sslSessionId = "";
    bool _isServer = false;

public:
    SessionData(uint32_t seq): _nextSeq(seq + 1), _minHeap(Compare), _payloadBuffer() {};
    int insertPacket(const struct pcap_pkthdr *header, const u_char *packet);
    struct timeval getLastPacketTime() { return _lastPacketTime; }
    RingBuffer& getBuffer(BufferType type)
    {
        if (type == BufferType::payloadBuffer)
        {
            return _payloadBuffer;
        }
        else
        {
            return _decryptBuffer;
        }
    }
    int getProtocol() { return _protocol; }
    void setProtocol(SessionProtocol type) { _protocol = type; }
    void setHttpHeader(std::map<std::string, std::string> &header) { _httpPacket.headers = std::move(header); }
    void setHttpBody(std::string body) { _httpPacket.body = std::move(body); }
    std::map<std::string, std::string>& getHttpHeader() { return _httpPacket.headers; }
    std::string& getHttpBody() { return _httpPacket.body; }
    void clearHttpPacket() { _httpPacket.clear(); }
    const struct HttpPacket& getHttpPacket() { return _httpPacket; }
    void setTLSSessionID(const std::string &sessionID) { _sslSessionId = sessionID; }
    std::string getTLSSessionID() { return _sslSessionId; } 
    void setIsServer(bool isServer) { _isServer = isServer; }
    bool getIsServer() { return _isServer; }
};
#endif