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
    std::map<std::string, std::string> header;
    std::string body = "";
    void clear()
    {
        header.clear();
        body = "";
    }
    std::string getString()
    {
        if (header.size() == 0)
        {
            return "";
        }

        std::string result;

        result += "[" + header["Type"] + "]\n";
        for (const auto &pair: header)
        {
            result += pair.first + " : " + pair.second + "\n";
        }

        if (not body.empty())
        {
            result += "-------------------------------------------\n";
            result += body;
            result += "\n-------------------------------------------\n";
        }

        return result;
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
    void setHttpHeader(std::map<std::string, std::string> &header) { _httpPacket.header = std::move(header); }
    void setHttpBody(std::string body) { _httpPacket.body = std::move(body); }
    std::map<std::string, std::string>& getHttpHeader() { return _httpPacket.header; }
    std::string& getHttpBody() { return _httpPacket.body; }
    void clearHttpPacket() { _httpPacket.clear(); }
    std::string getStringHttpPacket() { return _httpPacket.getString(); }
    void setTLSSessionID(const std::string &sessionID) { _sslSessionId = sessionID; }
    std::string getTLSSessionID() { return _sslSessionId; } 
    void setIsServer(bool isServer) { _isServer = isServer; }
    bool getIsServer() { return _isServer; }
};
#endif