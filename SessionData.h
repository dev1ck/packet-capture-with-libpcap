#ifndef _SESSION_DATA_H
#define _SESSION_DATA_H

#include <queue>
#include <vector>
#include <pcap/pcap.h>
#include <iostream>
#include <map>
#include "Protocol.h"

struct RingBuffer
{
private:
    uint32_t head = 0;
    uint32_t tail = 0;
    uint32_t max;
    std::vector<u_char> buffer;
public:
    RingBuffer(uint32_t size = 1048576) : max(size), buffer(size) {}
    std::vector<u_char> getBuffer();
    std::vector<u_char> getBuffer(uint32_t sizeArg);
    std::string getBufferAsString();
    std::string getBufferAsString(uint32_t sizeArg);
    void push(const u_char *data, uint32_t size);
    void pop(uint32_t sizeArg);
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
    RingBuffer _ringBuffer;
    SessionProtocol _protocol = SessionProtocol::UNKNOWN;
    HttpPacket _httpPacket;
    std::string _sslSessionId = "";
public:
    SessionData(uint32_t seq): _nextSeq(seq + 1), _minHeap(Compare), _ringBuffer() {}
    int insertPacket(const struct pcap_pkthdr *header, const u_char *packet);
    void deleteBuffer(uint32_t sizeArg) { _ringBuffer.pop(sizeArg); }
    std::vector<u_char> getBuffer() { return _ringBuffer.getBuffer(); }
    std::vector<u_char> getBuffer(uint32_t sizeArg) { return _ringBuffer.getBuffer(sizeArg); }
    std::string getBufferAsString()
    {
        std::vector<u_char> buffer = _ringBuffer.getBuffer();
        return std::string(buffer.begin(), buffer.end());
    }
    std::string getBufferAsString(uint32_t sizeArg)
    {
        std::vector<u_char> buffer = _ringBuffer.getBuffer(sizeArg);
        return std::string(buffer.begin(), buffer.end());
    }
    struct timeval getLastPacketTime()
    {
        return _lastPacketTime;
    }
    uint32_t getBufferSize() { return _ringBuffer.size(); }
    int getProtocol() { return _protocol; }
    void setProtocol(SessionProtocol type) { _protocol = type; }
    void setHttpHeader(std::map<std::string, std::string> header) { _httpPacket.header = header; }
    std::map<std::string, std::string> getHttpHeader() { return _httpPacket.header; }
    void setHttpBody(std::string body) { _httpPacket.body = body; }
    std::string getHttpBody() { return _httpPacket.body; }
    void clearHttpPacket() { _httpPacket.clear(); }
    std::string getStringHttpPacket() { return _httpPacket.getString(); }
};

#endif