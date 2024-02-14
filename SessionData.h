#ifndef _SESSION_DATA_H
#define _SESSION_DATA_H

#include <queue>
#include <vector>
#include <pcap/pcap.h>
#include <iostream>
#include "Protocol.h"


class SessionData
{
private:
    uint32_t _next_seq;
    uint32_t _rb_head = 0;
    uint32_t _rb_tail = 0;
    uint32_t _rb_max = 1048576; // 1MB
    struct timeval _last_packet_time;
    static bool Compare(const std::pair<uint32_t, std::vector<u_char>>& a, const std::pair<uint32_t, std::vector<u_char>>& b);
    std::vector<u_char> _payload = std::vector<u_char>(_rb_max);
    std::priority_queue<std::pair<uint32_t, std::vector<u_char>>, std::vector<std::pair<uint32_t, std::vector<u_char>>>, decltype(&Compare)> _min_heap;

public:
    SessionData(uint32_t seq): _next_seq(seq + 1) {}
    void insertPacket(const struct pcap_pkthdr *header, const u_char *packet);
    std::string getBufferAsString();
    std::string getBufferAsString(uint32_t size_arg);
    void push(const u_char *payload_locate, uint32_t payload_size);
    void pop(uint32_t size_arg);
    uint32_t size();
    struct timeval getLastPacketTime()
    {
        return _last_packet_time;
    }
};

#endif