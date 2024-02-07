#include "SessionData.h"
#include <iostream>

void SessionData::insertPacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    _last_packet_time = header->ts;
    
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));
    const u_char *payload_locate = reinterpret_cast<const u_char*>(tcp_hdr) + (tcp_hdr->offset * 4);

    uint32_t payload_size = ntohs(ip_hdr->ipLen) - (ip_hdr->ipHl * 4) - (tcp_hdr->offset * 4);
    
    if (payload_size == 0)
    {
        return;
    }

    if (ntohl(tcp_hdr->seqNum) == _next_seq)
    {
        insertRingBuffer(payload_locate, payload_size);
    }
    else
    {
        if (_min_heap.size() > 0 and _min_heap.top().first == _next_seq)
        {
            const auto &top = _min_heap.top().second;
            insertRingBuffer(top.data(), top.size());
            _min_heap.pop();

            insertPacket(header, packet);
        }
        std::vector<u_char> saved_payload(payload_size);
        std::copy(payload_locate, payload_locate + payload_size, saved_payload.begin());
        _min_heap.push({ntohl(tcp_hdr->seqNum), saved_payload});
    }
}

void SessionData::insertRingBuffer(const u_char *payload_locate, uint32_t payload_size)
{
    if (_rb_idx + payload_size <= _rb_max)
    {
        std::copy(payload_locate, payload_locate + payload_size, payload.begin() + _rb_idx);
        _rb_idx += payload_size;
    }
    else
    {
        int remaining_size = _rb_max - _rb_idx;
        std::copy(payload_locate, payload_locate + remaining_size, payload.begin() + _rb_idx);
        std::copy(payload_locate + remaining_size, payload_locate + payload_size, payload.begin());
        _rb_idx = payload_size - remaining_size;
        _rb_round = true;
    }
    _next_seq += payload_size;
}

std::string SessionData::getBufferAsString()
{
    if (_rb_round)
    {
        std::string front(payload.begin() + _rb_idx, payload.end());
        std::string back(payload.begin(), payload.begin() + _rb_idx);

        front.append(back);
        return front;
    }
    else
    {
        return std::string(payload.begin(), payload.begin() + _rb_idx);
    }
    
}
