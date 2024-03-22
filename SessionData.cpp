#include "SessionData.h"
#include <iostream>


void RingBuffer::push(const u_char *dataLocate, uint32_t dataSize)
{
    if (max - size() < dataSize)
    {
        throw std::runtime_error("Insufficient space in buffer");
    }

    if (head + dataSize <= max)
    {
        std::copy(dataLocate, dataLocate + dataSize, buffer.begin() + head);
        head += dataSize;
    }
    else
    {
        int remainingSize = max - head;
        std::copy(dataLocate, dataLocate + remainingSize, buffer.begin() + head);
        std::copy(dataLocate + remainingSize, dataLocate + dataSize, buffer.begin());
        head = dataSize - remainingSize;
    }
}

void RingBuffer::pop(uint32_t sizeArg)
{
    if (size() < sizeArg)
    {
        throw std::runtime_error("pop error");
    }

    if ( tail + sizeArg >= max)
    {
        tail = (tail + sizeArg) - max;
    }
    else
    {
        tail += sizeArg;
    }

}

std::vector<u_char> RingBuffer::getData()
{
    if (head >= tail)
    {
        return std::vector<u_char>(buffer.begin() + tail, buffer.begin() + head);
    }
    else
    {
        std::vector<u_char> result;
        result.reserve(size());
        result.insert(result.end(), buffer.begin() + tail, buffer.end());
        result.insert(result.end(), buffer.begin(), buffer.begin() + head);
        return result;
    }
}

std::vector<u_char> RingBuffer::getData(uint32_t sizeArg)
{
    if (size() < sizeArg)
    {
        throw std::runtime_error("Get Buffer Error");
    }

    if (tail + sizeArg >= max)
    {
        std::vector<u_char> result;
        result.reserve(sizeArg); // 최적화를 위해 필요한 크기를 미리 예약
        result.insert(result.end(), buffer.begin() + tail, buffer.end());
        result.insert(result.end(), buffer.begin(), buffer.begin() + (sizeArg - tail));
        return result;
    }
    else
    {
        return std::vector<u_char>(buffer.begin() + tail, buffer.begin() + (tail + sizeArg));
    }
}
std::string RingBuffer::getBufferAsString()
{
    std::vector<u_char> buffer = getData();
    return std::string(buffer.begin(), buffer.end());
}

std::string RingBuffer::getBufferAsString(uint32_t sizeArg)
{
    std::vector<u_char> buffer = getData(sizeArg);
    return std::string(buffer.begin(), buffer.end());
}

uint32_t RingBuffer::size()
{
    return head >= tail ? head - tail : (max - tail) + head;
}

std::string RingBuffer::getString();
{
    if (header.size() == 0)
    {
        return "";
    }

    std::string result;

    if (header["Type"] == "Request")
    {
        result += "[Request Headers]\n";

    }
    else
    {
        result += "[Response Headers]\n";
    }

    for (const auto &pair: header)
    {
        result += pair.first + " : " + pair.second + "\n";
    }

    if (not body.empty())
    {
        result += "\n[Body]\n";
        result += body + "\n";
    }
    result += "\n\n";

        return result;
}

int SessionData::insertPacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    _lastPacketTime = header->ts;
    
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));
    const u_char *payloadLocate = reinterpret_cast<const u_char*>(tcpHdr) + (tcpHdr->offset * 4);

    uint32_t payloadSize = ntohs(ipHdr->ipLen) - (ipHdr->ipHl * 4) - (tcpHdr->offset * 4);

    if (payloadSize == 0)
    {
        return 0;
    }
    // std::cout << "next seq : " << _nextSeq << " now seq : " << ntohl(tcpHdr->seqNum) << std::endl;

    if (ntohl(tcpHdr->seqNum) == _nextSeq)
    {
        _payloadBuffer.push(payloadLocate, payloadSize);
        _nextSeq += payloadSize;
    }
    else
    {
        if (_minHeap.size() > 0 and _minHeap.top().first == _nextSeq)
        {
            
            const auto &top = _minHeap.top().second;
            _payloadBuffer.push(top.data(), top.size());
            _nextSeq += top.size();
            _minHeap.pop();

            insertPacket(header, packet);
        }
        std::vector<u_char> savedPayload(payloadSize);
        std::copy(payloadLocate, payloadLocate + payloadSize, savedPayload.begin());
        _minHeap.push({ntohl(tcpHdr->seqNum), savedPayload});
    }
    return payloadSize;
}


bool SessionData::Compare(const std::pair<uint32_t, std::vector<unsigned char>>& a, const std::pair<uint32_t, std::vector<unsigned char>>& b)
{
    return a.first < b.first;
}