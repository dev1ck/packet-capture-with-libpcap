#include "PacketParser.h"
#include "SessionData.h"
#include <optional>

std::optional<std::string> parse_tcp_hdr(const struct pcap_pkthdr *header, const u_char *packet)
{
    std::string message;
    message = format_timeval(header->ts) + ' ';
    
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(
        reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));

    message += format_ipv4_address(&ip_hdr->srcIp) + ":" + std::to_string(ntohs(tcp_hdr->srcPort)) + " > ";
    message += format_ipv4_address(&ip_hdr->dstIp) + ":" + std::to_string(ntohs(tcp_hdr->dstPort)) + " ";
    
    message += "Flags [";

    if (tcp_hdr->flags & kURG)
    {
        message += 'U';
    }
    if (tcp_hdr->flags & kACK)
    {
        message += 'A';
    }
    if (tcp_hdr->flags & kPSH)
    {
        message += 'P';
    }
    if (tcp_hdr->flags & kRST)
    {
        message += 'R';
    }
    if (tcp_hdr->flags & kSYN)
    {
        message += 'S';
    }
    if (tcp_hdr->flags & kFIN)
    {
        message += 'F';
    }

    message += "], seq " + std::to_string(ntohl(tcp_hdr->seqNum)) + " ";

    if (tcp_hdr->flags & kACK)
    {
        message += "ack " + std::to_string(ntohl(tcp_hdr->ackNum)) + " ";
    }

    message += "win "+ std::to_string(ntohs(tcp_hdr->winSize)) + ", ";
    message += "length " + std::to_string(header->len);

    return message;
}

std::optional<std::string> parse_arp_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ArpHdr *arp_hdr = reinterpret_cast<const struct ArpHdr*>(packet + sizeof(EtherHdr));
  
    std::string message;
    if (ntohs(arp_hdr->arpOp) == kArpRequest)
    {
        message += "Request who-has " + format_ipv4_address(&arp_hdr->arpTip) 
            + " tell " + format_ipv4_address(&arp_hdr->arpSip) + ", ";
    }
    else if (ntohs(arp_hdr->arpOp) == kArpReply)
    {
        message += "Reply " + format_ipv4_address(&arp_hdr->arpSip)
            + " is-at " + format_mac_address(arp_hdr->arpSha) + ", ";
    }
    else
    {
        return std::nullopt;
    }
    
    return message;
}

std::optional<std::string> parse_http_packet(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>> *sessions)
{
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));

    SessionKey session_key(ip_hdr->srcIp.s_addr, tcp_hdr->srcPort, ip_hdr->dstIp.s_addr, tcp_hdr->dstPort);

    if (not reassemble_tcp_payload(header, packet, sessions, session_key))
    {
        return std::nullopt;
    }

    std::string buffer = (*sessions)[session_key]->getBufferAsString();
    return buffer;


}

int reassemble_tcp_payload(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>> *sessions, const SessionKey& session_key)
{
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));
    
    if (tcp_hdr->flags & kSYN)
    {
        (*sessions)[session_key] = std::make_shared<SessionData>(ntohl(tcp_hdr->seqNum));
        return 0;
    }

    if ((*sessions).count(session_key) == 0)
    {
        return 0;
    }
    
    if(tcp_hdr->flags & (kFIN + kRST))
    {
        (*sessions).erase(session_key);
        return 0;
    }

    (*sessions)[session_key]->insertPacket(header, packet);
    
    return 1;
}

// std::optional<std::string> parse_icmp_packet()
// {

// }


int classify_protocol(const u_char *packet)
{
    const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(packet);
    
    if (ntohs(ether_hdr->etherType) == kEtherTypeARP)
    {
        return kCaptureARP;
    }
    if (ntohs(ether_hdr->etherType) != kEtherTypeIP)
    {
        return kUndefined;
    }

    const struct IpHdr *ip_header = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    if (ip_header->ipP == kIpTypeTcp)
    {
        return kCaptureTCP;
    }

    return kUndefined;
}

std::string format_timeval(struct timeval tv)
{
    std::stringstream ss;
    char buffer[80];

    // 초 단위 시간을 tm 구조체로 변환
    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);

    // tm 구조체를 "시:분:초" 형식으로 포맷
    strftime(buffer, sizeof(buffer), "%H:%M:%S", nowtm);

    // 마이크로초 추가
    ss << buffer << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;

    return ss.str();
}

std::string format_mac_address(const uint8_t *mac_addr)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');

    for (int i = 0; i < 6; ++i)
    {
        stream << std::setw(2) << mac_addr[i];
        if (i < 5)
        {
            stream << ":";
        }
    }
    return stream.str();
}

std::string format_ipv4_address(const void *address)
{
    char str_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, address, str_ip, INET_ADDRSTRLEN);

    return std::string(str_ip);
}
