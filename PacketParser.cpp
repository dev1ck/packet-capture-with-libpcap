#include "PacketParser.h"
#include "SessionManager.h"
#include <optional>

std::optional<std::string> parse_tcp_packet(const struct pcap_pkthdr *header, const u_char *packet)
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
        return nullopt;
    }
    
    return message;
}

std::optional<std::string> parse_http_packet(const struct pcap_pkthdr *header, const u_char *packet, std::map<SessionKey, std::shared_ptr<SessionData>>*sessions)
{
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(
        reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));

    int tcp_size = ntohs(ip_hdr->ipLen) - (ip_hdr->ipHl * 4);
    int payload_size = tcp_size - (tcp_hdr->offset * 4);
    SessionKey session_key(ip_hdr->srcIp, tcp_hdr->srcPort, tcp_hdr->dstIp, ip_hdr->dstPort);
    
    if (tcp_hdr->flags & kSYN)
    {
        (*sessions)[session_key] = make_shared<SessionData>(htonl(tcp_hdr->seqNum));
    }


    if (payload_size > 0)
    {
        vector<u_char> tcp_packet(tcp_size);
        std::copy(tcp_hdr, tcp_hdr + tcp_size, tcp_packet.begin());

        (*sessions)[session_key].vectorPacket.insert(std::move(tcp_packet));        
    }
    
    
}

// std::optional<std::string> parse_icmp_packet()
// {

// }


int classify_protocol(const u_char *packet)
{
    const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(packet);
    
    if (htons(ether_hdr->etherType) == kEtherTypeARP)
    {
        return kCaptureARP;
    }
    if (htons(ether_hdr->etherType) != kEtherTypeIP)
    {
        return kUndefined;
    }

    const struct IpHdr *ip_header = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    if (ip_header->ipP != kIpTypeTcp)
    {
        return kCaptureTCP;
    }

    return -1;
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
