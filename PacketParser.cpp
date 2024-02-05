#include "PacketParser.h"
#include <optional>

std::optional<std::string> parse_tcp_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (not is_tcp_packet(packet))
    {
        return std::nullopt;
    }

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
    const struct ArpHdr *arp_hdr = reinterpret_cast<const struct ArpHdr*>(packet);
  
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
    
    return;
}

std::optional<std::string> parse_http_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (not is_tcp_packet(packet))
    {
        return std::nullopt;
    }

    std::string message;
    message = format_timeval(header->ts) + ' ';

    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(
        reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));
    const u_char *payload = reinterpret_cast<const u_char*>(tcp_hdr) + (tcp_hdr->offset * 4);
    

    
}


bool is_tcp_packet(const u_char *packet)
{
    const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(packet);
    if (htons(ether_hdr->etherType) != kEtherTypeIP)
    {
        return false;
    }

    const struct IpHdr *ip_header = reinterpret_cast<const struct IpHdr*>(packet + sizeof(struct EtherHdr));

    if (ip_header->ipP != kIpTypeTcp)
    {
        return false;
    }

    return true;
}








// std::optional<std::string> parse_packet(const struct pcap_pkthdr *header, const u_char *packet)
// {
//     std::string message;
//     message = format_timeval(header->ts) + ' '; 

//     int type = parse_ethernet_packet(packet);

//     if (type == kEtherTypeARP)
//     {
//         message += "ARP, ";
//         parse_arp_packet(packet + sizeof(struct EtherHdr), message);
//     }
//     else if (type == kEtherTypeIP)
//     {
//         message += "IP ";
//         parse_ip_packet(packet + sizeof(struct EtherHdr), message);
//     }
//     else
//     {
//         message = "undefined";
//     }

//     if (message == "undefined")
//     {
//         return std::nullopt;
//     }

//     message += "length " + std::to_string(header->len);
//     return message;
// }

// int parse_ethernet_packet(const u_char *packet)
// {
//     const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(packet);
//     return htons(ether_hdr->etherType);
// }
   
// void parse_arp_packet(const u_char *packet, std::string &message)
// {
//     const struct ArpHdr *arp_hdr = reinterpret_cast<const struct ArpHdr*>(packet);
    
//     if (ntohs(arp_hdr->arpOp) == kArpRequest)
//     {
//         message += "Request who-has " + format_ipv4_address(&arp_hdr->arpTip) 
//             + " tell " + format_ipv4_address(&arp_hdr->arpSip) + ", ";
//     }
//     else if (ntohs(arp_hdr->arpOp) == kArpReply)
//     {
//         message += "Reply " + format_ipv4_address(&arp_hdr->arpSip)
//             + " is-at " + format_mac_address(arp_hdr->arpSha) + ", ";
//     }
    
//     return;
// }

// void parse_ip_packet(const u_char *packet, std::string &message)
// {
//     const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(packet);

//     if (ip_hdr->ipP != kIpTypeTcp)
//     {
//         message = "undefined";
//         return;
//     }

//     const struct TcpPacket *tcp_packet = reinterpret_cast<const struct TcpPacket*>(packet);
//     message += format_ipv4_address(&tcp_packet->ipHdr.srcIp) + ":" + std::to_string(ntohs(tcp_packet->tcpHdr.srcPort)) + " > ";
//     message += format_ipv4_address(&tcp_packet->ipHdr.dstIp) + ":" + std::to_string(ntohs(tcp_packet->tcpHdr.dstPort)) + " ";
//     parse_tcp_packet(packet + sizeof(struct IpHdr), message);
// }

// void parse_icmp_packet()
// {

// }

// void parse_tcp_packet(const u_char *packet, std::string &message)
// {
//     const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(packet);
//     message += "Flags [";

//     if (tcp_hdr->flags & kURG)
//     {
//         message += 'U';
//     }
//     if (tcp_hdr->flags & kACK)
//     {
//         message += 'A';
//     }
//     if (tcp_hdr->flags & kPSH)
//     {
//         message += 'P';
//     }
//     if (tcp_hdr->flags & kRST)
//     {
//         message += 'R';
//     }
//     if (tcp_hdr->flags & kSYN)
//     {
//         message += 'S';
//     }
//     if (tcp_hdr->flags & kFIN)
//     {
//         message += 'F';
//     }

//     message += "], seq " + std::to_string(ntohl(tcp_hdr->seqNum)) + " ";

//     if (tcp_hdr->flags & kACK)
//     {
//         message += "ack " + std::to_string(ntohl(tcp_hdr->ackNum)) + " ";
//     }
//     message += "win "+ std::to_string(ntohs(tcp_hdr->winSize)) + ", ";
// }


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
