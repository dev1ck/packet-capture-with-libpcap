#include "PacketParser.h"
#include "SessionData.h"


std::optional<std::string> PacketParser::parse_tcp_hdr()
{
    std::string result;
    result = format_timeval(_header->ts) + ' ';
    
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(
        reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));

    result += format_ipv4_address(&ip_hdr->srcIp) + ":" + std::to_string(ntohs(tcp_hdr->srcPort)) + " > ";
    result += format_ipv4_address(&ip_hdr->dstIp) + ":" + std::to_string(ntohs(tcp_hdr->dstPort)) + " ";
    
    result += "Flags [";

    if (tcp_hdr->flags & kURG)
    {
        result += 'U';
    }
    if (tcp_hdr->flags & kACK)
    {
        result += 'A';
    }
    if (tcp_hdr->flags & kPSH)
    {
        result += 'P';
    }
    if (tcp_hdr->flags & kRST)
    {
        result += 'R';
    }
    if (tcp_hdr->flags & kSYN)
    {
        result += 'S';
    }
    if (tcp_hdr->flags & kFIN)
    {
        result += 'F';
    }

    result += "], seq " + std::to_string(ntohl(tcp_hdr->seqNum)) + " ";

    if (tcp_hdr->flags & kACK)
    {
        result += "ack " + std::to_string(ntohl(tcp_hdr->ackNum)) + " ";
    }

    result += "win "+ std::to_string(ntohs(tcp_hdr->winSize)) + ", ";
    result += "length " + std::to_string(_header->len);

    return result;

}
std::optional<std::string> PacketParser::parse_arp_packet()
{
    const struct ArpHdr *arp_hdr = reinterpret_cast<const struct ArpHdr*>(_packet + sizeof(EtherHdr));
  
    std::string result;
    if (ntohs(arp_hdr->arpOp) == kArpRequest)
    {
        result += "Request who-has " + format_ipv4_address(&arp_hdr->arpTip) 
            + " tell " + format_ipv4_address(&arp_hdr->arpSip) + ", ";
    }
    else if (ntohs(arp_hdr->arpOp) == kArpReply)
    {
        result += "Reply " + format_ipv4_address(&arp_hdr->arpSip)
            + " is-at " + format_mac_address(arp_hdr->arpSha) + ", ";
    }
    else
    {
        return std::nullopt;
    }
    
    return result;

}
std::optional<std::string> PacketParser::parse_http_packet()
{
    make_session_key();

    std::string result;

    if (not reassemble_tcp_payload())
    {
        return std::nullopt;
    }

    auto http_headers = parse_http_header((*_sessions)[_session_key]->getBufferAsString());
    if (not http_headers.has_value())
    {
        return std::nullopt;
    }

    uint32_t header_length = std::stoi((*http_headers)["Header-Length"]);
    uint32_t content_length = 0;

    if ((*http_headers).find("Content-Length") != (*http_headers).end())
    {
        content_length = std::stoi((*http_headers)["Content-Length"]);
    }
   
    if (header_length + content_length > (*_sessions)[_session_key]->size())
    {
        return std::nullopt;
    }

    (*_sessions)[_session_key]->pop(header_length);
    
    for (const auto &header: http_headers.value())
    {
        result += header.first + " : " + header.second + "\n";
    }
    
    if (content_length > 0)
    {
        result += "-------------------------------------------\n";
        result += parse_http_body(http_headers.value(), (*_sessions)[_session_key]->getBufferAsString(content_length));
        (*_sessions)[_session_key]->pop(content_length);
    }

    return result;

}

std::optional<std::map<std::string, std::string>> PacketParser::parse_http_header(const std::string &buffer)
{
    std::istringstream stream(buffer);
    std::string line;
    std::map<std::string, std::string> http_headers;
    uint32_t header_length = 0;

    if (not std::getline(stream, line))
    {
        return std::nullopt;   
    }

    header_length += line.length() + 1;

    std::regex request_pattern("^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|TRACE)\\s");
    std::regex response_pattern("^HTTP/");


    if (std::regex_search(line, request_pattern))
    {
        std::istringstream iss(line);
        std::string method, path, version;
        iss >> method >> path >> version;

        http_headers["Type"] = "Request";
        http_headers["Method"] = method;
        http_headers["Path"] = path;
        http_headers["Version"] = version;
    }
    else if (std::regex_search(line, response_pattern))
    {
        std::istringstream iss(line);
        std::string code, version;
        iss >> version >> code;

        http_headers["Type"] = "Response";
        http_headers["Version"] = version;
        http_headers["Code"] = code;
    }
    else
    {
        return std::nullopt;
    }

    bool found_empty_line = false;
    while (std::getline(stream, line))
    {
        header_length += line.length() + 1;
        if (line == "\r")
        {
            found_empty_line = true;
            break;
        }

        std::istringstream header_line(line);
        std::string header_key, header_value;
        if (std::getline(header_line, header_key, ':'))
        {
            if (std::getline(header_line, header_value))
            {
                header_value.erase(0, header_value.find_first_not_of(" "));
                if (not header_value.empty() and header_value.back() == '\r')
                {
                    header_value.pop_back();
                }
                http_headers[header_key] = header_value;
            }
        }
    }

    if (not found_empty_line)
    {
        return std::nullopt;
    }

    http_headers["Header-Length"] = std::to_string(header_length);
    return http_headers;

}

std::string PacketParser::parse_http_body(const std::map<std::string, std::string> &http_headers, const std::string &buffer)
{
    std::regex text_based_pattern(
        R"(text/.*|application/json|application/javascript|application/xml|application/xhtml\+xml)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::regex binary_based_pattern(
        R"(image/.*|application/octet-stream)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    auto it = http_headers.find("Content-Type");
    if (it == http_headers.end())
    {   
        return "Unknown type";
    }

    if (not std::regex_search(it->second, text_based_pattern))
    {
        if (std::regex_search(it->second, binary_based_pattern))
        {
            std::string file_extension = ".bin";
            std::string path = "file/";
            if (it->second.find("image/") != std::string::npos)
            {
                if (it->second.find("jpeg") != std::string::npos)
                {
                    file_extension = ".jpg";
                }
                else if (it->second.find("png") != std::string::npos)
                {
                    file_extension = ".png";
                }
                else if (it->second.find("gif") != std::string::npos)
                {
                    file_extension = ".gif";
                }
            }   
            std::string filename = path + format_timeval(_header->ts) + file_extension;
            std::ofstream file(filename, std::ios::binary);
            if (file.is_open())
            {
                file.write(buffer.data(), buffer.size());
                file.close();
                return "Saved File";
            }
        }   
        return "File not supported";
    }         

    it = http_headers.find("Content-Encoding");
    if (it != http_headers.end() and it->second == "gzip")
    {
        std::string decompress_data;
        codec::Gzip::Decompress(buffer, decompress_data);

        return decompress_data;
    }

    return buffer;
}

int PacketParser::reassemble_tcp_payload()
{
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));
    
    if (tcp_hdr->flags & kSYN)
    {
        (*_sessions)[_session_key] = std::make_shared<SessionData>(ntohl(tcp_hdr->seqNum));
        return 0;
    }

    if ((*_sessions).count(_session_key) == 0)
    {
        return 0;
    }
    
    if(tcp_hdr->flags & (kFIN + kRST))
    {
        (*_sessions).erase(_session_key);
        return 0;
    }

    (*_sessions)[_session_key]->insertPacket(_header, _packet);
    
    return 1;
}

int PacketParser::classify_protocol()
{
    const struct EtherHdr *ether_hdr = reinterpret_cast<const struct EtherHdr*>(_packet);
    
    if (ntohs(ether_hdr->etherType) == kEtherTypeARP)
    {
        return kCaptureARP;
    }
    else if (ntohs(ether_hdr->etherType) != kEtherTypeIP)
    {
        return kUndefined;
    }

    const struct IpHdr *ip_header = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    if (ip_header->ipP == kIpTypeTcp)
    {
        return kCaptureTCP;
    }
    else if (ip_header->ipP == kIpTypeICMP)
    {
        return kCaptureICMP;
    }

    return kUndefined;
}

std::string PacketParser::format_timeval(struct timeval tv)
{
    std::stringstream ss;
    char buffer[80];

    time_t nowtime = tv.tv_sec;
    struct tm *nowtm = localtime(&nowtime);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", nowtm);

    ss << buffer << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;

    return ss.str();
}

std::string PacketParser::format_mac_address(const uint8_t *mac_addr)
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

std::string PacketParser::format_ipv4_address(const void *address)
{
    char str_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, address, str_ip, INET_ADDRSTRLEN);

    return std::string(str_ip);
}

void PacketParser::make_session_key()
{
    const struct IpHdr *ip_hdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcp_hdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ip_hdr) + (ip_hdr->ipHl * 4));

    _session_key = SessionKey(ip_hdr->srcIp.s_addr, tcp_hdr->srcPort, ip_hdr->dstIp.s_addr, tcp_hdr->dstPort);
}
