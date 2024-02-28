#include "PacketParser.h"
#include "SessionData.h"


std::optional<std::string> PacketParser::parseTcpHdr()
{
    std::string result;
    result = formatTimeval(_header->ts) + ' ';
    
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(
        reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));

    result += formatIpV4Address(&ipHdr->srcIp) + ":" + std::to_string(ntohs(tcpHdr->srcPort)) + " > ";
    result += formatIpV4Address(&ipHdr->dstIp) + ":" + std::to_string(ntohs(tcpHdr->dstPort)) + " ";
    
    result += "Flags [";

    if (tcpHdr->flags & kURG)
    {
        result += 'U';
    }
    if (tcpHdr->flags & kACK)
    {
        result += 'A';
    }
    if (tcpHdr->flags & kPSH)
    {
        result += 'P';
    }
    if (tcpHdr->flags & kRST)
    {
        result += 'R';
    }
    if (tcpHdr->flags & kSYN)
    {
        result += 'S';
    }
    if (tcpHdr->flags & kFIN)
    {
        result += 'F';
    }

    result += "], seq " + std::to_string(ntohl(tcpHdr->seqNum)) + " ";

    if (tcpHdr->flags & kACK)
    {
        result += "ack " + std::to_string(ntohl(tcpHdr->ackNum)) + " ";
    }

    result += "win "+ std::to_string(ntohs(tcpHdr->winSize)) + ", ";
    result += "length " + std::to_string(_header->len);

    return result;

}
std::optional<std::string> PacketParser::parseArpPacket()
{
    const struct ArpHdr *arpHdr = reinterpret_cast<const struct ArpHdr*>(_packet + sizeof(EtherHdr));
  
    std::string result;
    result = formatTimeval(_header->ts) + ' ';

    if (ntohs(arpHdr->arpOp) == kArpRequest)
    {
        result += "Request who-has " + formatIpV4Address(&arpHdr->arpTip) 
            + " tell " + formatIpV4Address(&arpHdr->arpSip);
    }
    else if (ntohs(arpHdr->arpOp) == kArpReply)
    {
        result += "Reply " + formatIpV4Address(&arpHdr->arpSip)
            + " is-at " + formatMacAddress(arpHdr->arpSha);
    }
    else
    {
        return std::nullopt;
    }
    
    return result;

}
std::optional<std::string> PacketParser::parseHttpPacket()
{
    makeSessionKey();

    std::string result;

    if (not reassembleTcpPayload())
    {
        return std::nullopt;
    }

    
    auto httpHeaders = parseHttpHeader((*_sessions)[_sessionKey]->getBufferAsString());
    if (not httpHeaders.has_value())
    {
        return std::nullopt;
    }

    uint32_t headerLength = std::stoi((*httpHeaders)["Header-Length"]);
    uint32_t contentLength = 0;

    if ((*httpHeaders).find("Content-Length") != (*httpHeaders).end())
    {
        contentLength = std::stoi((*httpHeaders)["Content-Length"]);
    }
   
    uint32_t httpPacketSize = headerLength + contentLength;

    if (httpPacketSize > (*_sessions)[_sessionKey]->getBufferSize())
    {
        return std::nullopt;
    }
    else if (httpPacketSize < (*_sessions)[_sessionKey]->getBufferSize())
    {
        (*_sessions).erase(_sessionKey);
        return "Invalid Packet";
    }

    (*_sessions)[_sessionKey]->deleteBuffer(headerLength);
    
    for (const auto &header: httpHeaders.value())
    {
        result += header.first + " : " + header.second + "\n";
    }
    
    if (contentLength > 0)
    {
        result += "-------------------------------------------\n";
        result += parseHttpBody(httpHeaders.value(), (*_sessions)[_sessionKey]->getBufferAsString(contentLength));
        result += "\n-------------------------------------------\n";
        (*_sessions)[_sessionKey]->deleteBuffer(contentLength);
    }

    return result;
}

std::optional<std::map<std::string, std::string>> PacketParser::parseHttpHeader(const std::string &buffer)
{
    std::istringstream stream(buffer);
    std::string line;
    std::map<std::string, std::string> httpHeaders;
    uint32_t headerLength = 0;

    if (not std::getline(stream, line))
    {
        return std::nullopt;   
    }

    // line 길이 + 1(\n) headerLength에 저장
    headerLength += line.length() + 1;

    std::regex request_pattern("^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|TRACE)\\s");
    std::regex response_pattern("^HTTP/");

    if (std::regex_search(line, request_pattern))
    {
        std::istringstream iss(line);
        std::string method, path, version;
        iss >> method >> path >> version;

        httpHeaders["Type"] = "Request";
        httpHeaders["Method"] = method;
        httpHeaders["Path"] = path;
        httpHeaders["Version"] = version;
    }
    else if (std::regex_search(line, response_pattern))
    {
        std::istringstream iss(line);
        std::string code, version;
        iss >> version >> code;

        httpHeaders["Type"] = "Response";
        httpHeaders["Version"] = version;
        httpHeaders["Code"] = code;
    }
    else
    {
        (*_sessions).erase(_sessionKey);
        return std::nullopt;
    }

    bool found_empty_line = false;
    while (std::getline(stream, line))
    {
        headerLength += line.length() + 1;
        if (line == "\r")
        {
            found_empty_line = true;
            break;
        }

        std::istringstream headerLine(line);
        std::string header_key, headerValue;
        if (std::getline(headerLine, header_key, ':'))
        {
            if (std::getline(headerLine, headerValue))
            {
                headerValue.erase(0, headerValue.find_first_not_of(" "));
                if (not headerValue.empty() and headerValue.back() == '\r')
                {
                    headerValue.pop_back();
                }
                httpHeaders[header_key] = headerValue;
            }
        }
    }

    if (not found_empty_line)
    {
        return std::nullopt;
    }

    httpHeaders["Header-Length"] = std::to_string(headerLength);
    return httpHeaders;

}

std::string PacketParser::parseHttpBody(const std::map<std::string, std::string> &httpHeaders, const std::string &buffer)
{
    std::regex textBasedPattern(
        R"(text/.*|application/json|application/javascript|application/xml|application/xhtml\+xml)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::regex binaryBasedPattern(
        R"(image/.*|application/octet-stream)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    auto it = httpHeaders.find("Content-Type");
    if (it == httpHeaders.end())
    {   
        return "Unknown type";
    }

    if (not std::regex_search(it->second, textBasedPattern))
    {
        if (std::regex_search(it->second, binaryBasedPattern))
        {
            std::string fileExtension = ".bin";
            std::string path = "files/";
            if (it->second.find("image/") != std::string::npos)
            {
                if (it->second.find("jpeg") != std::string::npos)
                {
                    fileExtension = ".jpg";
                }
                else if (it->second.find("png") != std::string::npos)
                {
                    fileExtension = ".png";
                }
                else if (it->second.find("gif") != std::string::npos)
                {
                    fileExtension = ".gif";
                }
            }   
            std::string filename = path + formatTimeval(_header->ts) + fileExtension;
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

    it = httpHeaders.find("Content-Encoding");
    if (it != httpHeaders.end() and it->second == "gzip")
    {
        std::string decompress_data;
        codec::Gzip::Decompress(buffer, decompress_data);

        return decompress_data;
    }

    return buffer;
}

std::optional<std::string> PacketParser::parseIcmpPacket()
{
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct IcmpHdr *icmpHdr = reinterpret_cast<const struct IcmpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));

    std::string result;
    result = formatTimeval(_header->ts) + " IP ";
    result += formatIpV4Address(&ipHdr->srcIp) + " > ";
    result += formatIpV4Address(&ipHdr->dstIp) + " ICMP ";

    switch(icmpHdr->icmpType)
    {
        case kIcmpTypeEchoReply:
            result += "echo reply, ";
            break;
        case kIcmpTypeEchoReq:
            result += "echo request, ";
            break;
        case kIcmpTypeTimeExceeded:
            result += "time exceeded, code " + std::to_string(icmpHdr->icmpCode) + ", ";
            break;
        case kIcmpTypeUnreachable:
            result += "destination unreachable, code " +  std::to_string(icmpHdr->icmpCode) + ", ";
            break;
        default:
            return std::nullopt;
    }

    uint16_t icmp_len = ntohs(ipHdr->ipLen) - (ipHdr->ipHl * 4);
    result += "id " + std::to_string(ntohs(icmpHdr->icmpId)) + ", seq " + std::to_string(ntohs(icmpHdr->icmpSeq)) + ", length " + std::to_string(icmp_len);

    return result;
}

int PacketParser::reassembleTcpPayload()
{
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));
    
    if (tcpHdr->flags & kSYN)
    {
        (*_sessions)[_sessionKey] = std::make_shared<SessionData>(ntohl(tcpHdr->seqNum));
        return 0;
    }

    if ((*_sessions).count(_sessionKey) == 0)
    {
        return 0;
    }
    
    if(tcpHdr->flags & (kFIN + kRST))
    {
        (*_sessions).erase(_sessionKey);
        return 0;
    }

    (*_sessions)[_sessionKey]->insertPacket(_header, _packet);
    
    return 1;
}

int PacketParser::classifyProtocol()
{
    const struct EtherHdr *etherHdr = reinterpret_cast<const struct EtherHdr*>(_packet);
    if (ntohs(etherHdr->etherType) == kEtherTypeARP)
    {
        return ARP_TYPE;
    }
    else if (ntohs(etherHdr->etherType) != kEtherTypeIP)
    {
        return UNDEFINED_TYPE;
    }

    const struct IpHdr *ipHeader = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    if (ipHeader->ipP == kIpTypeTcp)
    {
        return TCP_TYPE;
    }
    else if (ipHeader->ipP == kIpTypeICMP)
    {
        return ICMP_TYPE;
    }

    return UNDEFINED_TYPE;
}

std::string PacketParser::formatTimeval(struct timeval tv)
{
    std::stringstream ss;
    char buffer[9];

    time_t now_time = tv.tv_sec;
    struct tm *now_tm = localtime(&now_time);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", now_tm);

    ss << buffer << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;

    return ss.str();
}

std::string PacketParser::formatMacAddress(const uint8_t *macAddr)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');

    for (int i = 0; i < 6; ++i)
    {
        stream << std::setw(2) << macAddr[i];
        if (i < 5)
        {
            stream << ":";
        }
    }
    return stream.str();
}

std::string PacketParser::formatIpV4Address(const void *address)
{
    char str_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, address, str_ip, INET_ADDRSTRLEN);

    return std::string(str_ip);
}

void PacketParser::makeSessionKey()
{
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));

    _sessionKey = SessionKey(ipHdr->srcIp.s_addr, tcpHdr->srcPort, ipHdr->dstIp.s_addr, tcpHdr->dstPort);
}

uint32_t PacketParser::getSeqNum()
{
    if (classifyProtocol() == TCP_TYPE)
    {
        const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
        const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));

        return ntohl(tcpHdr->seqNum);
    }
    else
    {
        return 0;
    }
}