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
std::optional<std::string> PacketParser::parseTcpPayload()
{
    makeSessionKey();

    if (not reassembleTcpPayload())
    {
        return std::nullopt;
    }

    if ((*_sessions)[_sessionKey]->getProtocol() == SessionProtocol::UNKNOWN)
    {
        auto protocol = classifyPayload();
        if (not protocol.has_value())
        {
            return std::nullopt;
        }
        (*_sessions)[_sessionKey]->setProtocol(protocol.value());
    }
    
    switch ((*_sessions)[_sessionKey]->getProtocol())
    {
        case SessionProtocol::HTTP:
        {
            return parseHttpPacket(BufferType::payloadBuffer);
            break;
        }
        case SessionProtocol::TLS:
        {
            return parseTLSPacket();
        }
        break;
        default:
            return std::nullopt;
    }
}

std::optional<std::string> PacketParser::parseHttpPacket(BufferType bufferType)
{
    RingBuffer &ringBuffer = (*_sessions)[_sessionKey]->getBuffer(bufferType);
    if ((*_sessions)[_sessionKey]->getHttpHeader().size() == 0)
    {
        auto optHttpHeader = std::move(parseHttpHeader(ringBuffer.getBufferAsString()));
        if (not optHttpHeader.has_value())
        {
            return std::nullopt;
        }
        (*_sessions)[_sessionKey]->setHttpHeader(optHttpHeader.value());
        uint32_t headerSize = std::stoi((*_sessions)[_sessionKey]->getHttpHeader()["Header-Length"]);
        ringBuffer.pop(headerSize);
    }
    
    auto& httpHeader = (*_sessions)[_sessionKey]->getHttpHeader();
    uint32_t contentLength = 0;

    if (httpHeader.find("Content-Length") != httpHeader.end())
    {
        contentLength = std::stoi(httpHeader["Content-Length"]);
    }

    if (contentLength > ringBuffer.size())
    {
        return std::nullopt;
    }
    else if (contentLength < ringBuffer.size())
    {
        (*_sessions).erase(_sessionKey);
        return "Invalid Packet";
    }
    
    if (contentLength > 0)
    {
        (*_sessions)[_sessionKey]->setHttpBody(parseHttpBody(httpHeader, ringBuffer.getBufferAsString()));
        ringBuffer.pop(contentLength);
    }


    std::string result = toStringFromHttp((*_sessions)[_sessionKey]->getHttpPacket());
    (*_sessions)[_sessionKey]->clearHttpPacket();

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
        // std::istringstream iss(line);
        // std::string method, path, version;
        // iss >> method >> path >> version;
        
        httpHeaders["Type"] = "Response";
        httpHeaders["StartLine"] = method;
    }
    else if (std::regex_search(line, response_pattern))
    {
        // std::istringstream iss(line);
        // std::string code, version, message;
        // iss >> version >> code >> message;
        
        httpHeaders["Type"] = "Response";
        httpHeaders["StartLine"] = method;
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
    std::string data;
    
    auto it = httpHeaders.find("Content-Encoding");
    if (it != httpHeaders.end() and it->second == "gzip")
    {
        std::string decompress_data;
        codec::Gzip::Decompress(buffer, decompress_data);

        data = std::move(decompress_data);
    }
    else
    {
        data = buffer;
    }

    std::regex textBasedPattern(
        R"(text/.*|application/json|application/javascript|application/xml|application/xhtml\+xml)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::regex binaryBasedPattern(
        R"(image/.*|application/octet-stream)",
        std::regex_constants::ECMAScript | std::regex_constants::icase);

    it = httpHeaders.find("Content-Type");
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
                file.write(data.data(), data.size());
                file.close();
                return "Saved File";
            }
        }   
        return "File not supported";
    }         

    return data;
}

std::optional<std::string> PacketParser::parseTLSPacket()
{
    RingBuffer *ringBuffer = &((*_sessions)[_sessionKey]->getBuffer(BufferType::payloadBuffer));
    std::vector<u_char> buffer = ringBuffer->getData();
    const struct TLSRecordHdr *tlsHdr = reinterpret_cast<const struct TLSRecordHdr*>(buffer.data());
    switch(tlsHdr->contentType)
    {
        case SSL3_RT_HANDSHAKE:
        {
            if (not parseTLSHandhake())
            {
                return std::nullopt;
            }
            ringBuffer->clear();
        }
        break;
        case SSL3_RT_APPLICATION_DATA:
        {
            if (not parseTLSApplicationData())
            {
                return std::nullopt;
            }
            ringBuffer->clear();

            ringBuffer = &((*_sessions)[_sessionKey]->getBuffer(BufferType::decryptBuffer));
            if (isHttpProtocol(BufferType::decryptBuffer))
            {
                return parseHttpPacket(BufferType::decryptBuffer);
            }
        }
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            ringBuffer->clear();
            break;
    }
    return std::nullopt; 
}

bool PacketParser::parseTLSHandhake()
{
    RingBuffer &ringBuffer = (*_sessions)[_sessionKey]->getBuffer(BufferType::payloadBuffer);
    std::vector<u_char> buffer = ringBuffer.getData();
    const struct TLSHandshakeHdr *tlsHandshakeHdr = reinterpret_cast<const struct TLSHandshakeHdr*>(buffer.data() + sizeof(struct TLSRecordHdr));

    switch (tlsHandshakeHdr->type)
    {
        case CLIENT_HELLO:
        {
            const struct TLSHandshakeHello *tlsHandshakeHello = reinterpret_cast<const struct TLSHandshakeHello*>(reinterpret_cast<const u_char*>(tlsHandshakeHdr) + sizeof(struct TLSHandshakeHdr));
            SSLSessionManager::Instance().saveClientRandom(_sessionKey, tlsHandshakeHello->random);
        }
        break;
        case SERVER_HELLO:
        {
            const struct TLSHandshakeHello *tlsHandshakeHello = reinterpret_cast<const struct TLSHandshakeHello*>(reinterpret_cast<const u_char*>(tlsHandshakeHdr) + sizeof(struct TLSHandshakeHdr));
            const u_char* sslSessionIDLocate = reinterpret_cast<const u_char*>(tlsHandshakeHello) + sizeof(TLSHandshakeHello);
            const uint16_t* cipherSuite = reinterpret_cast<const uint16_t*>(sslSessionIDLocate + tlsHandshakeHello->sessionIDLength);

            if (not checkCipherSuite(htons(*cipherSuite)))
            {
                SSLSessionManager::Instance().deleteClientRandom(peerSessionKey());
                (*_sessions).erase(_sessionKey);
                (*_sessions).erase(peerSessionKey());
                return false;
            }

            std::ostringstream stream;
            for (int i = 0; i < tlsHandshakeHello->sessionIDLength; i++)
            {
                stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sslSessionIDLocate[i]);
            }

            std::string tlsSessionID = stream.str();
            SSLSessionManager::Instance().makeTLSSession(tlsSessionID, peerSessionKey(), tlsHandshakeHello->random, htons(*cipherSuite));

            (*_sessions)[_sessionKey]->setTLSSessionID(tlsSessionID);
            (*_sessions)[peerSessionKey()]->setTLSSessionID(tlsSessionID);
        }
        break;
        case CLIENT_KEY_EXCHANGE:
        {
            const uint16_t *preMasterLength = reinterpret_cast<const uint16_t*>(reinterpret_cast<const u_char*>(tlsHandshakeHdr) + sizeof(TLSHandshakeHdr));
            const u_char* encryptedPreMaster = reinterpret_cast<const u_char*>(preMasterLength) + 2;

            if (not SSLSessionManager::Instance().generateMasterSecret((*_sessions)[_sessionKey]->getTLSSessionID(), encryptedPreMaster, ntohs(*preMasterLength)))
            {
                SSLSessionManager::Instance().deleteSession((*_sessions)[_sessionKey]->getTLSSessionID());
                (*_sessions).erase(_sessionKey);
                (*_sessions).erase(peerSessionKey());
                return false;
            }
            SSLSessionManager::Instance().generateSessionKey((*_sessions)[_sessionKey]->getTLSSessionID());
        }
        break;
    }
    return true;
}

bool PacketParser::parseTLSApplicationData()
{
    RingBuffer *ringBuffer = &((*_sessions)[_sessionKey]->getBuffer(BufferType::payloadBuffer));
    std::vector<u_char> buffer = ringBuffer->getData();
    const struct TLSRecordHdr *tlsHdr = reinterpret_cast<const struct TLSRecordHdr*>(buffer.data());
    size_t encryptDataLength = ntohs(tlsHdr->length);
    const u_char* encryptData = reinterpret_cast<const u_char*>(tlsHdr) + sizeof(TLSRecordHdr);

    ringBuffer = &((*_sessions)[_sessionKey]->getBuffer(BufferType::decryptBuffer));
    auto decryptData = SSLSessionManager::Instance().decryptData(encryptData, encryptDataLength, (*_sessions)[_sessionKey]->getTLSSessionID(), (*_sessions)[_sessionKey]->getIsServer());

    if (not decryptData.has_value())
    {
        return false;
    }

    ringBuffer->push(decryptData->data(), decryptData->size());
    return true;
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

bool PacketParser::reassembleTcpPayload()
{
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));
    
    if (tcpHdr->flags & kSYN)
    {
        (*_sessions)[_sessionKey] = std::make_shared<SessionData>(ntohl(tcpHdr->seqNum));

        if (tcpHdr->flags & kACK)
        {
            (*_sessions)[_sessionKey]->setIsServer(true);
        }

        return false;
    }

    if ((*_sessions).count(_sessionKey) == 0)
    {
        return false;
    }
    
    if(tcpHdr->flags & (kFIN + kRST))
    {
        (*_sessions).erase(_sessionKey);
        return false;
    }

    if ((*_sessions)[_sessionKey]->insertPacket(_header, _packet) == 0)
    {
        return false;
    }
    
    return true;
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

    std::string sip, dip;
    sip = formatIpV4Address(&ipHeader->srcIp);
    dip = formatIpV4Address(&ipHeader->dstIp);

    if(sip == "192.168.45.81" or dip == "192.168.45.81")
    {
        return UNDEFINED_TYPE;
    }
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

SessionKey PacketParser::peerSessionKey()
{
    const struct IpHdr *ipHdr = reinterpret_cast<const struct IpHdr*>(_packet + sizeof(struct EtherHdr));
    const struct TcpHdr *tcpHdr = reinterpret_cast<const struct TcpHdr*>(reinterpret_cast<const u_char*>(ipHdr) + (ipHdr->ipHl * 4));

    return SessionKey(ipHdr->dstIp.s_addr, tcpHdr->dstPort, ipHdr->srcIp.s_addr, tcpHdr->srcPort);
}

std::optional<SessionProtocol> PacketParser::classifyPayload()
{
    if (isHttpProtocol(BufferType::payloadBuffer))
    {
        (*_sessions)[_sessionKey]->setProtocol(SessionProtocol::HTTP);
        return SessionProtocol::HTTP;
    }

    if (_sslMode and isTLSProtocol(BufferType::payloadBuffer))
    {
        (*_sessions)[_sessionKey]->setProtocol(SessionProtocol::TLS);
        return SessionProtocol::TLS;
    }
    (*_sessions).erase(_sessionKey);
    return std::nullopt;
}

bool PacketParser::isHttpProtocol(BufferType bufferType)
{
    RingBuffer &ringBuffer = (*_sessions)[_sessionKey]->getBuffer(bufferType);
    std::string buffer = ringBuffer.getBufferAsString();

    std::istringstream stream(buffer);
    std::string line;
    if (not std::getline(stream, line))
    {
        return false;
    }

    std::regex http_pattern("^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|HTTP)");
    if (std::regex_search(line, http_pattern))
    {
        return true;
    }
    return false;
}

bool PacketParser::isTLSProtocol(BufferType bufferType)
{
    RingBuffer &ringBuffer = (*_sessions)[_sessionKey]->getBuffer(bufferType);
    if (ringBuffer.size() < sizeof(struct TLSRecordHdr))
    {
        return false;
    }

    std::vector<u_char> buffer = ringBuffer.getData();
    const struct TLSRecordHdr *tlsHdr = reinterpret_cast<const struct TLSRecordHdr*>(buffer.data());
    
    if (tlsHdr->contentType < SSL3_RT_CHANGE_CIPHER_SPEC or tlsHdr->contentType > TLS1_RT_HEARTBEAT)
    {
        return false;
    }

    if (ntohs(tlsHdr->version) < TLS1_VERSION or ntohs(tlsHdr->version) > TLS1_2_VERSION)
    {
        return false;
    }

    return true;
}

bool PacketParser::checkCipherSuite(uint16_t cipherSuite)
{
    switch(cipherSuite)
    {
        case TLS_RSA_WITH_AES_128_CBC_SHA:
        case TLS_RSA_WITH_AES_256_CBC_SHA:
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
        // case TLS_RSA_WITH_AES_128_GCM_SHA256:
        // case TLS_RSA_WITH_AES_256_GCM_SHA384:
            return true;
        default:
            return false;
    }
}

std::string PacketParser::toStringFromHttp(const struct HttpPacket& httpPacket)
{
    std::map<HeaderCategory, std::vector<std::pair<std::string, std::string>>> categorizeHeaders;
    std::string result = "";

    // 헤더 카테고리 분류
    for (const auto& header: httpPacket.headers)
    {
        HeaderCategory category = categoryHeader(header.first);
        categorizeHeaders[category].push_back(header);
    }

    std::vector<HeaderCategory> orderedCategories = {
        HeaderCategory::Request,
        HeaderCategory::Response,
        HeaderCategory::General,
        HeaderCategory::Unknown
    };

    result += "[Start Line]\n";
    result += httpPacket.headers["StartLine"] + "\n";
    
    for (const auto& category: orderedCategories)
    {
        auto it = categorizeHeaders.find(category);
        if (it != categorizeHeaders.end())
        {
            switch(category)
            {
                case HeaderCategory::Request:
                    result += "[Request Header]\n";
                    break;
                case HeaderCategory::Response:
                    result += "[Response Header]\n";
                    break;
                case HeaderCategory::General:
                    result += "[General Header]\n";
                    break;
            }

            for (const auto& headers: it->second)
            {
                result += "- " + headers.first + ": " + headers.second + "\n";
            }

            result += "\n";
        }
    }

    if (httpPacket.headers.count("Content-Length") != 0)
    {
        result += "[Body]\n";
        result += httpPacket.body + "\n";
    }

    result += "\n";

    return result;
}


HeaderCategory PacketParser::categoryHeader(const std::string& headerName)
{
    if (_headersByCategory["General"].find(headerName) != _headersByCategory["General"].end())
    {
        return HeaderCategory::General;
    }
    else if (_headersByCategory["Request"].find(headerName) != _headersByCategory["Request"].end())
    {
        return HeaderCategory::Request;
    }
    else if (_headersByCategory["Response"].find(headerName) != _headersByCategory["Response"].end())
    {
        return HeaderCategory::Response;
    }
    else
    {
        return HeaderCategory::Unknown;
    }
}