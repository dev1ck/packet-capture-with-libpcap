#include "CaptureEngine.h"

CaptureEngine::CaptureEngine(const std::string& if_name): _if_name(if_name)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    if((_pcap_handle = pcap_create(_if_name.c_str(), err_buf)) == nullptr)
    {
        throw std::runtime_error(err_buf);
    }
}

void CaptureEngine::setPromisc()
{
    if (pcap_set_promisc(_pcap_handle, 1) != 0)
    {
        throw std::runtime_error("promisc 변환 오류");
    }
}

void CaptureEngine::activate()
{
    int result = pcap_activate(_pcap_handle);
    if(result < 0)
    {
        std::string err_type;
        switch (result)
        {
        case(PCAP_ERROR_ACTIVATED):
            throw std::runtime_error("핸들이 이미 활성화되었습니다.");
        case(PCAP_ERROR_NO_SUCH_DEVICE):
            throw std::runtime_error("핸들을 만들 때 지정한 캡처 소스가 존재하지 않습니다.");
        case(PCAP_ERROR_PERM_DENIED):
            throw std::runtime_error("프로세스에 캡처 소스를 열 수 있는 권한이 없습니다.");
        case(PCAP_ERROR_PROMISC_PERM_DENIED):
            throw std::runtime_error("프로세스에 캡처 소스를 열 수 있는 권한이 있지만 이를 무차별 모드로 전환할 수 있는 권한이 없습니다.");
        case(PCAP_ERROR_RFMON_NOTSUP):
            throw std::runtime_error("모니터 모드가 지정되었지만 캡처 소스가 모니터 모드를 지원하지 않습니다.");
        case(PCAP_ERROR_IFACE_NOT_UP):
            throw std::runtime_error("캡처 소스 장치가 작동되지 않습니다.");
        case(PCAP_ERROR):
            throw std::runtime_error(pcap_geterr(_pcap_handle));
        }
    }
}


void capture_handle(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    CaptureData* data = reinterpret_cast<CaptureData*>(user);
    PacketParser packet_parser(header, packet, data->sessions);

    std::optional<std::string> result;

    int packet_type = packet_parser.classify_protocol();

    if (data->mode == ALL_TYPE or data->mode == packet_type)
    {
        switch (packet_type)
        {
            case TCP_TYPE:
                result = packet_parser.parse_tcp_hdr();
                break;
            case ARP_TYPE:
                result = packet_parser.parse_arp_packet();
                break;
            case ICMP_TYPE:
                result = packet_parser.parse_icmp_packet();
                break;
        }
    }

    if (data->mode == HTTP_TYPE and packet_type == TCP_TYPE)
    {
        result = packet_parser.parse_http_packet();
    }

    if (result.has_value())
    {
        std::cout << result.value() << std::endl;
    }
}

void CaptureEngine::liveCaptureStart(int mode)
{
    CaptureData data;
    data.mode = mode;
    data.sessions = &_sessions;

    // std::thread sessions_cheack_thread(&CaptureEngine::checkSessionThread, this);
    // sessions_cheack_thread.detach();

    pcap_loop(_pcap_handle, 0, capture_handle, reinterpret_cast<u_char *>(&data));
}

void CaptureEngine::dumpCaptureStart(const std::string& path)
{
    _dumper_t = pcap_dump_open(_pcap_handle, path.c_str());
    if (_dumper_t == nullptr)
    {
        char err_message[100];
        sprintf(err_message, "\"%s\" 는 올바른 경로가 아닙니다.", path.c_str());
        throw std::runtime_error(err_message);
    }
    std::cout << "Dump Start" << std::endl;
    pcap_loop(_pcap_handle, 0, pcap_dump, reinterpret_cast<u_char *>(_dumper_t));
}

void CaptureEngine::offlineParseStart(const std::string& path, int mode)
{
    CaptureData data;
    data.mode = mode;
    data.sessions = &_sessions;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    _pcap_handle = pcap_open_offline(path.c_str(), errbuf);

    if (_pcap_handle == nullptr)
    {
        throw std::runtime_error(errbuf);
    }

    pcap_loop(_pcap_handle, 0, capture_handle, reinterpret_cast<u_char *>(&data));
}

void CaptureEngine::PrintPcapVersion()
{
    std::cout << pcap_lib_version() << '\n';
}

void CaptureEngine::PrintNICInfo()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        throw std::runtime_error(errbuf);
    }

    for(device = alldevs; device != NULL; device = device->next)
    {
        std::cout << "* " << device->name << '\n';
    }
    pcap_freealldevs(alldevs);
}

void CaptureEngine::stop()
{   
    if (_dumper_t != nullptr)
    {
        pcap_dump_close(_dumper_t);
    }
    pcap_close(_pcap_handle);
}



// void CaptureEngine::checkSessionThread()
// {
//     for(;;)
//     {
//         if (_sessions.size() != 0)
//         {
//             struct timeval now = getCurrentTimeval();
//             std::vector<SessionKey> keys_to_remove;
//             for (const auto& session : _sessions)
//             {
//                 long long elapsed_time = now.tv_sec - session.second->getLastPacketTime().tv_sec;

//                 if (elapsed_time >= 240)
//                 {
//                     keys_to_remove.push_back(session.first);
//                 }
//             }

//             for (const auto& key : keys_to_remove)
//             {
//                 _sessions.erase(key);
//             }
            
//         }
//         std::this_thread::sleep_for(std::chrono::seconds(60));
//     }
// }

// struct::timeval CaptureEngine::getCurrentTimeval()
// {
//     struct timeval tv;
//     std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
//         std::chrono::system_clock::now().time_since_epoch()
//     );
//     tv.tv_sec = ms.count() / 1000;
//     tv.tv_usec = (ms.count() % 1000) * 1000;
//     return tv;
// }