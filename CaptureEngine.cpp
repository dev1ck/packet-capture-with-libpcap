#include "CaptureEngine.h"

CaptureEngine::CaptureEngine(const std::string& if_name): _if_name(if_name)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    if((_pcap_handle = pcap_create(_if_name.c_str(), err_buf)) == nullptr)
    {
        throw std::runtime_error(err_buf);
    }
}

CaptureEngine::~CaptureEngine()
{   
    if (_dumpert_t != nullptr)
    {
        pcap_dump_close(_dumpert_t);
    }
    pcap_close(_pcap_handle);
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

void live_capture_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    auto result = parse_packet(header, packet);

    if (result.has_value())
    {
        std::cout << result.value() << std::endl;
    }
}

void CaptureEngine::liveCaptureStart()
{
    pcap_loop(_pcap_handle, 0, live_capture_handler, nullptr);
}

void CaptureEngine::dumpCaptureStart(const std::string& path)
{
    _dumpert_t = pcap_dump_open(_pcap_handle, path.c_str());
    if (_dumpert_t == nullptr)
    {
        char err_message[100];
        sprintf(err_message, "\"%s\" 는 올바른 경로가 아닙니다.", path.c_str());
        throw std::runtime_error(err_message);
    }
    std::cout << "Dump Start" << std::endl;
    pcap_loop(_pcap_handle, 0, pcap_dump, reinterpret_cast<u_char *>(_dumpert_t));
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