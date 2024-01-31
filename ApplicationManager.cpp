#include "ApplicationManager.h"
#include "CaptureEngine.h"

ApplicationManager::ApplicationManager(int argc, char* argv[]): _argc(argc), _argv(argv)
{

    if (argc < 2)
    {
        usage();
        exit(0);
    }
    parseOptions();
}

void ApplicationManager::parseOptions()
{
    int opt;
    while ((opt = getopt(_argc, _argv, "vid::")) != -1) //:: 두개 확실히 처리 필요
    {
        switch (opt)
        {
            case 'v':
            {
                if (_argc != 2)
                {
                    usage();
                }
                CaptureEngine::PrintPcapVersion();
                exit(0);
            }
            case 'i':
            {
                if (_argc != 2)
                {
                    usage();
                }
                CaptureEngine::GetInterfaceInfo();
                exit(0);
            }
            case 'd':
            {
                if (optarg)
                {
                    _path = optarg;
                }
                _dump_mode = true;
                break;
            }
            default:
            {
                usage();
                exit(0);
            }
        }
    }
    // segemntation falt 해결 필요
    _if_name = _argv[optind];
}

void ApplicationManager::start()
{
    CaptureEngine capture_engine(_if_name);
    capture_engine.setting();

    if (_dump_mode)
    {
        capture_engine.dumpCaptureStart(_path);
    }
    else
    {
        capture_engine.liveCaptureStart();
    }
}

void ApplicationManager::usage()
{
    std::cout << _argv[0] << " -i : 인터페이스 정보 출력\n";
    std::cout << _argv[0] << " -v : pcap 버전 정보 출력\n";
    std::cout << _argv[0] << " <ifname> [-d <path>] : dump 모드\n";
}