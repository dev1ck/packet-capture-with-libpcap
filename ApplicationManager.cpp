#include "ApplicationManager.h"

ApplicationManager::ApplicationManager(int argc, char* argv[]): _argc(argc), _argv(argv)
{
    parseOptions();
}

void ApplicationManager::parseOptions()
{
    int opt;
    while ((opt = getopt(_argc, _argv, "hDI:W:R:triak:")) != -1)
    {
        switch (opt)
        {
            case 'h':
                usage();
                exit(0);
            case 'D':
                if (_argc != 2)
                {
                    usage();
                }
                CaptureEngine::PrintNICInfo();
                exit(0);
            case 'I':
                if (not optarg)
                {
                    usage();
                    exit(0);
                }
                _if_name = optarg;
                break;
            case 'W':
                if (not optarg)
                {
                    usage();
                    exit(0);
                }
                _capture_mode = WRITE_MODE;
                _path = optarg;
                break;
            case 'R':
                if (not optarg)
                {
                    usage();
                    exit(0);
                }
                _capture_mode = READ_MODE;
                _path = optarg;
                break;
            case 't':
                _packet_mode = HTTP_TYPE;
                break;
            case 'r':
                _packet_mode = ARP_TYPE;
                break;
            case 'i':
                _packet_mode = ICMP_TYPE;
                break;
            case 'a':
                _packet_mode = ALL_TYPE;
                break;
            case 'k':
                if (not optarg)
                {
                    usage();
                    exit(0);
                }
                _sslMode = true;
                _keyLogFile = optarg;
                break;
            default:
                usage();
                exit(0);
                break;
        }
    }
}

void ApplicationManager::setting()
{   
    _capture_engine = CaptureEngine(_if_name);
    if (_capture_mode != READ_MODE)
    {
        _capture_engine.setPromisc();

        if (_packet_mode == HTTP_TYPE)
        {
            _capture_engine.setBufferSize(16 * 1024 * 1024);
        }
    }

    if (_sslMode)
    {
        _capture_engine.setSSLMode(_keyLogFile);
    }
}

void ApplicationManager::start()
{
    _capture_engine.activate();
    if (_capture_mode == WRITE_MODE)
    {
        _capture_engine.dumpCaptureStart(_path);
    }
    else if(_capture_mode == READ_MODE)
    {
        _capture_engine.offlineParseStart(_path, _packet_mode);
    }
    else
    {
        _capture_engine.liveCaptureStart(_packet_mode);
    }
}

void ApplicationManager::stop()
{
    std::cout << "Stopping Dump..." << std::endl;
    _capture_engine.stop();
}

void ApplicationManager::usage()
{
    CaptureEngine::PrintPcapVersion();
    std::cout << "Usage: dump [-hDtria] [-I interface] [-W file] [-R file]\n";
}