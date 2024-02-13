#include "ApplicationManager.h"

ApplicationManager::ApplicationManager(int argc, char* argv[]): _argc(argc), _argv(argv)
{
    parseOptions();
}

void ApplicationManager::parseOptions()
{
    int opt;
    while ((opt = getopt(_argc, _argv, "hDI:w:tria")) != -1)
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
            case 'w':
                if (not optarg)
                {
                    usage();
                    exit(0);
                }
                mode = kWriteMode;
                _path = optarg;
                break;
            case 't':
                mode = kCaptureHTTP;
                break;
            case 'r':
                mode = kCaptureARP;
                break;
            case 'i':
                mode = kCaptureICMP;
                break;
            case 'a':
                mode = kCaptureALL;
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
    _capture_engine = std::make_unique<CaptureEngine>(_if_name);
    _capture_engine->setPromisc();
}

void ApplicationManager::start()
{
    _capture_engine->activate();
    if (mode == kWriteMode)
    {
        _capture_engine->dumpCaptureStart(_path);
    }
    else
    {
        _capture_engine->liveCaptureStart(mode);
    }
}

void ApplicationManager::stop()
{
    std::cout << "Stopping Dump..." << std::endl;
    _capture_engine.reset();
}

void ApplicationManager::usage()
{
    CaptureEngine::PrintPcapVersion();
    std::cout << "Usage: dump [-hDti] [-I interface] [-w file]\n";
}