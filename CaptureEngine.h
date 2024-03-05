#ifndef _CAPTURE_ENGINE_H
#define _CAPTURE_ENGINE_H

#include <string>
#include <iostream>
#include <map>
#include <memory>
#include <thread>
#include <chrono>

#include <pcap/pcap.h>
#include <sys/time.h>

#include "PacketParser.h"
#include "SessionData.h"

struct CaptureData {
    int mode;
    bool sslMode;
    std::map<SessionKey, std::shared_ptr<SessionData>>* sessions;
};

class CaptureEngine
{
private:
    std::string _if_name;
    pcap_t* _pcapHandle = nullptr;
    pcap_dumper_t *_dumper_t = nullptr;
    std::map<SessionKey, std::shared_ptr<SessionData>> _sessions;
    std::string _keyLogFile = "";
    bool _sslMode = false;
    // void checkSessionThread();
    // struct timeval getCurrentTimeval();
public:
    CaptureEngine(){};
    CaptureEngine(const std::string& if_name);
    void setPromisc();
    void setBufferSize(int size);
    void activate();
    void liveCaptureStart(int mode);
    void dumpCaptureStart(const std::string& path);
    void offlineParseStart(const std::string& path, int mode);
    void stop();
    void setSSLMode()
    {
        _sslMode = true;
    }
    static void PrintPcapVersion();
    static void PrintNICInfo();
};

#endif