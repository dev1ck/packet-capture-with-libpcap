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


#define kCaptureALL 0
#define kCaptureHTTP 4
#define kWriteMode 5

struct CaptureData {
    int mode;
    std::map<SessionKey, std::shared_ptr<SessionData>>* sessions;
};

class CaptureEngine
{
private:
    std::string _if_name;
    pcap_t* _pcap_handle = nullptr;
    pcap_dumper_t *_dumper_t = nullptr;
    std::map<SessionKey, std::shared_ptr<SessionData>> _sessions;
    // void checkSessionThread();
    // struct timeval getCurrentTimeval();
public:
    CaptureEngine(){};
    CaptureEngine(const std::string& if_name);
    void setPromisc();
    void activate();
    void liveCaptureStart(int mode);
    void dumpCaptureStart(const std::string& path);
    void stop();
    static void PrintPcapVersion();
    static void PrintNICInfo();
};

#endif