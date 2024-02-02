#ifndef _CAPTURE_ENGINE_H
#define _CAPTURE_ENGINE_H

#include <string>
#include <iostream>
#include <pcap/pcap.h>

#include "PacketParser.h"


#define kCaptureALL 0
#define kCaptureTCP 1
#define kCaptureARP 2
#define kCaptureHTTP 3
#define kWriteMode 4

class CaptureEngine
{
private:
    std::string _if_name;
    pcap_t* _pcap_handle;
    pcap_dumper_t *_dumpert_t;
public:
    CaptureEngine(const std::string& if_name);
    ~CaptureEngine();
    void setPromisc();
    void activate();
    void liveCaptureStart(int mode);
    void dumpCaptureStart(const std::string& path);
    static void PrintPcapVersion();
    static void PrintNICInfo();
    
};

#endif