#ifndef _CAPTURE_ENGINE_H
#define _CAPTURE_ENGINE_H

#include <string>
#include <iostream>
#include <pcap/pcap.h>

#include "PacketParser.h"

class CaptureEngine
{
private:
    std::string _if_name;
    pcap_t* _pcap_handle;
public:
    CaptureEngine(const std::string& if_name);
    ~CaptureEngine();
    void setting();
    void activate();
    void liveCaptureStart();
    void dumpCaptureStart(const std::string& path);
    static void PrintPcapVersion();
    static void GetInterfaceInfo();
    
};

#endif