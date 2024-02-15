#ifndef _APPLICATION_MANAGER_H
#define _APPLICATION_MANAGER_H

#include <iostream>
#include <cstdlib>
#include <unistd.h>

#include "CaptureEngine.h"

enum capture_mode
{
    LIVE_MODE,
    READ_MODE,
    WRITE_MODE
};

class ApplicationManager
{
private:
    int _argc;
    char **_argv;
    std::string _if_name = "eth0";
    std::string _path;
    int _capture_mode = LIVE_MODE;
    int _packet_mode = TCP_TYPE;
    CaptureEngine _capture_engine;
public:
    ApplicationManager(){};
    ApplicationManager(int argc, char *argv[]);
    void parseOptions();
    void setting();
    void start();
    void stop();
    void usage();
};

#endif
