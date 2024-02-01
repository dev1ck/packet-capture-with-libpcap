#ifndef _APPLICATION_MANAGER_H
#define _APPLICATION_MANAGER_H

#include <iostream>
#include <cstdlib>
#include <unistd.h>

#include "CaptureEngine.h"

class ApplicationManager
{
private:
    int _argc;
    char **_argv;
    std::string _if_name = "eth0";
    std::string _path;
    bool _write_mode = false;
    std::unique_ptr<CaptureEngine> _capture_engine;
public:
    ApplicationManager(int argc, char *argv[]);
    void parseOptions();
    void setting();
    void start();
    void stop();
    void usage();
};

#endif
