#ifndef _APPLICATION_MANAGER_H
#define _APPLICATION_MANAGER_H

#include <iostream>
#include <cstdlib>
#include <unistd.h>

class ApplicationManager
{
private:
    int _argc;
    char **_argv;
    std::string _if_name;
    std::string _path = "~/dump";
    bool _dump_mode = false;
public:
    ApplicationManager(int argc, char *argv[]);
    void parseOptions();
    void start();
    void usage();
};

#endif
