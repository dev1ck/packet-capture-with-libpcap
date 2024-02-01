#include <unistd.h>
#include <iostream>
#include <signal.h>

#include "ApplicationManager.h"

std::unique_ptr<ApplicationManager> gAppManager;

void signal_handler(int signum) {
    gAppManager->stop();
    exit(signum);
}

int main(int argc, char* argv[])
{
    gAppManager = std::make_unique<ApplicationManager>(argc, argv);
    gAppManager->setting();

    signal(SIGINT, signal_handler); 
    gAppManager->start();
    
    return 0;
}