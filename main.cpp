#include <unistd.h>
#include <iostream>
#include "ApplicationManager.h"

int main(int argc, char* argv[])
{
    ApplicationManager app_manager(argc, argv);
    app_manager.start();
    
    return 0;
}