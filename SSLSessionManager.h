#ifndef _SSL_SESSION_MANAGER_H
#define _SSL_SESSION_MANAGER_H
#include <unordered_map>

struct SSLSessionData
{

}

class SSLSessionManager
{
public:
    static SSLSessionManager& Instance()
    {
        static SSLSessionManager instance;
        return instance;
    }

private:
    SSLSessionManager();
    std::unordered_map<std::string, SSLSessionData> _sessions

}

#endif