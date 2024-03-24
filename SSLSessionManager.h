#ifndef _SSL_SESSION_MANAGER_H
#define _SSL_SESSION_MANAGER_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include <cstdio>
#include <vector>
#include <optional>

#include <iostream>
#include <sstream>
#include <iomanip>

#include "Protocol.h"

using SessionKey = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>;

enum HashAlgorithm
{
    TYPE_SHA,
    TYPE_SHA256,
    TYPE_SHA384
};

struct SSLSessionData
{
    uint16_t cipherSuite;
    std::vector<u_char> serverRandom;
    std::vector<u_char> clientRandom;
    std::vector<u_char> masterSecret;
    std::vector<u_char> serverWriteKey;
    std::vector<u_char> serverWriteIV;
    std::vector<u_char> clientWriteKey;
    std::vector<u_char> clientWriteIV;
};

class SSLSessionManager
{
public:
    static SSLSessionManager& Instance()
    {
        static SSLSessionManager instance;
        return instance;
    }
    bool loadPrivateKey(const std::string& path);
    void saveClientRandom(const SessionKey &sessionKey, const uint8_t* clientRandom);
    void deleteClientRandom(const SessionKey &sessionKey);
    void deleteSession(const std::string &sessionID);
    bool makeTLSSession(const std::string &tlsSessionID, const SessionKey &peerSessionKey, const uint8_t* serverRandom, const uint16_t cipherSuite);
    bool generateMasterSecret(const std::string &tlsSessionID, const u_char *encryptedPreMaster, uint16_t preMasterLength);
    void generateSessionKey(const std::string &tlsSessionID);
    std::optional<std::vector<u_char>> decryptData(const u_char* encryptData, size_t length, const std::string &sessionID, bool isServer);

    void cleanup();
   
private:
    SSLSessionManager() {}
    RSA* _privateKey;
    std::unordered_map<std::string, SSLSessionData> _sessions;
    std::map<SessionKey, std::vector<u_char>> _tmpClientRandom;
    std::optional<std::vector<u_char>> decryptPreMasterSecret(const u_char* encryptData, uint16_t ecryptDataLen);
    std::vector<u_char> PRF(const std::vector<u_char> &secret, const std::string &label, const std::vector<u_char > &seed, size_t outputLen, HashAlgorithm hashAlgorithm);
    std::vector<u_char> HMAC_hash(const std::vector<u_char> &secret, const std::vector<u_char> &data, HashAlgorithm hashAlgorithm);
    std::vector<u_char> generateKeyBlock(SSLSessionData &sessionData);
    HashAlgorithm checkAlgorithm(uint16_t cipherSuite);
    size_t getKeyBlockSize(uint16_t cipherSuite);
};

#endif