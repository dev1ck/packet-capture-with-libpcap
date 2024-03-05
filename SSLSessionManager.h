#ifndef _SSL_SESSION_MANAGER_H
#define _SSL_SESSION_MANAGER_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <string>
#include <map>
#include <cstring>
#include <cstdio>
#include <vector>

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
    std::array<u_char, TLS12_RANDOM_VALUE_LENGTH> serverRandom;
    std::array<u_char, TLS12_RANDOM_VALUE_LENGTH> clientRandom;
    uint16_t cipherSuite;
    std::array<u_char, TLS12_MASTER_SECRET_LENGTH> preMasterSecret;
    std::array<u_char, TLS12_MASTER_SECRET_LENGTH> masterSecret;
    std::string sessionkey;
    std::string iv;
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
    bool makeTLSSession(const std::string &tlsSessionID, const SessionKey &peerSessionKey, const uint8_t* serverRandom, const uint16_t cipherSuite);
    void setPreMasterSecret(const std::string &tlsSessionID, const u_char *encryptedPreMaster, uint16_t preMasterLength);
   
private:
    SSLSessionManager();
    RSA* _privateKey;
    std::unordered_map<std::string, SSLSessionData> _sessions;
    std::map<SessionKey, std::array<uint8_t, 32>> _tmpClientRandom;
    std::optional<std::vector<u_char>> decryptPreMasterSecret(uint16_t ecryptDataLen, u_char* encryptData);
    std::vector<u_char> PRF(const std::vector<u_char> &secret, const std::string &label, const std::vector<u_char > &seed, size_t outputLen, HashAlgorithm hashAlgorithm);
    std::vector<u_char> HMAC_hash(const std::vector<u_char> &secret, const std::vector<u_char> &data, HashAlgorithm hashAlgorithm);
};

#endif