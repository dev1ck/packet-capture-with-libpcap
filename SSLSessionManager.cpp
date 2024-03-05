#include "SSLSessionManager.h"

SSLSessionManager::SSLSessionManager()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

bool SSLSessionManager::loadPrivateKey(const std::string& path)
{
    FILE* file = fopen(path.c_str(), "rb");
    if (not file)
    {
        std::cerr << "Unable to open private key file." << std::endl;
        return false;
    }

    RSA* pkey = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);

    fclose(file);

    if (!pkey) {
        std::cerr << "Failed to read RSA private key" << std::endl;
        return false;
    }

    _privateKey = pkey;
    return true;
}

void SSLSessionManager::saveClientRandom(const SessionKey &sessionKey, const uint8_t* clientRandom)
{
    std::array<uint8_t, 32> clientRandomArray; 
    std::copy(clientRandom, clientRandom + 32, clientRandomArray.begin());

    _tmpClientRandom[sessionKey] = clientRandomArray;
}

void SSLSessionManager::deleteClientRandom(const SessionKey &sessionKey)
{
    _tmpClientRandom.erase(sessionKey);
}

bool SSLSessionManager::makeTLSSession(const std::string &tlsSessionID, const SessionKey &peerSessionKey, const uint8_t* serverRandom, const uint16_t cipherSuite)
{
    SSLSessionData sessionData;
    std::copy(serverRandom, serverRandom + 32, sessionData.serverRandom.begin());

    if (_tmpClientRandom.count(peerSessionKey) < 0)
    {
        return false;
    }
    sessionData.clientRandom = _tmpClientRandom[peerSessionKey];
    sessionData.cipherSuite = cipherSuite;

    _sessions[tlsSessionID] = std::move(sessionData);
    _tmpClientRandom.erase(peerSessionKey);

    return true;
}

void SSLSessionManager::setPreMasterSecret(const std::string &tlsSessionID, const u_char *encryptedPreMaster, uint16_t preMasterLength)
{
    // premaster 복호화 및 계산

}

std::optional<std::vector<u_char>> SSLSessionManager::decryptPreMasterSecret(uint16_t encryptedDataLen, u_char* encryptedData)
{
    std::vector<u_char> decryptedData(RSA_size(_privateKey));

    int decryptedDataLen = RSA_private_decrypt(encryptedDataLen, encryptedData, decryptedData.data(), _privateKey, RSA_PKCS1_PADDING);

    if (decryptedDataLen == -1) {
        ERR_print_errors_fp(stderr);
        return std::nullopt;
    }
    decryptedData.resize(decryptedDataLen);

    return decryptedData;
}

std::vector<u_char> SSLSessionManager::PRF(const std::vector<u_char> &secret, const std::string &label, const std::vector<u_char> &seed, size_t outputLen, HashAlgorithm hashAlgorithm)
{
    int seed_size = TLS12_MASTER_SECRET_LENGTH + label.size();
    std::vector<u_char> newSeed(seed_size);

    for (char c : label)
    {
        newSeed.push_back(static_cast<u_char>(c));
    }
    newSeed.insert(newSeed.end(), seed.begin(), seed.end());

    std::vector<u_char> result;
    result.reserve(outputLen);

    std::vector<std::vector<u_char>> A;
    A.push_back(newSeed);

    for (int i = 1; result.size() < outputLen; i++)
    {
        A.push_back(HMAC_hash(secret, A[i-1], hashAlgorithm));

        std::vector<u_char> tmpSeed = A[i];
        tmpSeed.insert(tmpSeed.end(), newSeed.begin(), newSeed.end());

        std::vector<u_char> tmpHash = HMAC_hash(secret, tmpSeed, hashAlgorithm);
        result.insert(result.end(), tmpHash.begin(), tmpHash.end());
    }
    result.resize(outputLen);
    
    return result;
}

std::vector<u_char> SSLSessionManager::HMAC_hash(const std::vector<u_char> &secret, const std::vector<u_char> &data, HashAlgorithm hashAlgorithm)
{
    const EVP_MD* evp_md = nullptr;
    switch (hashAlgorithm)
    {
        case HashAlgorithm::TYPE_SHA:
            evp_md = EVP_sha1();
            break;
        case HashAlgorithm::TYPE_SHA256:
            evp_md = EVP_sha256();
            break;
        case HashAlgorithm::TYPE_SHA384:
            evp_md = EVP_sha384();
            break;
    }

    unsigned int len = EVP_MD_size(evp_md);
    std::vector<u_char> hmac_result(len);

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, secret.data(), secret.size(), evp_md, nullptr);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, hmac_result.data(), &len);
    HMAC_CTX_free(ctx);

    hmac_result.resize(len);

    return hmac_result;
}