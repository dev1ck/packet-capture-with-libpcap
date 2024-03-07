#include "SSLSessionManager.h"

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

void SSLSessionManager::saveClientRandom(const SessionKey &sessionKey, const u_char* clientRandom)
{
    std::vector<u_char> clientRandomVector(TLS12_RANDOM_VALUE_LENGTH); 
    std::copy(clientRandom, clientRandom + TLS12_RANDOM_VALUE_LENGTH, clientRandomVector.begin());

    _tmpClientRandom[sessionKey] = clientRandomVector;
}

void SSLSessionManager::deleteClientRandom(const SessionKey &sessionKey)
{
    _tmpClientRandom.erase(sessionKey);
}

void SSLSessionManager::deleteSession(const std::string &sessionID)
{
    _sessions.erase(sessionID);
}

bool SSLSessionManager::makeTLSSession(const std::string &tlsSessionID, const SessionKey &peerSessionKey, const uint8_t* serverRandom, const uint16_t cipherSuite)
{
    SSLSessionData sessionData;
    sessionData.serverRandom.resize(TLS12_RANDOM_VALUE_LENGTH);
    std::copy(serverRandom, serverRandom + TLS12_RANDOM_VALUE_LENGTH, sessionData.serverRandom.begin());

    if (_tmpClientRandom.count(peerSessionKey) == 0)
    {
        return false;
    }
    sessionData.clientRandom = _tmpClientRandom[peerSessionKey];
    sessionData.cipherSuite = cipherSuite;

    _sessions[tlsSessionID] = std::move(sessionData);
    _tmpClientRandom.erase(peerSessionKey);

    return true;
}

bool SSLSessionManager::generateMasterSecret(const std::string &tlsSessionID, const u_char *encryptedPreMaster, uint16_t preMasterLength)
{
    SSLSessionData &sessionData = _sessions[tlsSessionID];
    HashAlgorithm hashAlgorithm = checkAlgorithm(sessionData.cipherSuite);

    auto decryptPreMaster = decryptPreMasterSecret(encryptedPreMaster, preMasterLength);

    if (not decryptPreMaster.has_value())
    {
        return false;
    }

    std::vector<u_char> seed = sessionData.clientRandom;
    seed.reserve(TLS12_RANDOM_VALUE_LENGTH * 2);
    seed.insert(seed.end(), sessionData.serverRandom.begin(), sessionData.serverRandom.end());
    sessionData.masterSecret = PRF(decryptPreMaster.value(), "master secret", seed, TLS12_MASTER_SECRET_LENGTH, hashAlgorithm);
    
    return true;
}

void SSLSessionManager::generateSessionKey(const std::string &tlsSessionID)
{
    SSLSessionData &sessionData = _sessions[tlsSessionID];
    std::vector<u_char> keyBlock = generateKeyBlock(sessionData);

    size_t macKeySize, keySize, ivSize;

    switch (sessionData.cipherSuite)
    {
        case TLS_RSA_WITH_AES_128_CBC_SHA:
            keySize = 16;
            ivSize = 16;
            macKeySize = 20;
            break;
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            keySize = 16;
            ivSize = 16;
            macKeySize = 32;
            break;
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            keySize = 16;
            ivSize = 12;
            macKeySize = 0;
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA:
            keySize = 32;
            ivSize = 16;
            macKeySize = 20;
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            keySize = 32;
            ivSize = 16;
            macKeySize = 32;
            break;
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            keySize = 32;
            ivSize = 12;
            macKeySize = 0;
            break;
    }

    sessionData.clientWriteKey.assign(keyBlock.begin() + macKeySize * 2, keyBlock.begin() + macKeySize * 2 + keySize);
    sessionData.serverWriteKey.assign(keyBlock.begin() + macKeySize * 2 + keySize, keyBlock.begin() + macKeySize * 2 + keySize * 2);
    sessionData.clientWriteIV.assign(keyBlock.begin() + macKeySize * 2 + keySize * 2, keyBlock.begin() + macKeySize * 2 + keySize * 2 + ivSize);
    sessionData.serverWriteIV.assign(keyBlock.begin() + macKeySize * 2 + keySize * 2 + ivSize, keyBlock.begin() + macKeySize * 2 + keySize * 2 + ivSize * 2);
}

std::vector<u_char> SSLSessionManager::generateKeyBlock(SSLSessionData &sessionData)
{
    HashAlgorithm hashAlgorithm = checkAlgorithm(sessionData.cipherSuite);
    size_t blockSize = getKeyBlockSize(sessionData.cipherSuite);

    std::vector<u_char> seed = sessionData.serverRandom;
    seed.insert(seed.end(), sessionData.clientRandom.begin(), sessionData.clientRandom.end());


    return PRF(sessionData.masterSecret, "key expansion", seed, blockSize, hashAlgorithm);
}

std::optional<std::vector<u_char>> SSLSessionManager::decryptPreMasterSecret(const u_char* encryptedData, uint16_t encryptedDataLen)
{
    std::vector<u_char> decryptedData(RSA_size(_privateKey));
    int decryptedDataLen = RSA_private_decrypt(encryptedDataLen, encryptedData, decryptedData.data(), _privateKey, RSA_PKCS1_PADDING);

    if (decryptedDataLen == -1) {
        return std::nullopt;
    }
    decryptedData.resize(decryptedDataLen);

    return decryptedData;
}

std::vector<u_char> SSLSessionManager::PRF(const std::vector<u_char> &secret, const std::string &label, const std::vector<u_char> &seed, size_t outputLen, HashAlgorithm hashAlgorithm)
{
    std::vector<u_char> newSeed;
    int seed_size = label.size() + seed.size();
    newSeed.reserve(seed_size);

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

std::optional<std::vector<u_char>> SSLSessionManager::decryptData(const u_char* encryptData, size_t encryptDataLength, const std::string &sessionID, bool isServer)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (not ctx)
    {
        std::cerr << "create context fail" << std::endl;
        return std::nullopt;
    }

    SSLSessionData &sessionData = _sessions[sessionID];
    std::vector<u_char> decryptedData;
    int len;
    int plaintextLen = 0;
    std::vector<u_char> *key, *iv;
    const EVP_CIPHER *evpCipher = nullptr;
    size_t macLength;

    if (isServer)
    {
        key = &sessionData.serverWriteKey;
        iv = &sessionData.serverWriteIV;
    }
    else
    {
        key = &sessionData.clientWriteKey;
        iv = &sessionData.clientWriteIV;
    }

    switch(sessionData.cipherSuite)
    {
        case TLS_RSA_WITH_AES_128_CBC_SHA:
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            evpCipher = EVP_aes_128_cbc();
            macLength = sessionData.cipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA ? 20 : 32;
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA:
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            evpCipher = EVP_aes_256_cbc();
            macLength = sessionData.cipherSuite == TLS_RSA_WITH_AES_256_CBC_SHA ? 20 : 32;
            break;
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            evpCipher = EVP_aes_128_gcm();
            macLength = 0;
            break;
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            evpCipher = EVP_aes_256_gcm();
            macLength = 0;
            break;
    }

    if (EVP_DecryptInit_ex(ctx, evpCipher, nullptr, key->data(), iv->data()) != 1)
    {
        std::cerr << "Decrypt init fail" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }

    if (evpCipher == EVP_aes_128_gcm() or evpCipher == EVP_aes_256_gcm())
    {
        const size_t tagLength = 16;
        if(encryptDataLength < tagLength) {
            std::cerr << "Decrypted data length too short for GCM tag" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
        
        encryptDataLength -= tagLength; // Adjust encrypted data length to exclude the tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, (void*)(encryptData + encryptDataLength)) != 1)
        {
            std::cerr << "Set GCM tag fail" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
    }

    decryptedData.resize(encryptDataLength);

    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &len, encryptData, encryptDataLength) != 1)
    {
        std::cerr << "Decrypt update fail" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    plaintextLen += len;

    if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + plaintextLen, &len) != 1)
    {
        std::cerr << "Decrypt final fail" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    plaintextLen += len;

    plaintextLen -= (macLength + 1);

    decryptedData.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return std::vector<u_char>(decryptedData.begin() + iv->size(), decryptedData.end());
}

HashAlgorithm SSLSessionManager::checkAlgorithm(uint16_t cipherSuite)
{
    HashAlgorithm type;
    switch(cipherSuite)
    {
        case TLS_RSA_WITH_AES_128_CBC_SHA:
        case TLS_RSA_WITH_AES_256_CBC_SHA:
            type = HashAlgorithm::TYPE_SHA;
            break;
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            type = HashAlgorithm::TYPE_SHA256;
            break;
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            type = HashAlgorithm::TYPE_SHA384;
            break;
    }
    return type;
}

size_t SSLSessionManager::getKeyBlockSize(uint16_t cipherSuite)
{
    int size;
    switch(cipherSuite)
    {
        case TLS_RSA_WITH_AES_128_CBC_SHA:
            size = 104;
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA:
            size = 136;
            break;
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            size = 128;
            break;
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            size = 160;
            break;
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            size = 56;
            break;
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            size = 88;
            break;
    }
    return size;
}

void SSLSessionManager::cleanup()
{
    RSA_free(_privateKey);
}
