/* *************************************************
   *                                               *
   *                                               *
   *                                               *
   *     VTXTSecureTextCore.dll source code        *
   *                                               *
   *                                               *
   *                                               *
   *************************************************
*/

#include <windows.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#define HEADER "VTXT"
#define HEADER_LEN 4
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define ITERATIONS 500000

extern "C" __declspec(dllexport)
int EncryptText(const unsigned char* input, int inputLen, const char* password, unsigned char* output, int maxLen)
{
    if (!input || !password || !output || maxLen <= 0 || inputLen <= 0 || strlen(password) == 0)
        return -1;

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];

    if (RAND_bytes(salt, SALT_SIZE) != 1) return -2;
    if (RAND_bytes(iv, IV_SIZE) != 1) return -3;

    unsigned char key[KEY_SIZE];

    DWORD t1 = GetTickCount();
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_SIZE, key))
        return -4;
    DWORD t2 = GetTickCount();

    char buf[128];
    sprintf_s(buf, sizeof(buf), "PBKDF2 time: %lu ms\n", t2 - t1);
    OutputDebugStringA(buf);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -5;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    int padVal = blockSize - (inputLen % blockSize);
    int paddedLen = inputLen + padVal;

    std::vector<unsigned char> padded(paddedLen);
    memcpy(padded.data(), input, inputLen);
    memset(padded.data() + inputLen, padVal, padVal);

    std::vector<unsigned char> encrypted(paddedLen + blockSize);
    int outLen1 = 0, outLen2 = 0;

    if (!EVP_EncryptUpdate(ctx, encrypted.data(), &outLen1, padded.data(), paddedLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }

    if (!EVP_EncryptFinal_ex(ctx, encrypted.data() + outLen1, &outLen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return -8;
    }

    int totalLen = HEADER_LEN + SALT_SIZE + IV_SIZE + (outLen1 + outLen2);
    if (totalLen > maxLen) {
        EVP_CIPHER_CTX_free(ctx);
        return -9;
    }

    memcpy(output, HEADER, HEADER_LEN);
    memcpy(output + HEADER_LEN, salt, SALT_SIZE);
    memcpy(output + HEADER_LEN + SALT_SIZE, iv, IV_SIZE);
    memcpy(output + HEADER_LEN + SALT_SIZE + IV_SIZE, encrypted.data(), outLen1 + outLen2);

    EVP_CIPHER_CTX_free(ctx);
    return totalLen;
}

extern "C" __declspec(dllexport)
char* DecryptText(const unsigned char* data, int length, const char* password, int* isPasswordOk)
{
    *isPasswordOk = 0;

    if (!data || !password || strlen(password) == 0 || length < HEADER_LEN + SALT_SIZE + IV_SIZE)
        return nullptr;

    if (memcmp(data, HEADER, HEADER_LEN) != 0)
        return nullptr;

    const unsigned char* salt = data + HEADER_LEN;
    const unsigned char* iv = salt + SALT_SIZE;
    const unsigned char* ciphertext = iv + IV_SIZE;
    int cipherLen = length - HEADER_LEN - SALT_SIZE - IV_SIZE;

    unsigned char key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, ITERATIONS, EVP_sha256(), KEY_SIZE, key))
        return nullptr;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return nullptr;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    std::vector<unsigned char> plaintext(cipherLen + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0, len2 = 0;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len1, ciphertext, cipherLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(ctx);
    int plainLen = len1 + len2;

    if (plainLen == 0 || plainLen % EVP_CIPHER_block_size(EVP_aes_256_cbc()) != 0)
        return nullptr;

    int pad = plaintext[plainLen - 1];
    if (pad <= 0 || pad > EVP_CIPHER_block_size(EVP_aes_256_cbc()) || pad > plainLen)
        return nullptr;

    int resultLen = plainLen - pad;
    char* result = (char*)malloc(resultLen + 1);
    if (!result)
        return nullptr;

    memcpy(result, plaintext.data(), resultLen);
    result[resultLen] = '\0';

    *isPasswordOk = 1;
    return result;
}

extern "C" __declspec(dllexport)
void FreeMemory(char* ptr)
{
    if (ptr)
        free(ptr);
}
