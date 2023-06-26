#ifndef STORAGE_HANDLER_NVS_H
#define STORAGE_HANDLER_NVS_H

#include "utils/logging.h"
#include "common/common_variables.h"

#define BASE_PATH(algorithmID, mode)                                                               \
    (String(algorithmID) + "_" + String(mode)) // Expands to algorithmID_mode
#define PK_PATH(algorithmID, mode) (BASE_PATH(algorithmID, mode) + "_pk")
#define SK_PATH(algorithmID, mode) (BASE_PATH(algorithmID, mode) + "_sk")
#define CERT_PATH(algorithmID, mode) (BASE_PATH(algorithmID, mode) + "_cert")

// Objects
namespace nvs_storage
{

void encryptAndStoreBlob(const uint8_t* object, const size_t objectLen, const String key,
                         const uint8_t* pin, const size_t pinLen);

void storeBlob(const uint8_t* object, const size_t objectLen, const String key);

void storeByte(const uint8_t object, const String key);

void decryptAndObtainBlob(uint8_t* object, const size_t objectLen, const String key,
                          const uint8_t* pin, const size_t pinLen);

void obtainBlob(uint8_t* object, const size_t objectLen, const String key);

void obtainBlobAndLength(uint8_t* object, size_t& objectLen, const String key);

void obtainByte(uint8_t& object, const String key);

bool hasCertificateStored(uint8_t algorithmID, uint8_t mode);

void printStorageInfo();

void listKeysAndValues();
} // namespace nvs_storage
#endif