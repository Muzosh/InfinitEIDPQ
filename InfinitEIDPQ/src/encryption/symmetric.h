#ifndef SYMMETIC_H
#define SYMMETIC_H

#include <aes/esp_aes.h>

#include "sha256.h"
#include "common/common_variables.h"

#define SALT_KEY "salt"
#define SALT_LENGTH 128
#define IV_LENGTH 16

void aes256Encrypt(const uint8_t* in, const size_t inLen, uint8_t* out, const uint8_t iv[IV_LENGTH],
                   const uint8_t* key, const size_t keyLen);

void aes256Decrypt(const uint8_t* in, const size_t inLen, uint8_t* out, const uint8_t iv[IV_LENGTH],
                   const uint8_t* key, const size_t keyLen);

void derivateKey(uint8_t* out, const size_t outLen, const uint8_t* in, const size_t inLen);

#endif