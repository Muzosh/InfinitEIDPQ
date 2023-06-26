#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include <memory>
#include <cstring>

#include "utils/supported-status-words.h"
#include "utils/supported-algorithms.h"
#include "utils/supported-instructions.h"
#include "pin/owner-pin.h"

#define LE_MUST_BE_0                                                                               \
    if (Le != 0) {                                                                                 \
        debugBoth("[E] Le != 0", Le);                                                              \
        return SW_WRONG_LENGTH_EXPECTED;                                                           \
    }

unsigned short getStatus(uint8_t* responseBuffer, const uint16_t Le);

unsigned short verifyPin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                         const uint16_t Le);

unsigned short pinRetriesLeft(uint8_t* responseBuffer, const uint8_t mode, const uint16_t Le);

unsigned short changePin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                         const uint16_t Le);

unsigned short setPin(const uint8_t* dataBuffer, const size_t dataLength, const uint8_t mode,
                      const uint16_t Le);

unsigned short generateKeypair(const SignatureAlgorithm algorithm, const uint8_t mode,
                               const uint16_t Le);

unsigned short getPublicKey(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                            const uint8_t mode, const uint16_t Le);

unsigned short getPrivateKey(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                             const uint8_t mode, const uint16_t Le);

unsigned short getCertificate(uint8_t* responseBuffer, const SignatureAlgorithm algorithm,
                              const uint8_t mode, const uint16_t Le);

unsigned short setCertificate(const uint8_t* dataBuffer, const size_t dataLength,
                              const SignatureAlgorithm algorithm, const uint8_t mode,
                              const uint16_t Le);

unsigned short createSignature(uint8_t* responseBuffer, const uint8_t* dataBuffer,
                               const size_t dataLength, const SignatureAlgorithm algorithm,
                               const uint8_t mode, const uint16_t Le);

#endif