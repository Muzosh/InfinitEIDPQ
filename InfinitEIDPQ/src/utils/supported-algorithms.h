#ifndef SUPPORTED_ALGORITHMS_H
#define SUPPORTED_ALGORITHMS_H

#include <stdint.h>
#include <map>
#include <functional>

struct SignatureAlgorithm
{
    uint8_t ID;
    std::function<void(uint8_t* pk, uint8_t* sk)> generateKeypair;
    std::function<void(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen,
                       const uint8_t* sk)>
        signature;
    std::function<void(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen,
                       const uint8_t* pk)>
        verify;
    size_t pklen;
    size_t sklen;
    size_t siglen;
};

// How to add a new algorithm:
// 1. add the include for the algorithm
// 2. create a new struct in this file
// 3. add the struct to the SUPPORTED_XXX_ALGORITHMS array

// Dilithium5
// extern "C" {
#include <api_dilithium5.h>
// }
const SignatureAlgorithm DILITHIUM5 = {0xD5,
                                       PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair,
                                       PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature,
                                       PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify,
                                       PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                       PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES,
                                       PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES};

// Falcon 1024
#include <api_falcon1024.h>
const SignatureAlgorithm FALCON1024 = {0xF1,
                                       PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair,
                                       PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature,
                                       PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify,
                                       PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                       PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                                       PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES};

// // SPHINCS+ SHA2 256s simple
// // extern "C" {
// #include <api_sphincs_sha2_256s_simple.h>
// // }
// const SignatureAlgorithm SPHINCS_SHA256_256S_S = {
//     0x55,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
//     PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES};

// // SPHINCS+ HARAKA 256s simple
// // extern "C" {
// #include <api_sphincs_haraka_256s_simple.h>
// // }
// const SignatureAlgorithm SPHINCS_HARAKA_256S_S = {
//     0x65,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_keypair,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_signature,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_crypto_sign_verify,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
//     PQCLEAN_SPHINCSHARAKA256SSIMPLE_CLEAN_CRYPTO_BYTES};

// Supported algorithms
const std::map<uint8_t, SignatureAlgorithm> SUPPORTED_SIGNATURE_ALGORITHMS = {
    {DILITHIUM5.ID, DILITHIUM5}, {FALCON1024.ID, FALCON1024}};
// {SPHINCS_SHA256_256S_S.ID, SPHINCS_SHA256_256S_S},
// {SPHINCS_HARAKA_256S_S.ID, SPHINCS_HARAKA_256S_S}};

// const std::map<uint8_t, KeyEncapsulationAlgorithm> SUPPORTED_KEY_ENCAPSULATION_ALGORITHMS = {};

#endif