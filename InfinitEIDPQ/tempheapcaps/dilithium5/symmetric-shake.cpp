#include <fips202.h>
#include "params.h"
#include "symmetric.h"
#include <stdint.h>
#include <memory>
#include <esp_heap_caps.h>

void PQCLEAN_DILITHIUM5_CLEAN_dilithium_shake128_stream_init(shake128incctx* state,
                                                             const uint8_t* seed, uint16_t nonce)
{
    uint8_t* t = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(2)), MALLOC_CAP_DEFAULT);
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);

    shake128_inc_init(state);
    shake128_inc_absorb(state, seed, SEEDBYTES);
    shake128_inc_absorb(state, t, 2);
    shake128_inc_finalize(state);
    heap_caps_free(t);
}

void PQCLEAN_DILITHIUM5_CLEAN_dilithium_shake256_stream_init(shake256incctx* state,
                                                             const uint8_t* seed, uint16_t nonce)
{
    uint8_t* t = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(2)), MALLOC_CAP_DEFAULT);
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);

    shake256_inc_init(state);
    shake256_inc_absorb(state, seed, CRHBYTES);
    shake256_inc_absorb(state, t, 2);
    shake256_inc_finalize(state);
    heap_caps_free(t);
}
