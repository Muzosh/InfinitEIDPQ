#include <stdint.h>
#include <string.h>
#include <esp_heap_caps.h>

#include "thash.h"

#include "address.h"
#include "hash.h"
#include "params.h"
#include "sha2.h"
#include "utils.h"

static void thash_512(uint8_t* out, const uint8_t* in, unsigned int inblocks,
                      const spx_ctx* ctx, uint32_t addr[8]);

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(uint8_t* out, const uint8_t* in, unsigned int inblocks, const spx_ctx* ctx,
           uint32_t addr[8])
{
    if (inblocks > 1) {
        thash_512(out, in, inblocks, ctx, addr);
        return;
    }

    uint8_t* outbuf = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_SHA256_OUTPUT_BYTES)), MALLOC_CAP_DEFAULT);
    sha256ctx sha2_state;
    PQCLEAN_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    sha256_inc_ctx_clone(&sha2_state, &ctx->state_seeded);

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha256_inc_finalize(outbuf, &sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    memcpy(out, outbuf, SPX_N);
    heap_caps_free(outbuf);
}

static void thash_512(uint8_t* out, const uint8_t* in, unsigned int inblocks,
                      const spx_ctx* ctx, uint32_t addr[8])
{
    uint8_t* outbuf = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_SHA512_OUTPUT_BYTES)), MALLOC_CAP_DEFAULT);
    sha512ctx sha2_state;
    PQCLEAN_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    sha512_inc_ctx_clone(&sha2_state, &ctx->state_seeded_512);

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * SPX_N);

    sha512_inc_finalize(outbuf, &sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks * SPX_N);
    memcpy(out, outbuf, SPX_N);
    heap_caps_free(outbuf);
}
