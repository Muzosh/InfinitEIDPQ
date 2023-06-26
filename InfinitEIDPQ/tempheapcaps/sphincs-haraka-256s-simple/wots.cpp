#include <stdint.h>
#include <string.h>
#include <cmath>
#include <esp_heap_caps.h>

#include "wots.h"
#include "wotsx1.h"

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"
#include "logging.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(uint8_t* out, const uint8_t* in, unsigned int start, unsigned int steps,
                      const spx_ctx* ctx, uint32_t addr[8])
{
    uint32_t i;
    debugMsg("gen_chain called");

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);
    debugMsg("out initialized");

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) {
        debugVar(i);
        set_hash_addr(addr, i);
        debugMsg("hash address set");
        thash(out, out, 1, ctx, addr);
        debugMsg("thash completed");
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int* output, const int out_len, const uint8_t* input)
{
    int in = 0;
    int out = 0;
    uint8_t total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int* csum_base_w, const unsigned int* msg_base_w)
{
    unsigned int csum = 0;
    uint8_t* csum_bytes = (uint8_t*)heap_caps_malloc(
        (sizeof(uint8_t) * ((int)std::floor((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8))),
        MALLOC_CAP_DEFAULT);
    debugMsg("wots_checksum called");
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    debugMsg("csum shifted");
    ull_to_bytes(csum_bytes,
                 sizeof(uint8_t) * (int)std::floor((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8), csum);
    debugMsg("ull_to_bytes completed");
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
    debugMsg("base_w completed");
    heap_caps_free(csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths(unsigned int* lengths, const uint8_t* msg)
{
    debugVar(esp_get_free_heap_size());
    debugVar(xPortGetFreeHeapSize());
    debugVar(esp_get_free_internal_heap_size());
    debugVar(esp_get_minimum_free_heap_size());
    debugMsg("chain_lengths called");
    base_w(lengths, SPX_WOTS_LEN1, msg);
    debugMsg("base_w completed");
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
    debugMsg("wots_checksum completed");
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* msg, const spx_ctx* ctx,
                      uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i * SPX_N, sig + i * SPX_N, lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx,
                  addr);
    }
}
