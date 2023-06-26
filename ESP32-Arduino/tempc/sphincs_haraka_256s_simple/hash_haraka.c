#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "utils.h"

#include "haraka.h"
#include "hash.h"

/*
 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
 */
void prf_addr(uint8_t *out, const spx_ctx *ctx,
              const uint32_t addr[8]) {
    /* Since SPX_N may be smaller than 32, we need temporary buffers. */
    uint8_t outbuf[32];
    uint8_t buf[64] = {0};

    memcpy(buf, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    haraka512(outbuf, (const void *)buf, ctx);
    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(uint8_t *R, const uint8_t *sk_prf,
                        const uint8_t *optrand,
                        const uint8_t *m, size_t mlen,
                        const spx_ctx *ctx) {
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, sk_prf, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, optrand, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, m, mlen, ctx);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(R, SPX_N, s_inc, ctx);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const uint8_t *R, const uint8_t *pk,
                  const uint8_t *m, size_t mlen,
                  const spx_ctx *ctx) {
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    uint8_t buf[SPX_DGST_BYTES];
    uint8_t *bufp = buf;
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, R, SPX_N, ctx);
    haraka_S_inc_absorb(s_inc, pk + SPX_N, SPX_N, ctx); // Only absorb root part of pk
    haraka_S_inc_absorb(s_inc, m, mlen, ctx);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(buf, SPX_DGST_BYTES, s_inc, ctx);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;


    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
