#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"
#include "params.h"

#define prf_addr SPX_NAMESPACE(prf_addr)
void prf_addr(uint8_t *out, const spx_ctx *ctx,
              const uint32_t addr[8]);

#define gen_message_random SPX_NAMESPACE(gen_message_random)
void gen_message_random(uint8_t *R, const uint8_t *sk_prf,
                        const uint8_t *optrand,
                        const uint8_t *m, size_t mlen,
                        const spx_ctx *ctx);

#define hash_message SPX_NAMESPACE(hash_message)
void hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const uint8_t *R, const uint8_t *pk,
                  const uint8_t *m, size_t mlen,
                  const spx_ctx *ctx);


#   define SPX_SHA256_ADDR_BYTES 22

#   define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(uint8_t *out, unsigned long outlen,
              const uint8_t *in, unsigned long inlen);

#   define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(uint8_t *out, unsigned long outlen,
              const uint8_t *in, unsigned long inlen);

#endif
