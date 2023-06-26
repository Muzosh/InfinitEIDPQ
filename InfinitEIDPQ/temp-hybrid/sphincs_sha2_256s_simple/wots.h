#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>

#include "context.h"
#include "params.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
#define wots_pk_from_sig SPX_NAMESPACE(wots_pk_from_sig)
void wots_pk_from_sig(uint8_t *pk,
                      const uint8_t *sig, const uint8_t *msg,
                      const spx_ctx *ctx, uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
#define chain_lengths SPX_NAMESPACE(chain_lengths)
void chain_lengths(unsigned int *lengths, const uint8_t *msg);

#endif
