#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <esp_heap_caps.h>

#include "fors.h"

#include "address.h"
#include "hash.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"

static void fors_gen_sk(uint8_t* sk, const spx_ctx* ctx, uint32_t fors_leaf_addr[8])
{
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf(uint8_t* leaf, const uint8_t* sk, const spx_ctx* ctx,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info
{
    uint32_t leaf_addrx[8];
};

static void fors_gen_leafx1(uint8_t* leaf, const spx_ctx* ctx, uint32_t addr_idx, void* info)
{
    struct fors_gen_leaf_info* fors_info = static_cast<struct fors_gen_leaf_info*>(info);
    uint32_t* fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf, ctx, fors_leaf_addr);
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t* indices, const uint8_t* m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= (uint32_t)(((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j);
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const spx_ctx* ctx,
               const uint32_t fors_addr[8])
{
    uint32_t* indices = (uint32_t*)heap_caps_malloc((sizeof(uint32_t)*(SPX_FORS_TREES)), MALLOC_CAP_DEFAULT);
    uint8_t* roots = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_FORS_TREES * SPX_N)), MALLOC_CAP_DEFAULT);
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t* fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        /* Compute the authentication path for this leaf node. */
        treehashx1(roots + i * SPX_N, sig, ctx, indices[i], idx_offset, SPX_FORS_HEIGHT,
                   fors_gen_leafx1, fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
    heap_caps_free(indices);
    heap_caps_free(roots);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const spx_ctx* ctx,
                      const uint32_t fors_addr[8])
{
    uint32_t* indices = (uint32_t*)heap_caps_malloc((sizeof(uint32_t)*(SPX_FORS_TREES)), MALLOC_CAP_DEFAULT);
    uint8_t* roots = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_FORS_TREES * SPX_N)), MALLOC_CAP_DEFAULT);
    uint8_t* leaf = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_N)), MALLOC_CAP_DEFAULT);
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        compute_root(roots + i * SPX_N, leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT,
                     ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
    heap_caps_free(indices);
    heap_caps_free(roots);
    heap_caps_free(leaf);
}
