#include <stdint.h>
#include <string.h>
#include <memory>
#include <esp_heap_caps.h>

#include "address.h"
#include "merkle.h"
#include "params.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign(uint8_t* sig, uint8_t* root, const spx_ctx* ctx, uint32_t wots_addr[8],
                 uint32_t tree_addr[8], uint32_t idx_leaf)
{
    uint8_t* auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = {0};
    unsigned steps[SPX_WOTS_LEN];

    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leafx1, tree_addr,
               &info);
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(uint8_t* root, const spx_ctx* ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    uint8_t* auth_path = (uint8_t*)heap_caps_malloc((sizeof(uint8_t)*(SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES)), MALLOC_CAP_DEFAULT);
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr,
                (uint32_t)~0 /* ~0 means "don't bother generating an auth path */);
    heap_caps_free(auth_path);
}
