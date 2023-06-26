#include <stdint.h>
#include <string.h>
#include "loggingcpp.h"

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
    debugMsg("variables initialized");

    info.wots_sig = sig;
    debugMsg("wots_sig set");
    chain_lengths(steps, root);
    debugMsg("chain lengths computed");
    info.wots_steps = steps;
    debugMsg("wots_steps set");

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);
    debugMsg("addresses set");

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leafx1, tree_addr,
               &info);
    debugMsg("treehashx1 completed");
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(uint8_t* root, const spx_ctx* ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
	debugMsg("merkle_gen_root called");
    uint8_t auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
	debugMsg("auth_path initialized");
    uint32_t top_tree_addr[8] = {0};
	debugMsg("top_tree_addr initialized");
    uint32_t wots_addr[8] = {0};
	debugMsg("wots_addr initialized");
    debugMsg("variables initialized");

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);
    debugMsg("addresses set");

    merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr,
                (uint32_t)~0 /* ~0 means "don't bother generating an auth path */);
    debugMsg("merkle_sign completed");
}
