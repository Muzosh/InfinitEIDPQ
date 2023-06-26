#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "utils.h"

/*
 * Specify which level of Merkle tree (the "layer") we're working on
 */
void set_layer_addr(uint32_t addr[8], uint32_t layer) {
    ((uint8_t *)addr)[SPX_OFFSET_LAYER] = (uint8_t)layer;
}

/*
 * Specify which Merkle tree within the level (the "tree address") we're working on
 */
void set_tree_addr(uint32_t addr[8], uint64_t tree) {
    ull_to_bytes(&((uint8_t *)addr)[SPX_OFFSET_TREE], 8, tree );
}

/*
 * Specify the reason we'll use this address structure for, that is, what
 * hash will we compute with it.  This is used so that unrelated types of
 * hashes don't accidentally get the same address structure.  The type will be
 * one of the SPX_ADDR_TYPE constants
 */
void set_type(uint32_t addr[8], uint32_t type) {
    ((uint8_t *)addr)[SPX_OFFSET_TYPE] = (uint8_t)type;
}

/*
 * Copy the layer and tree fields of the address structure.  This is used
 * when we're doing multiple types of hashes within the same Merkle tree
 */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]) {
    memcpy( out, in, SPX_OFFSET_TREE + 8 );
}

/* These functions are used for OTS addresses. */

/*
 * Specify which Merkle leaf we're working on; that is, which OTS keypair
 * we're talking about.
 */
void set_keypair_addr(uint32_t addr[8], uint32_t keypair) {
    ((uint8_t *)addr)[SPX_OFFSET_KP_ADDR1] = (uint8_t)keypair;
}

/*
 * Copy the layer, tree and keypair fields of the address structure.  This is
 * used when we're doing multiple things within the same OTS keypair
 */
void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]) {
    memcpy( out, in, SPX_OFFSET_TREE + 8 );
    ((uint8_t *)out)[SPX_OFFSET_KP_ADDR1] = ((uint8_t *)in)[SPX_OFFSET_KP_ADDR1];
}

/*
 * Specify which Merkle chain within the OTS we're working with
 * (the chain address)
 */
void set_chain_addr(uint32_t addr[8], uint32_t chain) {
    ((uint8_t *)addr)[SPX_OFFSET_CHAIN_ADDR] = (uint8_t)chain;
}

/*
 * Specify where in the Merkle chain we are
* (the hash address)
 */
void set_hash_addr(uint32_t addr[8], uint32_t hash) {
    ((uint8_t *)addr)[SPX_OFFSET_HASH_ADDR] = (uint8_t)hash;
}

/* These functions are used for all hash tree addresses (including FORS). */

/*
 * Specify the height of the node in the Merkle/FORS tree we are in
 * (the tree height)
 */
void set_tree_height(uint32_t addr[8], uint32_t tree_height) {
    ((uint8_t *)addr)[SPX_OFFSET_TREE_HGT] = (uint8_t)tree_height;
}

/*
 * Specify the distance from the left edge of the node in the Merkle/FORS tree
 * (the tree index)
 */
void set_tree_index(uint32_t addr[8], uint32_t tree_index) {
    u32_to_bytes(&((uint8_t *)addr)[SPX_OFFSET_TREE_INDEX], tree_index );
}
