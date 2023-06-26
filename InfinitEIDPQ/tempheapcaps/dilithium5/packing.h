#ifndef PQCLEAN_DILITHIUM5_CLEAN_PACKING_H
#define PQCLEAN_DILITHIUM5_CLEAN_PACKING_H
#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void PQCLEAN_DILITHIUM5_CLEAN_pack_pk(uint8_t* pk, const uint8_t* rho, const polyveck* t1);

void PQCLEAN_DILITHIUM5_CLEAN_pack_sk(uint8_t* sk, const uint8_t* rho, const uint8_t* tr,
                                      const uint8_t* key, const polyveck* t0, const polyvecl* s1,
                                      const polyveck* s2);

void PQCLEAN_DILITHIUM5_CLEAN_pack_sig(uint8_t* sig, const uint8_t* c, const polyvecl* z,
                                       const polyveck* h);

void PQCLEAN_DILITHIUM5_CLEAN_unpack_pk(uint8_t* rho, polyveck* t1, const uint8_t* pk);

void PQCLEAN_DILITHIUM5_CLEAN_unpack_sk(uint8_t* rho, uint8_t* tr, uint8_t* key, polyveck* t0,
                                        polyvecl* s1, polyveck* s2, const uint8_t* sk);

int PQCLEAN_DILITHIUM5_CLEAN_unpack_sig(uint8_t* c, polyvecl* z, polyveck* h, const uint8_t* sig);

#endif
