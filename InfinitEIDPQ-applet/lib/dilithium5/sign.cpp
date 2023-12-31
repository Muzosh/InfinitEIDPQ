#include <fips202.h>
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>
#include <memory>
#include <vector>

/*************************************************
 * Name:        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk)
{
    std::unique_ptr<uint8_t[]> seedbuf(new uint8_t[2 * SEEDBYTES + CRHBYTES]);
    std::unique_ptr<uint8_t[]> tr(new uint8_t[SEEDBYTES]);
    const uint8_t *rho, *rhoprime, *key;
    std::unique_ptr<polyvecl[]> mat(new polyvecl[K]);
    std::unique_ptr<polyvecl> s1(new polyvecl);
    std::unique_ptr<polyvecl> s1hat(new polyvecl);
    std::unique_ptr<polyveck> s2(new polyveck);
    std::unique_ptr<polyveck> t1(new polyveck);
    std::unique_ptr<polyveck> t0(new polyveck);

    /* Get randomness for rho, rhoprime and key */
    randombytes(seedbuf.get(), SEEDBYTES);
    shake256(seedbuf.get(), 2 * SEEDBYTES + CRHBYTES, seedbuf.get(), SEEDBYTES);
    rho = seedbuf.get();
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_expand(mat.get(), rho);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_eta(s1.get(), rhoprime, 0);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_uniform_eta(s2.get(), rhoprime, L);

    /* Matrix-vector multiplication */
    *s1hat = *s1;
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(s1hat.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_pointwise_montgomery(t1.get(), mat.get(), s1hat.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(t1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(t1.get());

    /* Add error vector s2 */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_add(t1.get(), t1.get(), s2.get());

    /* Extract t1 and write public key */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_caddq(t1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_power2round(t1.get(), t0.get(), t1.get());
    PQCLEAN_DILITHIUM5_CLEAN_pack_pk(pk, rho, t1.get());

    /* Compute H(rho, t1) and write secret key */
    shake256(tr.get(), SEEDBYTES, pk, PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_DILITHIUM5_CLEAN_pack_sk(sk, rho, tr.get(), key, t0.get(), s1.get(), s2.get());

    return 0;
}

/*************************************************
 * Name:        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length
 *PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m,
                                                   size_t mlen, const uint8_t* sk)
{
    unsigned int n;
    std::unique_ptr<uint8_t[]> seedbuf(new uint8_t[3 * SEEDBYTES + 2 * CRHBYTES]);
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    std::unique_ptr<uint16_t> nonce(new uint16_t);
    *nonce = 0;
    std::unique_ptr<polyvecl[]> mat(new polyvecl[K]);
    std::unique_ptr<polyvecl> s1(new polyvecl);
    std::unique_ptr<polyvecl> y(new polyvecl);
    std::unique_ptr<polyvecl> z(new polyvecl);
    std::unique_ptr<polyveck> t0(new polyveck);
    std::unique_ptr<polyveck> s2(new polyveck);
    std::unique_ptr<polyveck> w1(new polyveck);
    std::unique_ptr<polyveck> w0(new polyveck);
    std::unique_ptr<polyveck> h(new polyveck);
    std::unique_ptr<poly> cp(new poly);
    std::unique_ptr<shake256incctx> state(new shake256incctx);

    rho = seedbuf.get();
    tr = rho + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_DILITHIUM5_CLEAN_unpack_sk(rho, tr, key, t0.get(), s1.get(), s2.get(), sk);

    /* Compute CRH(tr, msg) */
    shake256_inc_init(state.get());
    shake256_inc_absorb(state.get(), tr, SEEDBYTES);
    shake256_inc_absorb(state.get(), m, mlen);
    shake256_inc_finalize(state.get());
    shake256_inc_squeeze(mu, CRHBYTES, state.get());
    shake256_inc_ctx_release(state.get());

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_expand(mat.get(), rho);
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(s1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_ntt(s2.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_ntt(t0.get());

rej:
    /* Sample intermediate vector y */
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_gamma1(y.get(), rhoprime, (*nonce)++);

    /* Matrix-vector multiplication */
    *z = *y;
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(z.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_pointwise_montgomery(w1.get(), mat.get(), z.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(w1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(w1.get());

    /* Decompose w and call the random oracle */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_caddq(w1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_decompose(w1.get(), w0.get(), w1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_pack_w1(sig, w1.get());

    shake256_inc_init(state.get());
    shake256_inc_absorb(state.get(), mu, CRHBYTES);
    shake256_inc_absorb(state.get(), sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(state.get());
    shake256_inc_squeeze(sig, SEEDBYTES, state.get());
    shake256_inc_ctx_release(state.get());
    PQCLEAN_DILITHIUM5_CLEAN_poly_challenge(cp.get(), sig);
    PQCLEAN_DILITHIUM5_CLEAN_poly_ntt(cp.get());

    /* Compute z, reject if it reveals secret */
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_pointwise_poly_montgomery(z.get(), cp.get(), s1.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_invntt_tomont(z.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_add(z.get(), z.get(), y.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_reduce(z.get());
    if (PQCLEAN_DILITHIUM5_CLEAN_polyvecl_chknorm(z.get(), GAMMA1 - BETA)) {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(h.get(), cp.get(), s2.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(h.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_sub(w0.get(), w0.get(), h.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(w0.get());
    if (PQCLEAN_DILITHIUM5_CLEAN_polyveck_chknorm(w0.get(), GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(h.get(), cp.get(), t0.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(h.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(h.get());
    if (PQCLEAN_DILITHIUM5_CLEAN_polyveck_chknorm(h.get(), GAMMA2)) {
        goto rej;
    }

    PQCLEAN_DILITHIUM5_CLEAN_polyveck_add(w0.get(), w0.get(), h.get());
    n = PQCLEAN_DILITHIUM5_CLEAN_polyveck_make_hint(h.get(), w0.get(), w1.get());
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_DILITHIUM5_CLEAN_pack_sig(sig, sig, z.get(), h.get());
    *siglen = PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES;
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign
 *
 * Description: Compute signed message.
 *
 * Arguments:   - uint8_t *sm: pointer to output signed message (allocated
 *                             array with PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES + mlen bytes),
 *                             can be equal to m
 *              - size_t *smlen: pointer to output length of signed
 *                               message
 *              - const uint8_t *m: pointer to message to be signed
 *              - size_t mlen: length of message
 *              - const uint8_t *sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen,
                                         const uint8_t* sk)
{
    size_t i;

    for (i = 0; i < mlen; ++i) {
        sm[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(
        sm, smlen, sm + PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES, mlen, sk);
    *smlen += mlen;
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,
                                                size_t mlen, const uint8_t* pk)
{
    unsigned int i;
    std::unique_ptr<uint8_t[]> buf(new uint8_t[K * POLYW1_PACKEDBYTES]);
    std::unique_ptr<uint8_t[]> rho(new uint8_t[SEEDBYTES]);
    std::unique_ptr<uint8_t[]> mu(new uint8_t[CRHBYTES]);
    std::unique_ptr<uint8_t[]> c(new uint8_t[SEEDBYTES]);
    std::unique_ptr<uint8_t[]> c2(new uint8_t[SEEDBYTES]);
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    if (siglen != PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES) {
        return -1;
    }

    PQCLEAN_DILITHIUM5_CLEAN_unpack_pk(rho.get(), &t1, pk);
    if (PQCLEAN_DILITHIUM5_CLEAN_unpack_sig(c.get(), &z, &h, sig)) {
        return -1;
    }
    if (PQCLEAN_DILITHIUM5_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu.get(), SEEDBYTES, pk, PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu.get(), SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu.get(), CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    PQCLEAN_DILITHIUM5_CLEAN_poly_challenge(&cp, c.get());
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_expand(mat, rho.get());

    PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_DILITHIUM5_CLEAN_poly_ntt(&cp);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_DILITHIUM5_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_DILITHIUM5_CLEAN_polyveck_pack_w1(buf.get(), &w1);

    /* Call random oracle and verify PQCLEAN_DILITHIUM5_CLEAN_challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu.get(), CRHBYTES);
    shake256_inc_absorb(&state, buf.get(), K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2.get(), SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i) {
        if (c.get()[i] != c2.get()[i]) {
            return -1;
        }
    }

    return 0;
}

/*************************************************
 * Name:        PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - size_t *mlen: pointer to output length of message
 *              - const uint8_t *sm: pointer to signed message
 *              - size_t smlen: length of signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open(uint8_t* m, size_t* mlen, const uint8_t* sm,
                                              size_t smlen, const uint8_t* pk)
{
    size_t i;

    if (smlen < PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES) {
        goto badsig;
    }

    *mlen = smlen - PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES;
    if (PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(sm, PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES,
                                                    sm + PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES,
                                                    *mlen, pk)) {
        goto badsig;
    } else {
        /* All good, copy msg, return 0 */
        for (i = 0; i < *mlen; ++i) {
            m[i] = sm[PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES + i];
        }
        return 0;
    }

badsig:
    /* Signature verification failed */
    *mlen = (size_t)-1;
    for (i = 0; i < smlen; ++i) {
        m[i] = 0;
    }

    return -1;
}
