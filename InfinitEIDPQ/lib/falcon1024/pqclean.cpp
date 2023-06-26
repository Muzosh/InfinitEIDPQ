/*
 * Wrapper for implementing the PQClean API.
 */

#include <stddef.h>
#include <string.h>

#include "api_falcon1024.h"
#include "inner.h"

#define NONCELEN 40

#include "randombytes.h"

/*
 * Encoding formats (nnnn = log of degree, 9 for Falcon-512, 10 for Falcon-1024)
 *
 *   private key:
 *      header byte: 0101nnnn
 *      private f  (6 or 5 bits by element, depending on degree)
 *      private g  (6 or 5 bits by element, depending on degree)
 *      private F  (8 bits by element)
 *
 *   public key:
 *      header byte: 0000nnnn
 *      public h   (14 bits by element)
 *
 *   signature:
 *      header byte: 0011nnnn
 *      nonce     40 bytes
 *      value     (12 bits by element)
 *
 *   message + signature:
 *      signature length   (2 bytes, big-endian)
 *      nonce              40 bytes
 *      message
 *      header byte:       0010nnnn
 *      value              (12 bits by element)
 *      (signature length is 1+len(value), not counting the nonce)
 */

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk)
{
    std::unique_ptr<uint8_t[]> b(new uint8_t[FALCON_KEYGEN_TEMP_10]);
    std::unique_ptr<int8_t[]> f(new int8_t[1024]);
    std::unique_ptr<int8_t[]> g(new int8_t[1024]);
    std::unique_ptr<int8_t[]> F(new int8_t[1024]);
    std::unique_ptr<uint16_t[]> h(new uint16_t[1024]);
    std::unique_ptr<uint8_t[]> seed(new uint8_t[48]);
    inner_shake256_context rng;
    size_t u, v;

    /*
     * Generate key pair.
     */
    randombytes(seed.get(), sizeof(uint8_t) * 48);
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed.get(), sizeof(uint8_t) * 48);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON1024_CLEAN_keygen(&rng, f.get(), g.get(), F.get(), NULL, h.get(), 10, b.get());
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    sk[0] = 0x50 + 10;
    u = 1;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u, f.get(), 10,
        PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u, g.get(), 10,
        PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u, F.get(), 10,
        PQCLEAN_FALCON1024_CLEAN_max_FG_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + 10;
    v = PQCLEAN_FALCON1024_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1, h.get(), 10);
    if (v != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}

/*
 * Compute the signature. nonce[] receives the nonce and must have length
 * NONCELEN bytes. sigbuf[] receives the signature value (without nonce
 * or header byte), with *sigbuflen providing the maximum value length and
 * receiving the actual value length.
 *
 * If a signature could be computed but not encoded because it would
 * exceed the output buffer size, then a new signature is computed. If
 * the provided buffer size is too low, this could loop indefinitely, so
 * the caller must provide a size that can accommodate signatures with a
 * large enough probability.
 *
 * Return value: 0 on success, -1 on error.
 */
static int do_sign(uint8_t* nonce, uint8_t* sigbuf, size_t* sigbuflen, const uint8_t* m,
                   size_t mlen, const uint8_t* sk)
{
    std::unique_ptr<uint8_t[]> b(new uint8_t[72 * 1024]);
    std::unique_ptr<int8_t[]> f(new int8_t[1024]);
    std::unique_ptr<int8_t[]> g(new int8_t[1024]);
    std::unique_ptr<int8_t[]> F(new int8_t[1024]);
    std::unique_ptr<int8_t[]> G(new int8_t[1024]);
    std::unique_ptr<uint8_t[]> seed(new uint8_t[48]);
    std::unique_ptr<int16_t[]> r_sig(new int16_t[1024]);
    std::unique_ptr<uint16_t[]> r_hm(new uint16_t[1024]);
    inner_shake256_context sc;
    size_t u, v;

    /*
     * Decode the private key.
     */
    if (sk[0] != 0x50 + 10) {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(f.get(), 10,
                                                PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10], sk + u,
                                                PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(g.get(), 10,
                                                PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10], sk + u,
                                                PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(F.get(), 10,
                                                PQCLEAN_FALCON1024_CLEAN_max_FG_bits[10], sk + u,
                                                PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }
    if (!PQCLEAN_FALCON1024_CLEAN_complete_private(G.get(), f.get(), g.get(), F.get(), 10,
                                                   b.get())) {
        return -1;
    }

    /*
     * Create a random nonce (40 bytes).
     */
    randombytes(nonce, NONCELEN);

    /*
     * Hash message nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON1024_CLEAN_hash_to_point_ct(&sc, r_hm.get(), 10, b.get());
    inner_shake256_ctx_release(&sc);

    /*
     * Initialize a RNG.
     */
    randombytes(seed.get(), sizeof(uint8_t) * 48);
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed.get(), sizeof(uint8_t) * 48);
    inner_shake256_flip(&sc);

    /*
     * Compute and return the signature. This loops until a signature
     * value is found that fits in the provided buffer.
     */
    for (;;) {
        PQCLEAN_FALCON1024_CLEAN_sign_dyn(r_sig.get(), &sc, f.get(), g.get(), F.get(), G.get(), r_hm.get(), 10, b.get());
        v = PQCLEAN_FALCON1024_CLEAN_comp_encode(sigbuf, *sigbuflen, r_sig.get(), 10);
        if (v != 0) {
            inner_shake256_ctx_release(&sc);
            *sigbuflen = v;
            return 0;
        }
    }
}

/*
 * Verify a sigature. The nonce has size NONCELEN bytes. sigbuf[]
 * (of size sigbuflen) contains the signature value, not including the
 * header byte or nonce. Return value is 0 on success, -1 on error.
 */
static int do_verify(const uint8_t* nonce, const uint8_t* sigbuf, size_t sigbuflen,
                     const uint8_t* m, size_t mlen, const uint8_t* pk)
{
    std::unique_ptr<uint8_t[]> b(new uint8_t[2 * 1024]);
    std::unique_ptr<uint16_t[]> h(new uint16_t[1024]);
    std::unique_ptr<uint16_t[]> hm(new uint16_t[1024]);
    std::unique_ptr<int16_t[]> sig(new int16_t[1024]);
    inner_shake256_context sc;

    /*
     * Decode public key.
     */
    if (pk[0] != 0x00 + 10) {
        return -1;
    }
    if (PQCLEAN_FALCON1024_CLEAN_modq_decode(h.get(), 10, pk + 1,
                                             PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
        != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }
    PQCLEAN_FALCON1024_CLEAN_to_ntt_monty(h.get(), 10);

    /*
     * Decode signature.
     */
    if (sigbuflen == 0) {
        return -1;
    }
    if (PQCLEAN_FALCON1024_CLEAN_comp_decode(sig.get(), 10, sigbuf, sigbuflen) != sigbuflen) {
        return -1;
    }

    /*
     * Hash nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    PQCLEAN_FALCON1024_CLEAN_hash_to_point_ct(&sc, hm.get(), 10, b.get());
    inner_shake256_ctx_release(&sc);

    /*
     * Verify signature.
     */
    if (!PQCLEAN_FALCON1024_CLEAN_verify_raw(hm.get(), sig.get(), h.get(), 10, b.get())) {
        return -1;
    }
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m,
                                                   size_t mlen, const uint8_t* sk)
{
    /*
     * The PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES constant is used for
     * the signed message object (as produced by crypto_sign())
     * and includes a two-byte length value, so we take care here
     * to only generate signatures that are two bytes shorter than
     * the maximum. This is done to ensure that crypto_sign()
     * and crypto_sign_signature() produce the exact same signature
     * value, if used on the same message, with the same private key,
     * and using the same output from randombytes() (this is for
     * reproducibility of tests).
     */
    size_t vlen;

    vlen = PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES - NONCELEN - 3;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, &vlen, m, mlen, sk) < 0) {
        return -1;
    }
    sig[0] = 0x30 + 10;
    *siglen = 1 + NONCELEN + vlen;
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m,
                                                size_t mlen, const uint8_t* pk)
{
    if (siglen < 1 + NONCELEN) {
        return -1;
    }
    if (sig[0] != 0x30 + 10) {
        return -1;
    }
    return do_verify(sig + 1, sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen,
                                         const uint8_t* sk)
{
    uint8_t *pm, *sigbuf;
    size_t sigbuflen;

    /*
     * Move the message to its final location; this is a memmove() so
     * it handles overlaps properly.
     */
    memmove(sm + 2 + NONCELEN, m, mlen);
    pm = sm + 2 + NONCELEN;
    sigbuf = pm + 1 + mlen;
    sigbuflen = PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES - NONCELEN - 3;
    if (do_sign(sm + 2, sigbuf, &sigbuflen, pm, mlen, sk) < 0) {
        return -1;
    }
    pm[mlen] = 0x20 + 10;
    sigbuflen++;
    sm[0] = (uint8_t)(sigbuflen >> 8);
    sm[1] = (uint8_t)sigbuflen;
    *smlen = mlen + 2 + NONCELEN + sigbuflen;
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(uint8_t* m, size_t* mlen, const uint8_t* sm,
                                              size_t smlen, const uint8_t* pk)
{
    const uint8_t* sigbuf;
    size_t pmlen, sigbuflen;

    if (smlen < 3 + NONCELEN) {
        return -1;
    }
    sigbuflen = ((size_t)sm[0] << 8) | (size_t)sm[1];
    if (sigbuflen < 2 || sigbuflen > (smlen - NONCELEN - 2)) {
        return -1;
    }
    sigbuflen--;
    pmlen = smlen - NONCELEN - 3 - sigbuflen;
    if (sm[2 + NONCELEN + pmlen] != 0x20 + 10) {
        return -1;
    }
    sigbuf = sm + 2 + NONCELEN + pmlen + 1;

    /*
     * The 2-byte length header and the one-byte signature header
     * have been verified. Nonce is at sm+2, followed by the message
     * itself. Message length is in pmlen. sigbuf/sigbuflen point to
     * the signature value (excluding the header byte).
     */
    if (do_verify(sm + 2, sigbuf, sigbuflen, sm + 2 + NONCELEN, pmlen, pk) < 0) {
        return -1;
    }

    /*
     * Signature is correct, we just have to copy/move the message
     * to its final destination. The memmove() properly handles
     * overlaps.
     */
    memmove(m, sm + 2 + NONCELEN, pmlen);
    *mlen = pmlen;
    return 0;
}
