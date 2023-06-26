/*
 * Constant time implementation of the Haraka hash function.
 *
 * The bit-sliced implementation of the AES round functions are
 * based on the AES implementation in BearSSL written
 * by Thomas Pornin <pornin@bolet.org>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "haraka.h"
#include "utils.h"
#include "logging.h"
#include <esp_system.h>

#define HARAKAS_RATE 32

static const uint64_t haraka512_rc64[10][8] = {
    {0x24cf0ab9086f628b, 0xbdd6eeecc83b8382, 0xd96fb0306cdad0a7, 0xaace082ac8f95f89,
     0x449d8e8870d7041f, 0x49bb2f80b2b3e2f8, 0x0569ae98d93bb258, 0x23dc9691e7d6a4b1},
    {0xd8ba10ede0fe5b6e, 0x7ecf7dbe424c7b8e, 0x6ea9949c6df62a31, 0xbf3f3c97ec9c313e,
     0x241d03a196a1861e, 0xead3a51116e5a2ea, 0x77d479fcad9574e3, 0x18657a1af894b7a0},
    {0x10671e1a7f595522, 0xd9a00ff675d28c7b, 0x2f1edf0d2b9ba661, 0xb8ff58b8e3de45f9,
     0xee29261da9865c02, 0xd1532aa4b50bdf43, 0x8bf858159b231bb1, 0xdf17439d22d4f599},
    {0xdd4b2f0870b918c0, 0x757a81f3b39b1bb6, 0x7a5c556898952e3f, 0x7dd70a16d915d87a,
     0x3ae61971982b8301, 0xc3ab319e030412be, 0x17c0033ac094a8cb, 0x5a0630fc1a8dc4ef},
    {0x17708988c1632f73, 0xf92ddae090b44f4f, 0x11ac0285c43aa314, 0x509059941936b8ba,
     0xd03e152fa2ce9b69, 0x3fbcbcb63a32998b, 0x6204696d692254f7, 0x915542ed93ec59b4},
    {0xf4ed94aa8879236e, 0xff6cb41cd38e03c0, 0x069b38602368aeab, 0x669495b820f0ddba,
     0xf42013b1b8bf9e3d, 0xcf935efe6439734d, 0xbc1dcf42ca29e3f8, 0x7e6d3ed29f78ad67},
    {0xf3b0f6837ffcddaa, 0x3a76faef934ddf41, 0xcec7ae583a9c8e35, 0xe4dd18c68f0260af,
     0x2c0e5df1ad398eaa, 0x478df5236ae22e8c, 0xfb944c46fe865f39, 0xaa48f82f028132ba},
    {0x231b9ae2b76aca77, 0x292a76a712db0b40, 0x5850625dc8134491, 0x73137dd469810fb5,
     0x8a12a6a202a474fd, 0xd36fd9daa78bdb80, 0xb34c5e733505706f, 0xbaf1cdca818d9d96},
    {0x2e99781335e8c641, 0xbddfe5cce47d560e, 0xf74e9bf32e5e040c, 0x1d7a709d65996be9,
     0x670df36a9cf66cdd, 0xd05ef84a176a2875, 0x0f888e828cb1c44e, 0x1a79e9c9727b052c},
    {0x83497348628d84de, 0x2e9387d51f22a754, 0xb000068da2f852d6, 0x378c9e1190fd6fe5,
     0x870027c316de7293, 0xe51a9d4462e047bb, 0x90ecf7f8c6251195, 0x655953bfbed90a9c},
};

static inline uint32_t br_dec32le(const uint8_t* src)
{
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

static void br_range_dec32le(uint32_t* v, size_t num, const uint8_t* src)
{
    while (num-- > 0) {
        *v++ = br_dec32le(src);
        src += 4;
    }
}

static inline void br_enc32le(uint8_t* dst, uint32_t x)
{
    dst[0] = (uint8_t)x;
    dst[1] = (uint8_t)(x >> 8);
    dst[2] = (uint8_t)(x >> 16);
    dst[3] = (uint8_t)(x >> 24);
}

static void br_range_enc32le(uint8_t* dst, const uint32_t* v, size_t num)
{
    while (num-- > 0) {
        br_enc32le(dst, *v++);
        dst += 4;
    }
}

static void br_aes_ct64_bitslice_Sbox(uint64_t* q)
{
    /*
     * This S-box implementation is a straightforward translation of
     * the circuit described by Boyar and Peralta in "A new
     * combinational logic minimization technique with applications
     * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
     *
     * Note that variables x* (input) and s* (output) are numbered
     * in "reverse" order (x[0] is the high bit, x[7] is the low bit).
     */

    uint64_t* x = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);
    uint64_t* y = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 22, MALLOC_CAP_DEFAULT);
    uint64_t* z = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 18, MALLOC_CAP_DEFAULT);
    uint64_t* t = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 68, MALLOC_CAP_DEFAULT);
    uint64_t* s = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);

    x[0] = q[7];
    x[1] = q[6];
    x[2] = q[5];
    x[3] = q[4];
    x[4] = q[3];
    x[5] = q[2];
    x[6] = q[1];
    x[7] = q[0];

    /*
     * Top linear transformation.
     */
    y[14] = x[3] ^ x[5];
    y[13] = x[0] ^ x[6];
    y[9] = x[0] ^ x[3];
    y[8] = x[0] ^ x[5];
    t[0] = x[1] ^ x[2];
    y[1] = t[0] ^ x[7];
    y[4] = y[1] ^ x[3];
    y[12] = y[13] ^ y[14];
    y[2] = y[1] ^ x[0];
    y[5] = y[1] ^ x[6];
    y[3] = y[5] ^ y[8];
    t[1] = x[4] ^ y[12];
    y[15] = t[1] ^ x[5];
    y[20] = t[1] ^ x[1];
    y[6] = y[15] ^ x[7];
    y[10] = y[15] ^ t[0];
    y[11] = y[20] ^ y[9];
    y[7] = x[7] ^ y[11];
    y[17] = y[10] ^ y[11];
    y[19] = y[10] ^ y[8];
    y[16] = t[0] ^ y[11];
    y[21] = y[13] ^ y[16];
    y[18] = x[0] ^ y[16];

    /*
     * Non-linear section.
     */
    t[2] = y[12] & y[15];
    t[3] = y[3] & y[6];
    t[4] = t[3] ^ t[2];
    t[5] = y[4] & x[7];
    t[6] = t[5] ^ t[2];
    t[7] = y[13] & y[16];
    t[8] = y[5] & y[1];
    t[9] = t[8] ^ t[7];
    t[10] = y[2] & y[7];
    t[11] = t[10] ^ t[7];
    t[12] = y[9] & y[11];
    t[13] = y[14] & y[17];
    t[14] = t[13] ^ t[12];
    t[15] = y[8] & y[10];
    t[16] = t[15] ^ t[12];
    t[17] = t[4] ^ t[14];
    t[18] = t[6] ^ t[16];
    t[19] = t[9] ^ t[14];
    t[20] = t[11] ^ t[16];
    t[21] = t[17] ^ y[20];
    t[22] = t[18] ^ y[19];
    t[23] = t[19] ^ y[21];
    t[24] = t[20] ^ y[18];

    t[25] = t[21] ^ t[22];
    t[26] = t[21] & t[23];
    t[27] = t[24] ^ t[26];
    t[28] = t[25] & t[27];
    t[29] = t[28] ^ t[22];
    t[30] = t[23] ^ t[24];
    t[31] = t[22] ^ t[26];
    t[32] = t[31] & t[30];
    t[33] = t[32] ^ t[24];
    t[34] = t[23] ^ t[33];
    t[35] = t[27] ^ t[33];
    t[36] = t[24] & t[35];
    t[37] = t[36] ^ t[34];
    t[38] = t[27] ^ t[36];
    t[39] = t[29] & t[38];
    t[40] = t[25] ^ t[39];

    t[41] = t[40] ^ t[37];
    t[42] = t[29] ^ t[33];
    t[43] = t[29] ^ t[40];
    t[44] = t[33] ^ t[37];
    t[45] = t[42] ^ t[41];
    z[0] = t[44] & y[15];
    z[1] = t[37] & y[6];
    z[2] = t[33] & x[7];
    z[3] = t[43] & y[16];
    z[4] = t[40] & y[1];
    z[5] = t[29] & y[7];
    z[6] = t[42] & y[11];
    z[7] = t[45] & y[17];
    z[8] = t[41] & y[10];
    z[9] = t[44] & y[12];
    z[10] = t[37] & y[3];
    z[11] = t[33] & y[4];
    z[12] = t[43] & y[13];
    z[13] = t[40] & y[5];
    z[14] = t[29] & y[2];
    z[15] = t[42] & y[9];
    z[16] = t[45] & y[14];
    z[17] = t[41] & y[8];

    /*
     * Bottom linear transformation.
     */
    t[46] = z[15] ^ z[16];
    t[47] = z[10] ^ z[11];
    t[48] = z[5] ^ z[13];
    t[49] = z[9] ^ z[10];
    t[50] = z[2] ^ z[12];
    t[51] = z[2] ^ z[5];
    t[52] = z[7] ^ z[8];
    t[53] = z[0] ^ z[3];
    t[54] = z[6] ^ z[7];
    t[55] = z[16] ^ z[17];
    t[56] = z[12] ^ t[48];
    t[57] = t[50] ^ t[53];
    t[58] = z[4] ^ t[46];
    t[59] = z[3] ^ t[54];
    t[60] = t[46] ^ t[57];
    t[61] = z[14] ^ t[57];
    t[62] = t[52] ^ t[58];
    t[63] = t[49] ^ t[58];
    t[64] = z[4] ^ t[59];
    t[65] = t[61] ^ t[62];
    t[66] = z[1] ^ t[63];
    s[0] = t[59] ^ t[63];
    s[6] = t[56] ^ ~t[62];
    s[7] = t[48] ^ ~t[60];
    t[67] = t[64] ^ t[65];
    s[3] = t[53] ^ t[66];
    s[4] = t[51] ^ t[66];
    s[5] = t[47] ^ t[65];
    s[1] = t[64] ^ ~s[3];
    s[2] = t[55] ^ ~t[67];

    q[7] = s[0];
    q[6] = s[1];
    q[5] = s[2];
    q[4] = s[3];
    q[3] = s[4];
    q[2] = s[5];
    q[1] = s[6];
    q[0] = s[7];

    heap_caps_free(x);
    heap_caps_free(y);
    heap_caps_free(z);
    heap_caps_free(t);
    heap_caps_free(s);
}

static void br_aes_ct_bitslice_Sbox(uint32_t* q)
{
    /*
     * This S-box implementation is a straightforward translation of
     * the circuit described by Boyar and Peralta in "A new
     * combinational logic minimization technique with applications
     * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
     *
     * Note that variables x* (input) and s* (output) are numbered
     * in "reverse" order (x[0] is the high bit, x[7] is the low bit).
     */

    uint64_t* x = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);
    uint64_t* y = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 22, MALLOC_CAP_DEFAULT);
    uint64_t* z = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 18, MALLOC_CAP_DEFAULT);
    uint64_t* t = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 68, MALLOC_CAP_DEFAULT);
    uint64_t* s = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);

    x[0] = q[7];
    x[1] = q[6];
    x[2] = q[5];
    x[3] = q[4];
    x[4] = q[3];
    x[5] = q[2];
    x[6] = q[1];
    x[7] = q[0];

    /*
     * Top linear transformation.
     */
    y[14] = x[3] ^ x[5];
    y[13] = x[0] ^ x[6];
    y[9] = x[0] ^ x[3];
    y[8] = x[0] ^ x[5];
    t[0] = x[1] ^ x[2];
    y[1] = t[0] ^ x[7];
    y[4] = y[1] ^ x[3];
    y[12] = y[13] ^ y[14];
    y[2] = y[1] ^ x[0];
    y[5] = y[1] ^ x[6];
    y[3] = y[5] ^ y[8];
    t[1] = x[4] ^ y[12];
    y[15] = t[1] ^ x[5];
    y[20] = t[1] ^ x[1];
    y[6] = y[15] ^ x[7];
    y[10] = y[15] ^ t[0];
    y[11] = y[20] ^ y[9];
    y[7] = x[7] ^ y[11];
    y[17] = y[10] ^ y[11];
    y[19] = y[10] ^ y[8];
    y[16] = t[0] ^ y[11];
    y[21] = y[13] ^ y[16];
    y[18] = x[0] ^ y[16];

    /*
     * Non-linear section.
     */
    t[2] = y[12] & y[15];
    t[3] = y[3] & y[6];
    t[4] = t[3] ^ t[2];
    t[5] = y[4] & x[7];
    t[6] = t[5] ^ t[2];
    t[7] = y[13] & y[16];
    t[8] = y[5] & y[1];
    t[9] = t[8] ^ t[7];
    t[10] = y[2] & y[7];
    t[11] = t[10] ^ t[7];
    t[12] = y[9] & y[11];
    t[13] = y[14] & y[17];
    t[14] = t[13] ^ t[12];
    t[15] = y[8] & y[10];
    t[16] = t[15] ^ t[12];
    t[17] = t[4] ^ t[14];
    t[18] = t[6] ^ t[16];
    t[19] = t[9] ^ t[14];
    t[20] = t[11] ^ t[16];
    t[21] = t[17] ^ y[20];
    t[22] = t[18] ^ y[19];
    t[23] = t[19] ^ y[21];
    t[24] = t[20] ^ y[18];

    t[25] = t[21] ^ t[22];
    t[26] = t[21] & t[23];
    t[27] = t[24] ^ t[26];
    t[28] = t[25] & t[27];
    t[29] = t[28] ^ t[22];
    t[30] = t[23] ^ t[24];
    t[31] = t[22] ^ t[26];
    t[32] = t[31] & t[30];
    t[33] = t[32] ^ t[24];
    t[34] = t[23] ^ t[33];
    t[35] = t[27] ^ t[33];
    t[36] = t[24] & t[35];
    t[37] = t[36] ^ t[34];
    t[38] = t[27] ^ t[36];
    t[39] = t[29] & t[38];
    t[40] = t[25] ^ t[39];

    t[41] = t[40] ^ t[37];
    t[42] = t[29] ^ t[33];
    t[43] = t[29] ^ t[40];
    t[44] = t[33] ^ t[37];
    t[45] = t[42] ^ t[41];
    z[0] = t[44] & y[15];
    z[1] = t[37] & y[6];
    z[2] = t[33] & x[7];
    z[3] = t[43] & y[16];
    z[4] = t[40] & y[1];
    z[5] = t[29] & y[7];
    z[6] = t[42] & y[11];
    z[7] = t[45] & y[17];
    z[8] = t[41] & y[10];
    z[9] = t[44] & y[12];
    z[10] = t[37] & y[3];
    z[11] = t[33] & y[4];
    z[12] = t[43] & y[13];
    z[13] = t[40] & y[5];
    z[14] = t[29] & y[2];
    z[15] = t[42] & y[9];
    z[16] = t[45] & y[14];
    z[17] = t[41] & y[8];

    /*
     * Bottom linear transformation.
     */
    t[46] = z[15] ^ z[16];
    t[47] = z[10] ^ z[11];
    t[48] = z[5] ^ z[13];
    t[49] = z[9] ^ z[10];
    t[50] = z[2] ^ z[12];
    t[51] = z[2] ^ z[5];
    t[52] = z[7] ^ z[8];
    t[53] = z[0] ^ z[3];
    t[54] = z[6] ^ z[7];
    t[55] = z[16] ^ z[17];
    t[56] = z[12] ^ t[48];
    t[57] = t[50] ^ t[53];
    t[58] = z[4] ^ t[46];
    t[59] = z[3] ^ t[54];
    t[60] = t[46] ^ t[57];
    t[61] = z[14] ^ t[57];
    t[62] = t[52] ^ t[58];
    t[63] = t[49] ^ t[58];
    t[64] = z[4] ^ t[59];
    t[65] = t[61] ^ t[62];
    t[66] = z[1] ^ t[63];
    s[0] = t[59] ^ t[63];
    s[6] = t[56] ^ ~t[62];
    s[7] = t[48] ^ ~t[60];
    t[67] = t[64] ^ t[65];
    s[3] = t[53] ^ t[66];
    s[4] = t[51] ^ t[66];
    s[5] = t[47] ^ t[65];
    s[1] = t[64] ^ ~s[3];
    s[2] = t[55] ^ ~t[67];

    q[7] = s[0];
    q[6] = s[1];
    q[5] = s[2];
    q[4] = s[3];
    q[3] = s[4];
    q[2] = s[5];
    q[1] = s[6];
    q[0] = s[7];

    heap_caps_free(x);
    heap_caps_free(y);
    heap_caps_free(z);
    heap_caps_free(t);
    heap_caps_free(s);
}

static void br_aes_ct_ortho(uint32_t* q)
{
#define SWAPN_32(cl, ch, s, x, y)                                                                  \
    do {                                                                                           \
        uint32_t a, b;                                                                             \
        a = (x);                                                                                   \
        b = (y);                                                                                   \
        (x) = (a & (uint32_t)(cl)) | ((b & (uint32_t)(cl)) << (s));                                \
        (y) = ((a & (uint32_t)(ch)) >> (s)) | (b & (uint32_t)(ch));                                \
    } while (0)

#define SWAP2_32(x, y) SWAPN_32(0x55555555, 0xAAAAAAAA, 1, x, y)
#define SWAP4_32(x, y) SWAPN_32(0x33333333, 0xCCCCCCCC, 2, x, y)
#define SWAP8_32(x, y) SWAPN_32(0x0F0F0F0F, 0xF0F0F0F0, 4, x, y)

    SWAP2_32(q[0], q[1]);
    SWAP2_32(q[2], q[3]);
    SWAP2_32(q[4], q[5]);
    SWAP2_32(q[6], q[7]);

    SWAP4_32(q[0], q[2]);
    SWAP4_32(q[1], q[3]);
    SWAP4_32(q[4], q[6]);
    SWAP4_32(q[5], q[7]);

    SWAP8_32(q[0], q[4]);
    SWAP8_32(q[1], q[5]);
    SWAP8_32(q[2], q[6]);
    SWAP8_32(q[3], q[7]);
}

static inline void add_round_key32(uint32_t* q, const uint32_t* sk)
{
    q[0] ^= sk[0];
    q[1] ^= sk[1];
    q[2] ^= sk[2];
    q[3] ^= sk[3];
    q[4] ^= sk[4];
    q[5] ^= sk[5];
    q[6] ^= sk[6];
    q[7] ^= sk[7];
}

static inline void shift_rows32(uint32_t* q)
{
    int i;

    for (i = 0; i < 8; i++) {
        uint32_t x;

        x = q[i];
        q[i] = (x & 0x000000FF) | ((x & 0x0000FC00) >> 2) | ((x & 0x00000300) << 6)
            | ((x & 0x00F00000) >> 4) | ((x & 0x000F0000) << 4) | ((x & 0xC0000000) >> 6)
            | ((x & 0x3F000000) << 2);
    }
}

static inline uint32_t rotr16(uint32_t x)
{
    return (x << 16) | (x >> 16);
}

static inline void mix_columns32(uint32_t* q)
{
    uint64_t* qn = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);
    uint64_t* r = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);

    qn[0] = q[0];
    qn[1] = q[1];
    qn[2] = q[2];
    qn[3] = q[3];
    qn[4] = q[4];
    qn[5] = q[5];
    qn[6] = q[6];
    qn[7] = q[7];
    r[0] = (qn[0] >> 8) | (qn[0] << 24);
    r[1] = (qn[1] >> 8) | (qn[1] << 24);
    r[2] = (qn[2] >> 8) | (qn[2] << 24);
    r[3] = (qn[3] >> 8) | (qn[3] << 24);
    r[4] = (qn[4] >> 8) | (qn[4] << 24);
    r[5] = (qn[5] >> 8) | (qn[5] << 24);
    r[6] = (qn[6] >> 8) | (qn[6] << 24);
    r[7] = (qn[7] >> 8) | (qn[7] << 24);

    q[0] = qn[7] ^ r[7] ^ r[0] ^ rotr16(qn[0] ^ r[0]);
    q[1] = qn[0] ^ r[0] ^ qn[7] ^ r[7] ^ r[1] ^ rotr16(qn[1] ^ r[1]);
    q[2] = qn[1] ^ r[1] ^ r[2] ^ rotr16(qn[2] ^ r[2]);
    q[3] = qn[2] ^ r[2] ^ qn[7] ^ r[7] ^ r[3] ^ rotr16(qn[3] ^ r[3]);
    q[4] = qn[3] ^ r[3] ^ qn[7] ^ r[7] ^ r[4] ^ rotr16(qn[4] ^ r[4]);
    q[5] = qn[4] ^ r[4] ^ r[5] ^ rotr16(qn[5] ^ r[5]);
    q[6] = qn[5] ^ r[5] ^ r[6] ^ rotr16(qn[6] ^ r[6]);
    q[7] = qn[6] ^ r[6] ^ r[7] ^ rotr16(qn[7] ^ r[7]);

    heap_caps_free(qn);
    heap_caps_free(r);
}

static void br_aes_ct64_ortho(uint64_t* q)
{
#define SWAPN(cl, ch, s, x, y)                                                                     \
    do {                                                                                           \
        uint64_t a, b;                                                                             \
        a = (x);                                                                                   \
        b = (y);                                                                                   \
        (x) = (a & (uint64_t)(cl)) | ((b & (uint64_t)(cl)) << (s));                                \
        (y) = ((a & (uint64_t)(ch)) >> (s)) | (b & (uint64_t)(ch));                                \
    } while (0)

#define SWAP2(x, y) SWAPN(0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 1, x, y)
#define SWAP4(x, y) SWAPN(0x3333333333333333, 0xCCCCCCCCCCCCCCCC, 2, x, y)
#define SWAP8(x, y) SWAPN(0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 4, x, y)

    SWAP2(q[0], q[1]);
    SWAP2(q[2], q[3]);
    SWAP2(q[4], q[5]);
    SWAP2(q[6], q[7]);

    SWAP4(q[0], q[2]);
    SWAP4(q[1], q[3]);
    SWAP4(q[4], q[6]);
    SWAP4(q[5], q[7]);

    SWAP8(q[0], q[4]);
    SWAP8(q[1], q[5]);
    SWAP8(q[2], q[6]);
    SWAP8(q[3], q[7]);
}

static void br_aes_ct64_interleave_in(uint64_t* q0, uint64_t* q1, const uint32_t* w)
{
    uint64_t* x = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 4, MALLOC_CAP_DEFAULT);

    x[0] = w[0];
    x[1] = w[1];
    x[2] = w[2];
    x[3] = w[3];
    x[0] |= (x[0] << 16);
    x[1] |= (x[1] << 16);
    x[2] |= (x[2] << 16);
    x[3] |= (x[3] << 16);
    x[0] &= (uint64_t)0x0000FFFF0000FFFF;
    x[1] &= (uint64_t)0x0000FFFF0000FFFF;
    x[2] &= (uint64_t)0x0000FFFF0000FFFF;
    x[3] &= (uint64_t)0x0000FFFF0000FFFF;
    x[0] |= (x[0] << 8);
    x[1] |= (x[1] << 8);
    x[2] |= (x[2] << 8);
    x[3] |= (x[3] << 8);
    x[0] &= (uint64_t)0x00FF00FF00FF00FF;
    x[1] &= (uint64_t)0x00FF00FF00FF00FF;
    x[2] &= (uint64_t)0x00FF00FF00FF00FF;
    x[3] &= (uint64_t)0x00FF00FF00FF00FF;
    *q0 = x[0] | (x[2] << 8);
    *q1 = x[1] | (x[3] << 8);

    heap_caps_free(x);
}

static void br_aes_ct64_interleave_out(uint32_t* w, uint64_t q0, uint64_t q1)
{
    uint64_t* x = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 4, MALLOC_CAP_DEFAULT);

    x[0] = q0 & (uint64_t)0x00FF00FF00FF00FF;
    x[1] = q1 & (uint64_t)0x00FF00FF00FF00FF;
    x[2] = (q0 >> 8) & (uint64_t)0x00FF00FF00FF00FF;
    x[3] = (q1 >> 8) & (uint64_t)0x00FF00FF00FF00FF;
    x[0] |= (x[0] >> 8);
    x[1] |= (x[1] >> 8);
    x[2] |= (x[2] >> 8);
    x[3] |= (x[3] >> 8);
    x[0] &= (uint64_t)0x0000FFFF0000FFFF;
    x[1] &= (uint64_t)0x0000FFFF0000FFFF;
    x[2] &= (uint64_t)0x0000FFFF0000FFFF;
    x[3] &= (uint64_t)0x0000FFFF0000FFFF;
    w[0] = (uint32_t)x[0] | (uint32_t)(x[0] >> 16);
    w[1] = (uint32_t)x[1] | (uint32_t)(x[1] >> 16);
    w[2] = (uint32_t)x[2] | (uint32_t)(x[2] >> 16);
    w[3] = (uint32_t)x[3] | (uint32_t)(x[3] >> 16);

    heap_caps_free(x);
}

static inline void add_round_key(uint64_t* q, const uint64_t* sk)
{
    q[0] ^= sk[0];
    q[1] ^= sk[1];
    q[2] ^= sk[2];
    q[3] ^= sk[3];
    q[4] ^= sk[4];
    q[5] ^= sk[5];
    q[6] ^= sk[6];
    q[7] ^= sk[7];
}

static inline void shift_rows(uint64_t* q)
{
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t x;

        x = q[i];
        q[i] = (x & (uint64_t)0x000000000000FFFF) | ((x & (uint64_t)0x00000000FFF00000) >> 4)
            | ((x & (uint64_t)0x00000000000F0000) << 12) | ((x & (uint64_t)0x0000FF0000000000) >> 8)
            | ((x & (uint64_t)0x000000FF00000000) << 8) | ((x & (uint64_t)0xF000000000000000) >> 12)
            | ((x & (uint64_t)0x0FFF000000000000) << 4);
    }
}

static inline uint64_t rotr32(uint64_t x)
{
    return (x << 32) | (x >> 32);
}

static inline void mix_columns(uint64_t* q)
{
    uint64_t* qn = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);
    uint64_t* r = (uint64_t*)heap_caps_malloc(sizeof(uint64_t) * 8, MALLOC_CAP_DEFAULT);

    qn[0] = q[0];
    qn[1] = q[1];
    qn[2] = q[2];
    qn[3] = q[3];
    qn[4] = q[4];
    qn[5] = q[5];
    qn[6] = q[6];
    qn[7] = q[7];
    r[0] = (qn[0] >> 16) | (qn[0] << 48);
    r[1] = (qn[1] >> 16) | (qn[1] << 48);
    r[2] = (qn[2] >> 16) | (qn[2] << 48);
    r[3] = (qn[3] >> 16) | (qn[3] << 48);
    r[4] = (qn[4] >> 16) | (qn[4] << 48);
    r[5] = (qn[5] >> 16) | (qn[5] << 48);
    r[6] = (qn[6] >> 16) | (qn[6] << 48);
    r[7] = (qn[7] >> 16) | (qn[7] << 48);

    q[0] = qn[7] ^ r[7] ^ r[0] ^ rotr32(qn[0] ^ r[0]);
    q[1] = qn[0] ^ r[0] ^ qn[7] ^ r[7] ^ r[1] ^ rotr32(qn[1] ^ r[1]);
    q[2] = qn[1] ^ r[1] ^ r[2] ^ rotr32(qn[2] ^ r[2]);
    q[3] = qn[2] ^ r[2] ^ qn[7] ^ r[7] ^ r[3] ^ rotr32(qn[3] ^ r[3]);
    q[4] = qn[3] ^ r[3] ^ qn[7] ^ r[7] ^ r[4] ^ rotr32(qn[4] ^ r[4]);
    q[5] = qn[4] ^ r[4] ^ r[5] ^ rotr32(qn[5] ^ r[5]);
    q[6] = qn[5] ^ r[5] ^ r[6] ^ rotr32(qn[6] ^ r[6]);
    q[7] = qn[6] ^ r[6] ^ r[7] ^ rotr32(qn[7] ^ r[7]);

    heap_caps_free(qn);
    heap_caps_free(r);
}

static void interleave_constant(uint64_t* out, const uint8_t* in)
{
    uint32_t* tmp_32_constant =
        (uint32_t*)heap_caps_malloc((sizeof(uint32_t) * (16)), MALLOC_CAP_DEFAULT);
    int i;

    br_range_dec32le(tmp_32_constant, 16, in);
    for (i = 0; i < 4; i++) {
        br_aes_ct64_interleave_in(&out[i], &out[i + 4], tmp_32_constant + (i << 2));
    }
    br_aes_ct64_ortho(out);
    heap_caps_free(tmp_32_constant);
}

static void interleave_constant32(uint32_t* out, const uint8_t* in)
{
    int i;
    for (i = 0; i < 4; i++) {
        out[2 * i] = br_dec32le(in + 4 * i);
        out[2 * i + 1] = br_dec32le(in + 4 * i + 16);
    }
    br_aes_ct_ortho(out);
}

void tweak_constants(spx_ctx* ctx)
{
    uint8_t* buf = (uint8_t*)heap_caps_malloc((sizeof(uint8_t) * (40 * 16)), MALLOC_CAP_DEFAULT);
    int i;

    /* Use the standard constants to generate tweaked ones. */
    memcpy((uint8_t*)ctx->tweaked512_rc64, (uint8_t*)haraka512_rc64, 40 * 16);

    /* Constants for pk.seed */
    haraka_S(buf, 40 * 16, ctx->pub_seed, SPX_N, ctx);
    for (i = 0; i < 10; i++) {
        interleave_constant32(ctx->tweaked256_rc32[i], buf + 32 * i);
        interleave_constant(ctx->tweaked512_rc64[i], buf + 64 * i);
    }
    heap_caps_free(buf);
}

static void haraka_S_absorb(uint8_t* s, unsigned int r, const uint8_t* m, unsigned long long mlen,
                            uint8_t p, const spx_ctx* ctx)
{
    unsigned long long i;
    PQCLEAN_VLA(uint8_t, t, r);

    while (mlen >= r) {
        /* XOR block to state */
        for (i = 0; i < r; ++i) {
            s[i] ^= m[i];
        }
        haraka512_perm(s, s, ctx);
        mlen -= r;
        m += r;
    }

    for (i = 0; i < r; ++i) {
        t[i] = 0;
    }
    for (i = 0; i < mlen; ++i) {
        t[i] = m[i];
    }
    t[i] = p;
    t[r - 1] |= 128;
    for (i = 0; i < r; ++i) {
        s[i] ^= t[i];
    }
}

static void haraka_S_squeezeblocks(uint8_t* h, unsigned long long nblocks, uint8_t* s,
                                   unsigned int r, const spx_ctx* ctx)
{
    while (nblocks > 0) {
        haraka512_perm(s, s, ctx);
        memcpy(h, s, HARAKAS_RATE);
        h += r;
        nblocks--;
    }
}

void haraka_S_inc_init(uint8_t* s_inc)
{
    size_t i;

    for (i = 0; i < 64; i++) {
        s_inc[i] = 0;
    }
    s_inc[64] = 0;
}

void haraka_S_inc_absorb(uint8_t* s_inc, const uint8_t* m, size_t mlen, const spx_ctx* ctx)
{
    size_t i;

    /* Recall that s_inc[64] is the non-absorbed bytes xored into the state */
    while (mlen + s_inc[64] >= HARAKAS_RATE) {
        for (i = 0; i < (size_t)(HARAKAS_RATE - s_inc[64]); i++) {
            /* Take the i'th byte from message
               xor with the s_inc[64] + i'th byte of the state */
            s_inc[s_inc[64] + i] ^= m[i];
        }
        mlen -= (size_t)(HARAKAS_RATE - s_inc[64]);
        m += HARAKAS_RATE - (uint8_t)s_inc[64];
        s_inc[64] = 0;

        haraka512_perm(s_inc, s_inc, ctx);
    }

    for (i = 0; i < mlen; i++) {
        s_inc[s_inc[64] + i] ^= m[i];
    }
    s_inc[64] += (uint8_t)mlen;
}

void haraka_S_inc_finalize(uint8_t* s_inc)
{
    /* After haraka_S_inc_absorb, we are guaranteed that s_inc[64] < HARAKAS_RATE,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[64]] ^= 0x1F;
    s_inc[HARAKAS_RATE - 1] ^= 128;
    s_inc[64] = 0;
}

void haraka_S_inc_squeeze(uint8_t* out, size_t outlen, uint8_t* s_inc, const spx_ctx* ctx)
{
    size_t i;

    /* First consume any bytes we still have sitting around */
    for (i = 0; i < outlen && i < s_inc[64]; i++) {
        /* There are s_inc[64] bytes left, so r - s_inc[64] is the first
           available byte. We consume from there, i.e., up to r. */
        out[i] = (uint8_t)s_inc[(HARAKAS_RATE - s_inc[64] + i)];
    }
    out += i;
    outlen -= i;
    s_inc[64] -= (uint8_t)i;

    /* Then squeeze the remaining necessary blocks */
    while (outlen > 0) {
        haraka512_perm(s_inc, s_inc, ctx);

        for (i = 0; i < outlen && i < HARAKAS_RATE; i++) {
            out[i] = s_inc[i];
        }
        out += i;
        outlen -= i;
        s_inc[64] = (uint8_t)(HARAKAS_RATE - i);
    }
}

void haraka_S(uint8_t* out, unsigned long long outlen, const uint8_t* in, unsigned long long inlen,
              const spx_ctx* ctx)
{
    unsigned long long i;
    uint8_t* s = (uint8_t*)heap_caps_malloc((sizeof(uint8_t) * (64)), MALLOC_CAP_DEFAULT);
    uint8_t* d = (uint8_t*)heap_caps_malloc((sizeof(uint8_t) * (32)), MALLOC_CAP_DEFAULT);

    for (i = 0; i < 64; i++) {
        s[i] = 0;
    }
    haraka_S_absorb(s, 32, in, inlen, 0x1F, ctx);

    haraka_S_squeezeblocks(out, outlen / 32, s, 32, ctx);
    out += (outlen / 32) * 32;

    if (outlen % 32) {
        haraka_S_squeezeblocks(d, 1, s, 32, ctx);
        for (i = 0; i < outlen % 32; i++) {
            out[i] = d[i];
        }
    }
    heap_caps_free(s);
    heap_caps_free(d);
}

void haraka512_perm(uint8_t* out, const uint8_t* in, const spx_ctx* ctx)
{
    uint32_t* w = (uint32_t*)heap_caps_malloc((sizeof(uint32_t) * (16)), MALLOC_CAP_DEFAULT);
    uint64_t* q = (uint64_t*)heap_caps_malloc((sizeof(uint64_t) * (16)), MALLOC_CAP_DEFAULT);

    uint64_t tmp_q;
    unsigned int i, j;

    br_range_dec32le(w, 16, in);
    for (i = 0; i < 4; i++) {
        br_aes_ct64_interleave_in(&(q[i]), &(q[i + 4]), w + (i << 2));
    }
    br_aes_ct64_ortho(q);

    /* AES rounds */
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 2; j++) {
            br_aes_ct64_bitslice_Sbox(q);
            shift_rows(q);
            mix_columns(q);
            add_round_key(q, ctx->tweaked512_rc64[2 * i + j]);
        }
        /* Mix states */
        for (j = 0; j < 8; j++) {
            tmp_q = q[j];
            q[j] = (tmp_q & 0x0001000100010001) << 5 | (tmp_q & 0x0002000200020002) << 12
                | (tmp_q & 0x0004000400040004) >> 1 | (tmp_q & 0x0008000800080008) << 6
                | (tmp_q & 0x0020002000200020) << 9 | (tmp_q & 0x0040004000400040) >> 4
                | (tmp_q & 0x0080008000800080) << 3 | (tmp_q & 0x2100210021002100) >> 5
                | (tmp_q & 0x0210021002100210) << 2 | (tmp_q & 0x0800080008000800) << 4
                | (tmp_q & 0x1000100010001000) >> 12 | (tmp_q & 0x4000400040004000) >> 10
                | (tmp_q & 0x8400840084008400) >> 3;
        }
    }

    br_aes_ct64_ortho(q);
    for (i = 0; i < 4; i++) {
        br_aes_ct64_interleave_out(w + (i << 2), q[i], q[i + 4]);
    }
    br_range_enc32le(out, w, 16);
    heap_caps_free(w);
    heap_caps_free(q);
}

void haraka512(uint8_t* out, const uint8_t* in, const spx_ctx* ctx)
{
    int i;

    uint8_t* buf = (uint8_t*)heap_caps_malloc((sizeof(uint8_t) * (64)), MALLOC_CAP_DEFAULT);

    haraka512_perm(buf, in, ctx);
    /* Feed-forward */
    for (i = 0; i < 64; i++) {
        buf[i] = buf[i] ^ in[i];
    }

    /* Truncated */
    memcpy(out, buf + 8, 8);
    memcpy(out + 8, buf + 24, 8);
    memcpy(out + 16, buf + 32, 8);
    memcpy(out + 24, buf + 48, 8);
    heap_caps_free(buf);
}

void haraka256(uint8_t* out, const uint8_t* in, const spx_ctx* ctx)
{
    uint32_t q[8], tmp_q;
    int i, j;

    for (i = 0; i < 4; i++) {
        q[2 * i] = br_dec32le(in + 4 * i);
        q[2 * i + 1] = br_dec32le(in + 4 * i + 16);
    }
    br_aes_ct_ortho(q);

    /* AES rounds */
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 2; j++) {
            br_aes_ct_bitslice_Sbox(q);
            shift_rows32(q);
            mix_columns32(q);
            add_round_key32(q, ctx->tweaked256_rc32[2 * i + j]);
        }

        /* Mix states */
        for (j = 0; j < 8; j++) {
            tmp_q = q[j];
            q[j] = (tmp_q & 0x81818181) | (tmp_q & 0x02020202) << 1 | (tmp_q & 0x04040404) << 2
                | (tmp_q & 0x08080808) << 3 | (tmp_q & 0x10101010) >> 3 | (tmp_q & 0x20202020) >> 2
                | (tmp_q & 0x40404040) >> 1;
        }
    }

    br_aes_ct_ortho(q);
    for (i = 0; i < 4; i++) {
        br_enc32le(out + 4 * i, q[2 * i]);
        br_enc32le(out + 4 * i + 16, q[2 * i + 1]);
    }

    for (i = 0; i < 32; i++) {
        out[i] ^= in[i];
    }
}
