#include "symmetric.h"

void aes256Encrypt(const uint8_t* in, const size_t inLen, uint8_t* out, const uint8_t iv[IV_LENGTH],
                   const uint8_t* key, const size_t keyLen)
{
    // debugBoth("[D] inLen before", inLen);
    // debugBoth("[D] in[0] before", in[0]);
    // debugBoth("[D] in[1] before", in[1]);
    // debugBoth("[D] in[2] before", in[2]);
    // debugBoth("[D] in[3] before", in[3]);

    size_t ivOffset = 0;
    uint8_t tempIV[IV_LENGTH];
    memcpy(tempIV, iv, IV_LENGTH);

    esp_aes_context ctx;
    esp_aes_init(&ctx);
    esp_aes_setkey(&ctx, key, keyLen * 8);
    esp_aes_crypt_ofb(&ctx, inLen, &ivOffset, tempIV, in, out);

    // debugBoth("[D] out[0] after", out[0]);
    // debugBoth("[D] out[1] after", out[1]);
    // debugBoth("[D] out[2] after", out[2]);
    // debugBoth("[D] out[3] after", out[3]);
    esp_aes_free(&ctx);
}

void aes256Decrypt(const uint8_t* in, const size_t inLen, uint8_t* out, const uint8_t iv[IV_LENGTH],
                   const uint8_t* key, const size_t keyLen)
{
    // debugBoth("[D] inLen before", inLen);
    // debugBoth("[D] in[0] before", in[0]);
    // debugBoth("[D] in[1] before", in[1]);
    // debugBoth("[D] in[2] before", in[2]);
    // debugBoth("[D] in[3] before", in[3]);

    size_t ivOffset = 0;
    uint8_t tempIV[IV_LENGTH];
    memcpy(tempIV, iv, IV_LENGTH);

    esp_aes_context ctx;
    esp_aes_init(&ctx);
    esp_aes_setkey(&ctx, key, keyLen * 8);
    esp_aes_crypt_ofb(&ctx, inLen, &ivOffset, tempIV, in, out);

    // debugBoth("out[0] after", out[0]);
    // debugBoth("out[1] after", out[1]);
    // debugBoth("out[2] after", out[2]);
    // debugBoth("out[3] after", out[3]);

    esp_aes_free(&ctx);
}

void derivateKey(uint8_t* out, const size_t outLen, const uint8_t* in, const size_t inLen)
{
    // time how much it takes to compute pbkdf2
    // unsigned long time = millis();
    PBKDF2_SHA256(in, inLen, globalSalt, SALT_LENGTH, 500, out, outLen);
    // debugBoth("[I] PBKDF2 took [ms]", millis() - time);
}