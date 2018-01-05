#ifndef CIA_AES_H
#define CIA_AES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t round_key[176];
} aes128_ctx;

void aes128_init(aes128_ctx *ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
void aes128_cbc_decrypt(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);
void aes128_ctr_xcrypt(const uint8_t key[16], uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t len);
void aes128_ctr_advance(uint8_t ctr[16], uint64_t blocks);

int aes_self_test(void);

#endif
