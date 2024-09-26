#ifndef CRYPTO_METH_H
#define CRYPTO_METH_H

#include <base/types.h>

u8 * build_iv(u8 *iv, uint64_t *seq);
u8 * build_nonce(u8 *record_iv, uint64_t *seq);
int evp_enc_init(EVP_CIPHER_CTX **ctx, u8 key[EVP_MAX_KEY_LENGTH], u8 iv[EVP_MAX_IV_LENGTH]);
int evp_dec_init(EVP_CIPHER_CTX **ctx, u8 key[EVP_MAX_KEY_LENGTH], u8 iv[EVP_MAX_IV_LENGTH]);
int enc_update(EVP_CIPHER_CTX *ctx, u8 *plaintext, int pt_len, u8 *ciphertext, int *ciphertext_len, int *outlen);
int dec_update(EVP_CIPHER_CTX *ctx, u8 *ciphertext, int ciphertext_len, u8 *plaintext, int *plaintext_len, int *outlen);
int complete_enc(EVP_CIPHER_CTX **ctx, u8 *ciphertext, int *ciphertext_len, int *outlen, u8 *tag);
int complete_dec(EVP_CIPHER_CTX **ctx, u8 *plaintext, int *plaintext_len, int *outlen, u8 *tag);

#endif