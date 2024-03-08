#ifndef AES_256_GCM_H
#define AES_256_GCM_H

#include <base/base.h>
#include <crypto/openssl_base.h>

uchar * build_iv(uchar *iv, uint64_t *seq);
int evp_enc_init(EVP_CIPHER_CTX **ctx, uchar key[EVP_MAX_KEY_LENGTH], uchar iv[EVP_MAX_IV_LENGTH]);
int evp_dec_init(EVP_CIPHER_CTX **ctx, uchar key[EVP_MAX_KEY_LENGTH], uchar iv[EVP_MAX_IV_LENGTH]);
int enc_update(EVP_CIPHER_CTX *ctx, uchar *plaintext, int pt_len, uchar *ciphertext, int *ciphertext_len, int *outlen);
int dec_update(EVP_CIPHER_CTX *ctx, uchar *ciphertext, int ciphertext_len, uchar *plaintext, int *plaintext_len, int *outlen);
int complete_enc(EVP_CIPHER_CTX **ctx, uchar *ciphertext, int *ciphertext_len, int *outlen, uchar *tag);
int complete_dec(EVP_CIPHER_CTX **ctx, uchar *plaintext, int *plaintext_len, int *outlen, uchar *tag);

#endif