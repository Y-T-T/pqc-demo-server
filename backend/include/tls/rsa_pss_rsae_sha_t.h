#ifndef RSA_PSS_RSAE_SHA_T_H
#define RSA_PSS_RSAE_SHA_T_H


#include <base/types.h>

u8 * sign_msg(const u8 *msg, const uint32_t msg_len, const EVP_MD *alg, size_t *outlen);
int verify_msg(const u8 *msg, const size_t msg_len, const EVP_MD *alg, const u8 *sig, const size_t siglen);

#endif