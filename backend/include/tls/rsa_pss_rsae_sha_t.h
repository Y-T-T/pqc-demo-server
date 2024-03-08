#ifndef RSA_PSS_RSAE_SHA_T_H
#define RSA_PSS_RSAE_SHA_T_H


#include <base/base.h>
#include <crypto/openssl_base.h>

#define ALG_SHA256 EVP_sha256()
#define ALG_SHA384 EVP_sha384()

uchar * sign_msg(const uchar *msg, const uint32_t msg_len, const EVP_MD *alg, size_t *outlen);
int verify_msg(const uchar *msg, const size_t msg_len, const EVP_MD *alg, const uchar *sig, const size_t siglen);

#endif