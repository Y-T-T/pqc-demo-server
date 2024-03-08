#ifndef RSA_PKCS1_SHA384_H
#define RSA_PKCS1_SHA384_H

#include <base/base.h>

uchar * sign_msg(const uchar *msg, const uint32_t msg_len, uint32_t *outlen);
int verify_msg(const uchar *msg, const size_t msg_len, const uchar *sig, const uint32_t siglen);

#endif