#ifndef TLS13_HKDF_EXPAND_H
#define TLS13_HKDF_EXPAND_H

#include <base/base.h>

struct HkdfLabel
{
    uint16_t length;
    char label[256];
    uchar context[256];
};

uchar * sha256(const uchar *message, const size_t message_len);
uchar * sha384(const uchar *message, const size_t message_len);
uchar * hmac_sha384(const uchar *key, const size_t key_len, const uchar *data, const size_t data_len);
uchar * hkdf_extract(const uchar *salt, const size_t salt_len, const uchar *ikm,const size_t key_len);
uchar * derive_secret(const uchar *ss, const size_t ss_len, const char *label, const uchar *msg,  const uint16_t context_len, const uint16_t out_len);

#endif