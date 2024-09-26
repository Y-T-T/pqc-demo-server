#ifndef TLS13_HKDF_EXPAND_H
#define TLS13_HKDF_EXPAND_H

#include <base/types.h>

u8 * sha_t(const u8 *message, const size_t message_len);
// u8 * sha256(const u8 *message, const size_t message_len);
// u8 * sha384(const u8 *message, const size_t message_len);
u8 * hmac_sha_t(const u8 *key, const size_t key_len, const u8 *data, const size_t data_len);
// u8 * hmac_sha384(const u8 *key, const size_t key_len, const u8 *data, const size_t data_len);
u8 * hkdf_extract(const u8 *salt, const size_t salt_len, const u8 *ikm,const size_t key_len);
u8 * derive_secret(const u8 *ss, const size_t ss_len, const char *label, const u8 *msg,  const uint16_t context_len, const uint16_t out_len);

#endif