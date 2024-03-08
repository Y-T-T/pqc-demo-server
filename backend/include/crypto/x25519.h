#ifndef X25519_H
#define X25519_H

#include <base/base.h>

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int x25519_keygen(uchar *priv_key, uchar *pub_key);
int curve25519_donna(u8 *, const u8 *, const u8 *);

#endif