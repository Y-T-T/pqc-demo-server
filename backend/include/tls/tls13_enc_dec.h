#ifndef TLS13_ENC_DEC_H
#define TLS13_ENC_DEC_H

#include <base/base.h>
#include <tls/handshake.h>


size_t server_msg_enc(u8 *msg, size_t msg_len, TLS13_KEY_EXCHANGE_CTX *key_ctx, u8 *output);
size_t client_msg_dec(u8 *msg, size_t msg_len, TLS13_KEY_EXCHANGE_CTX *key_ctx, u8 *output);

#endif