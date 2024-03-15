#ifndef TLS13_ENC_DEC_H
#define TLS13_ENC_DEC_H

#include <base/types.h>

size_t server_msg_enc(BUFFER_POOL *pool, const size_t pool_idx, TLS13_KEY_EXCHANGE_CTX *key_ctx);
size_t client_msg_dec(BUFFER_POOL *pool, const size_t pool_idx, TLS13_KEY_EXCHANGE_CTX *key_ctx);

#endif