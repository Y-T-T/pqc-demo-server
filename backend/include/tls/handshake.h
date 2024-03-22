#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <base/types.h>

size_t parse_client_hello(u8 *, ssize_t, HANDSHAKE_HELLO_MSG_CTX *);
void update_transcript_hash_msg(TRANSCRIPT_HASH_MSG *, u8 *msg, size_t msg_len);
int check_session_ticket(HANDSHAKE_HELLO_MSG_CTX *client_hello, const SESSION_POOL **pool, const size_t pool_len);
void add_change_cipher_spec(SERVER_HELLO_MSG *);
void TLS13_KEY_EXCHANGE_CTX_INIT(TLS13_KEY_EXCHANGE_CTX *);
u8 * calc_ss(const HANDSHAKE_HELLO_MSG_CTX client, const HANDSHAKE_HELLO_MSG_CTX server);
void handshake_key_calc(const u8 *hello_hash, TLS13_KEY_EXCHANGE_CTX *);
void enc_server_ext(SERVER_HELLO_MSG *, TLS13_KEY_EXCHANGE_CTX *, TRANSCRIPT_HASH_MSG *);
void enc_server_cert(SERVER_HELLO_MSG *, TLS13_KEY_EXCHANGE_CTX *, TRANSCRIPT_HASH_MSG *);
void enc_server_cert_verify(SERVER_HELLO_MSG *, TLS13_KEY_EXCHANGE_CTX *, TRANSCRIPT_HASH_MSG *);
void enc_server_handshake_finished(SERVER_HELLO_MSG *, TLS13_KEY_EXCHANGE_CTX *, TRANSCRIPT_HASH_MSG *);
void master_key_calc(TLS13_KEY_EXCHANGE_CTX *, const TRANSCRIPT_HASH_MSG);
int verify_client_finished(u8 *, size_t, TLS13_KEY_EXCHANGE_CTX *, const TRANSCRIPT_HASH_MSG);
u8 * generate_session_ticket(TLS13_KEY_EXCHANGE_CTX *key_ctx, SESSION_POOL *pool, size_t *pool_len, size_t *outlen);
void TRANSCRIPT_HASH_MSG_FREE(TRANSCRIPT_HASH_MSG *);
void SERVER_HELLO_MSG_FREE(SERVER_HELLO_MSG *);
void HANDSHAKE_HELLO_MSG_CTX_FREE(HANDSHAKE_HELLO_MSG_CTX *);
void TLS13_KEY_EXCHANGE_CTX_FREE(TLS13_KEY_EXCHANGE_CTX *);
void SESSION_POOL_FREE(SESSION_POOL *, size_t);
#endif