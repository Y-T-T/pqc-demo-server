#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <base/base.h>
#include <base/param.h>
#include <kyber/params.h>

typedef struct X25519
{
    u8 pkey[X25519_KEY_LENGTH];
    u8 skey[X25519_KEY_LENGTH];
} X25519;

typedef struct KYBER768
{
    u8 pkey[KYBER_PUBLICKEYBYTES];
    u8 ct[KYBER_CIPHERTEXTBYTES];
    u8 ss[KYBER_SSBYTES];
    u8 skey[KYBER_INDCPA_SECRETKEYBYTES];
} KYBER768;


typedef struct X25519_KYBER768_DRAFT00
{
    X25519 x25519;
    KYBER768 kyber768;
} X25519_KYBER768_DRAFT00;

typedef struct SESSION_ID
{
    u8 length[1];
    u8 id[32];
} SESSION_ID;

typedef struct SESSION_TICKET
{
    int valid;
    u8 handshake_header[4];
    u8 ticket_lifetime[4];
    u8 ticket_age_add[4];
    u8 ticket_nonce[9];
    u8 *ticket;
    size_t ticket_len;
    u8 extensions[2];
} SESSION_TICKET;

typedef struct SUPPORTED_VERSIONS
{
    u8 header[2];
    u8 length[2];
    u8 *versions;
}SUPPORTED_VERSIONS;

typedef struct KEY_SHARE
{
    u8 header[2];
    u8 record_length[2];
    u8 keys_length[2];
    u8 key_change_method[2];
    u8 key_len[2];
    X25519_KYBER768_DRAFT00 key;
} KEY_SHARE;

typedef struct PSK
{
    u8 type[2];
    u8 record_length[2];
    u8 identities_len[2];
    u8 identity_len[2];
    u8 *identity;
    u8 ticket_age[4];
    u8 psk_binders_len[2];
    u8 *psk_binders;
} PSK;


typedef struct EXTENSIONS
{
    SESSION_TICKET session_ticket;
    SUPPORTED_VERSIONS supported_versions;
    KEY_SHARE key_share;
    PSK pre_share_key;
} EXTENSIONS;

typedef struct TRANSCRIPT_HASH_MSG
{
    u8 *msg;
    size_t msg_len;
    u8 *hash;
    size_t hash_len;
} TRANSCRIPT_HASH_MSG;

typedef struct SERVER_HELLO_MSG // for server response
{
    u8 *hello_msg;
    size_t hello_msg_len;
    u8 change_cipher_spec[6];
    size_t change_cipher_spec_len;
    u8 *extensions;
    size_t extensions_len;
    u8 *cert;
    size_t cert_len;
    u8 *cert_verify;
    size_t cert_verify_len;
    u8 *finished;
    size_t finished_len;
    u8 *all_msg;
    size_t all_msg_len;
} SERVER_HELLO_MSG;


typedef struct HANDSHAKE_HELLO_MSG_CTX
{
    u8 record_header[5];
    u8 handshake_header[4];
    u8 tls_version[2];
    u8 random[32];
    SESSION_ID session_id;
    u8 *cipher_suites;
    u8 compression_method[1];
    u8 extensions_length[2];
    EXTENSIONS extensions;
} HANDSHAKE_HELLO_MSG_CTX;

typedef struct TLS13_KEY_EXCHANGE_CTX
{
    u8 *shared_secret;
    u8 *handshake_secret; // SHA384_DIGEST_LENGTH
    u8 *server_handshake_traffic_secret; // SHA384_DIGEST_LENGTH
    u8 *client_handshake_traffic_secret; // SHA384_DIGEST_LENGTH
    u8 *server_handshake_key; // AES_KEY_LENGTH_256
    u8 *client_handshake_key; // AES_KEY_LENGTH_256
    u8 *server_handshake_iv; // GCM_IV_LENGTH
    uint64_t s_hs_seq;
    u8 *client_handshake_iv; // GCM_IV_LENGTH
    uint64_t c_hs_seq;
    u8 *server_master_key; // AES_KEY_LENGTH_256
    u8 *client_master_key; // AES_KEY_LENGTH_256
    u8 *server_master_iv; // GCM_IV_LENGTH
    uint64_t s_ap_seq;
    u8 *client_master_iv; // GCM_IV_LENGTH
    uint64_t c_ap_seq;
} TLS13_KEY_EXCHANGE_CTX;

typedef struct SESSION_POOL
{
    TLS13_KEY_EXCHANGE_CTX *key_ctx;
    SESSION_TICKET session_ticket;
} SESSION_POOL;

void parse_client_hello(u8 *, ssize_t, HANDSHAKE_HELLO_MSG_CTX *);
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