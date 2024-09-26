#ifndef PARAM_H
#define PARAM_H

#include <crypto/openssl_base.h>

#define SERVER_ADDR "127.0.0.1"
#define PROXY_PORT 443
#define SERVER_PORT 8080
#define BUFFER_SIZE 5000 // 0x3e80 // Maximum TLS record size is 16 KB (16384 bytes), 0x3e80 = 16000 
#define TAG_SIZE 16
#define SPLIT_STR "\r\n\r\n"

#define AES_256_KEY_LENGTH 32
#define CHACHA20_KEY_LENGTH 32
#define GCM_IV_LENGTH 12
#define CHACHA20_NONCE_LENGTH 12
#define X25519_KEY_LENGTH 32

#define SS_LEN 64

#define ALG_SHA256 EVP_sha256()
#define ALG_SHA384 EVP_sha384()

#define TLS_AES_256_GCM_SHA_384 2
#define TLS_CHACHA_20_POLY_1305_SHA_256 3

#define BUILD_RAND(s) build_##s

#define CIPHER_SUITE TLS_AES_256_GCM_SHA_384
// #define CIPHER_SUITE TLS_CHACHA_20_POLY_1305_SHA_256

#if CIPHER_SUITE == TLS_AES_256_GCM_SHA_384
    #define TLS_CIPHER_SUITE EVP_aes_256_gcm
    #define TLS_CIPHER_SUITE_ID {0x13, 0x02}
    #define _SHA_FUNCTION EVP_sha384
    #define _SHA_DIGEST_LENGTH SHA384_DIGEST_LENGTH
    #define _KEY_LENGTH AES_256_KEY_LENGTH
    #define _NONCE_LENGTH GCM_IV_LENGTH
    #define GEN_IV BUILD_RAND(nonce)
    #define COUNTER_INIT 0
#elif CIPHER_SUITE == TLS_CHACHA_20_POLY_1305_SHA_256
    #define TLS_CIPHER_SUITE EVP_chacha20_poly1305
    #define TLS_CIPHER_SUITE_ID {0x13, 0x03}
    #define _SHA_FUNCTION EVP_sha256
    #define _SHA_DIGEST_LENGTH SHA256_DIGEST_LENGTH
    #define _KEY_LENGTH CHACHA20_KEY_LENGTH
    #define _NONCE_LENGTH CHACHA20_NONCE_LENGTH
    #define GEN_IV BUILD_RAND(nonce)
    #define COUNTER_INIT 0
#else
    #define TLS_CIPHER_SUITE EVP_aes_256_gcm
    #define TLS_CIPHER_SUITE_ID {0x13, 0x02}
    #define _SHA_FUNCTION EVP_sha384
    #define _SHA_DIGEST_LENGTH SHA384_DIGEST_LENGTH
    #define _KEY_LENGTH AES_256_KEY_LENGTH
    #define _NONCE_LENGTH GCM_IV_LENGTH
    #define GEN_IV BUILD_RAND(nonce)
    #define COUNTER_INIT 0
    #error "Unsupported TLS_CIPHER_SUITE, reset to default: TLS_AES_256_GCM_SHA384"
#endif

#define SIGN_ALG ALG_SHA256
#define CRT_SIZE 0xFFFFFF
#define SIGN_SIZE 0xFFFFFF

#define TICKET_SIZE 0xC0
#define MAX_POOL_SIZE 100
#define TLS_RECORDER_HEADER_LENGTH 5
#define MAX_POOL_BUFFER_SIZE BUFFER_SIZE + TLS_RECORDER_HEADER_LENGTH + 1 + TAG_SIZE
#define MAX_PRINT_BYTES 1000

#define TLS_END_START_DATA_EXCHANGE "\nTLS handshake ends.\n==============================\nStart data exchange.\n==============================\n\n"

#define MAX_KEEP_ALIVE_CONN_TIMES 100
#define KEEP_ALIVE_TIMEOUT 10

#endif