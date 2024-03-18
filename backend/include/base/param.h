#ifndef PARAM_H
#define PARAM_H

#include <crypto/openssl_base.h>

#define SERVER_ADDR "127.0.0.1"
#define PROXY_PORT 443
#define SERVER_PORT 8080
#define BUFFER_SIZE 5000 // 0x3e80 // Maximum TLS record size is 16 KB (16384 bytes), 0x3e80 = 16000 
#define TAG_SIZE 16
#define SPLIT_STR "\r\n\r\n"

#define AES_KEY_LENGTH_256 32
#define GCM_IV_LENGTH 12
#define X25519_KEY_LENGTH 32

#define SS_LEN 64
#define ZERO_STR "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

#define ALG_SHA256 EVP_sha256()
#define ALG_SHA384 EVP_sha384()

#define SIGN_ALG ALG_SHA256
#define CRT_SIZE 0xFFFFFF
#define SIGN_SIZE 0xFFFFFF

#define TICKET_SIZE 0xC0
#define MAX_POOL_SIZE 100
#define TLS_RECORDER_HEADER_LENGTH 5
#define MAX_POOL_BUFFER_SIZE BUFFER_SIZE + TLS_RECORDER_HEADER_LENGTH + 1 + TAG_SIZE
#define MAX_PRINT_BYTES 3000

#define TLS_END_START_DATA_EXCHANGE "\nTLS handshake ends.\n==============================\nStart data exchange.\n==============================\n\n"

#define MAX_KEEP_ALIVE_CONN_TIMES 100
#define KEEP_ALIVE_TIMEOUT 10

#endif