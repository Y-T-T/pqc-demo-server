#ifndef PARAM_H
#define PARAM_H

#include <tls/rsa_pss_rsae_sha_t.h>

#define PROXY_PORT 80
#define SERVER_PORT 8080
#define BUFFER_SIZE USHRT_MAX
#define TAG_SIZE 16
#define SPLIT_STR "\r\n\r\n"

#define AES_KEY_LENGTH_256 32
#define GCM_IV_LENGTH 12

#define SS_LEN 64
#define ZERO_STR "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

#define SIGN_ALG ALG_SHA256
#define CRT_SIZE 0xFFFFFF
#define SIGN_SIZE 0xFFFFFF

#endif