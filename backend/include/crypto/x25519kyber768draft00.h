#ifndef X25519_KYBER768_DRAFT00_H
#define X25519_KYBER768_DRAFT00_H

#include <base/base.h>
#include <tls/handshake.h>

void X25519_KYBER768_KEYGEN(const HANDSHAKE_HELLO_MSG_CTX client, HANDSHAKE_HELLO_MSG_CTX *server);
void build_server_hello(SERVER_HELLO_MSG *hello_msg, const HANDSHAKE_HELLO_MSG_CTX client, HANDSHAKE_HELLO_MSG_CTX *server);

#endif