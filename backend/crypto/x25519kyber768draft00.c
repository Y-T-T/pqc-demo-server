#include <crypto/x25519kyber768draft00.h>
#include <crypto/x25519.h>
#include <base/base.h>
#include <kyber/kem.h>
#include <base/serving.h>

void X25519_KYBER768_KEYGEN(const HANDSHAKE_HELLO_MSG_CTX client, HANDSHAKE_HELLO_MSG_CTX *server){
    /* X25519 */
    x25519_keygen(server);


    /* Kyber768 */
    crypto_kem_enc(
        server->extensions.key_share.key.kyber768.ct,
        server->extensions.key_share.key.kyber768.ss, 
        client.extensions.key_share.key.kyber768.pkey);
}

void build_server_hello(SERVER_HELLO_MSG *server_hello_msg, const HANDSHAKE_HELLO_MSG_CTX client, HANDSHAKE_HELLO_MSG_CTX *server){
    /* return server hello msg */

    server->cipher_suites = malloc(2 * sizeof(u8));
    server->extensions.session_ticket.ticket = NULL;
    server->extensions.supported_versions.versions = malloc(2 * sizeof(u8));
    server->extensions.pre_share_key.identity = NULL;
    server->extensions.pre_share_key.psk_binders = NULL;

    size_t len = 0;
    if(!client.extensions.session_ticket.valid){
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.key_share.key.x25519.pkey, X25519_KEY_LENGTH, 
            server->extensions.key_share.key.kyber768.ct, KYBER_CIPHERTEXTBYTES
        );
        len += X25519_KEY_LENGTH + KYBER_CIPHERTEXTBYTES;
        server_hello_msg->hello_msg_len = X25519_KEY_LENGTH + KYBER_CIPHERTEXTBYTES;

        insert_header_len(server->extensions.key_share.key_len, len, 0 ,1);
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.key_share.key_len, 2,
            server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
        );
        len += 2;
        server_hello_msg->hello_msg_len += 2;

        u8 x25519kyber768draft00_key_method[] = {0x63, 0x99};
        memcpy(server->extensions.key_share.key_change_method, x25519kyber768draft00_key_method, 2);
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.key_share.key_change_method, 2,
            server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
        );
        len += 2;
        server_hello_msg->hello_msg_len += 2;

        insert_header_len(server->extensions.key_share.record_length, len, 0 ,1);
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.key_share.record_length, 2,
            server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
        );
        len += 2;
        server_hello_msg->hello_msg_len += 2;

        u8 key_share_header[] = {0x00, 0x33};
        memcpy(server->extensions.key_share.header, key_share_header, 2);
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.key_share.header, 2,
            server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
        );
        len += 2;
        server_hello_msg->hello_msg_len += 2;
    }
    else {
        memcpy(server->extensions.pre_share_key.type, client.extensions.pre_share_key.type, 2);
        memcpy(server->extensions.pre_share_key.record_length, client.extensions.pre_share_key.record_length, 2);
        memcpy(server->extensions.pre_share_key.identities_len, client.extensions.pre_share_key.identities_len, 2);
        memcpy(server->extensions.pre_share_key.identity_len, client.extensions.pre_share_key.identity_len, 2);
        len = server->extensions.pre_share_key.identity_len[0] << 8 | server->extensions.pre_share_key.identity_len[1];
        server->extensions.pre_share_key.identity = malloc(len * sizeof(u8));
        memcpy(server->extensions.pre_share_key.identity, client.extensions.pre_share_key.identity, 2);
        memcpy(server->extensions.pre_share_key.ticket_age, client.extensions.pre_share_key.ticket_age, 4);
        memcpy(server->extensions.pre_share_key.psk_binders_len, client.extensions.pre_share_key.psk_binders_len, 2);
        len = server->extensions.pre_share_key.psk_binders_len[0] << 8 | server->extensions.pre_share_key.psk_binders_len[1];
        server->extensions.pre_share_key.psk_binders = malloc(len * sizeof(u8));
        memcpy(server->extensions.pre_share_key.psk_binders, client.extensions.pre_share_key.psk_binders, 2);
        server_hello_msg->hello_msg = concat_uc_str(
            server->extensions.pre_share_key.type, 2,
            server->extensions.pre_share_key.record_length, 2
        );
    }

    len = 0;
    u8 supported_versions[] = {0x03, 0x04};
    memcpy(server->extensions.supported_versions.versions, supported_versions, 2);
    server_hello_msg->hello_msg = concat_uc_str(
        server->extensions.supported_versions.versions, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    len += 2;
    server_hello_msg->hello_msg_len += 2;

    insert_header_len(server->extensions.supported_versions.length, len, 0, 1);
    server_hello_msg->hello_msg = concat_uc_str(
        server->extensions.supported_versions.length, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    len += 2;
    server_hello_msg->hello_msg_len += 2;

    u8 supported_versions_header[] = {0x00, 0x2b};
    memcpy(server->extensions.supported_versions.header, supported_versions_header, 2);
    server_hello_msg->hello_msg = concat_uc_str(
        server->extensions.supported_versions.header, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    len += 2;
    server_hello_msg->hello_msg_len += 2;

    insert_header_len(server->extensions_length, server_hello_msg->hello_msg_len, 0, 1);
    server_hello_msg->hello_msg = concat_uc_str(
        server->extensions_length, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 2;

    memset(server->compression_method, 0x00, sizeof(u8));
    server_hello_msg->hello_msg = concat_uc_str(
        server->compression_method, 1,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 1;

    u8 cipher_suite[] = {0x13, 0x02};
    memcpy(server->cipher_suites, cipher_suite, 2);
    server_hello_msg->hello_msg = concat_uc_str(
        server->cipher_suites, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 2;

    memcpy(server->session_id.length, client.session_id.length, 1);
    memcpy(server->session_id.id, client.session_id.id, 32);
    server_hello_msg->hello_msg = concat_uc_str(
        server->session_id.id, 32,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 32;
    server_hello_msg->hello_msg = concat_uc_str(
        server->session_id.length, 1,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 1;

    u8 random[32];
    get_random(random, 32);
    memcpy(server->random, random, 32);
    server_hello_msg->hello_msg = concat_uc_str(
        server->random, 32,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 32;

    u8 version[] = {0x03, 0x03};
    memcpy(server->tls_version, version, 2);
    server_hello_msg->hello_msg = concat_uc_str(
        server->tls_version, 2,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 2;

    u8 server_hello_handshake_header[] = {0x02, 0x00, 0x00, 0x00};
    insert_header_len(server_hello_handshake_header, server_hello_msg->hello_msg_len, 1, 3);
    memcpy(server->handshake_header, server_hello_handshake_header, 4);
    server_hello_msg->hello_msg = concat_uc_str(
        server->handshake_header, 4,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 4;

    u8 tls_record_header[] = {0x16, 0x03, 0x03, 0x00, 0x00};
    insert_header_len(tls_record_header, server_hello_msg->hello_msg_len, 3, 4);
    memcpy(server->record_header, tls_record_header, 5);
    server_hello_msg->hello_msg = concat_uc_str(
        server->record_header, 5,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->hello_msg_len += 5;

    server_hello_msg->all_msg = NULL;
    server_hello_msg->all_msg_len = 0;
    server_hello_msg->all_msg = concat_uc_str(
        server_hello_msg->all_msg, server_hello_msg->all_msg_len,
        server_hello_msg->hello_msg, server_hello_msg->hello_msg_len
    );
    server_hello_msg->all_msg_len += server_hello_msg->hello_msg_len;
}