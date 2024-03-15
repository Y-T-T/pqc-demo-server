#include <tls/handshake.h>
#include <base/base.h>
#include <crypto/aes_256_gcm.h>
#include <crypto/x25519.h>
#include <tls/tls13_enc_dec.h>
#include <tls/tls13_hkdf_expand.h>
#include <tls/rsa_pss_rsae_sha_t.h>

void parse_client_hello(u8 *buffer, ssize_t buffer_len, HANDSHAKE_HELLO_MSG_CTX *client_hello){

    client_hello->cipher_suites = NULL;
    client_hello->extensions.session_ticket.ticket = NULL;
    client_hello->extensions.supported_versions.versions = NULL;
    client_hello->extensions.pre_share_key.identity = NULL;
    client_hello->extensions.pre_share_key.psk_binders = NULL;
    int idx = 0, eidx, len;

    // Record Header
    len = 5;
    memcpy((*client_hello).record_header, &buffer[idx], len);
    // printf("Record Header:\n");
    // print_bytes((*client_hello).record_header, len);
    idx += len;

    // Handshake Header
    len = 4;
    memcpy((*client_hello).handshake_header, &buffer[idx], len);
    // printf("Handshake Header:\n");
    // print_bytes((*client_hello).handshake_header, len);
    idx += len;

    // Client Version
    len = 2;
    memcpy((*client_hello).tls_version, &buffer[idx], len);
    // printf("Client Version:\n");
    // print_bytes((*client_hello).tls_version, len);
    idx += len;
    
    // Client Random
    len = 32;
    memcpy((*client_hello).random, &buffer[idx], len);
    // printf("Client Random:\n");
    // print_bytes((*client_hello).random, len);
    idx += len;

    // Session ID
    len = 33;
    memcpy((*client_hello).session_id.length, &buffer[idx], 1);
    memcpy((*client_hello).session_id.id, &buffer[idx+1], 32);
    // printf("Session ID:\n");
    // print_bytes((*client_hello).session_id.length, 1);
    // print_bytes((*client_hello).session_id.id, 32);
    idx += len;

    // Cipher Suites
    len = buffer[idx] << 8 | buffer[idx+1];
    len += 2;
    client_hello->cipher_suites = malloc(len * sizeof(u8));
    memcpy(client_hello->cipher_suites, &buffer[idx], len);
    // printf("Cipher Suites:\n");
    // print_bytes(client_hello->cipher_suites, len);
    idx += len;

    // Compression Methods
    len = 2;
    memcpy((*client_hello).compression_method, &buffer[idx], len);
    // printf("Compression Methods:\n");
    // print_bytes((*client_hello).compression_method, len);
    idx += len;

    // Extensions len
    len = 2;
    memcpy((*client_hello).extensions_length, &buffer[idx], len);
    // printf("Extensions len:\n");
    // print_bytes((*client_hello).extensions_length, len);
    idx += len;
    eidx = idx;

    /* Session ticket is in pre_share_key extension in TLS 1.3*/
    // // Find session_ticket extension
    // while(!(buffer[idx] == 0x00 && buffer[idx+1] == 0x23)){
    //     len = buffer[idx+2] << 8 | buffer[idx+3];
    //     idx += len + 4;
    // }
    // // printf("Find: %02x %02x\n", buffer[idx], buffer[idx+1]);
    // if(idx < buffer_len){
    //     len = buffer[idx+2] << 8 | buffer[idx+3];
    //     if(len != 0){
    //         client_hello->extensions.session_ticket.ticket = malloc(len * sizeof(u8));
    //         memcpy(client_hello->extensions.session_ticket.ticket, &buffer[idx], len);
    //     }
    //     else client_hello->extensions.session_ticket.ticket = NULL;
    // }
    // else printf("session_ticket extension not found.\n");

    idx = eidx;
    // Find supported_versions extension
    while(!(buffer[idx] == 0x00 && buffer[idx+1] == 0x2b) && idx < buffer_len){
        len = buffer[idx+2] << 8 | buffer[idx+3];
        idx += len + 4;
    }
    if(idx < buffer_len){
        len = buffer[idx+2] << 8 | buffer[idx+3];
        if(len != 0){
            memcpy(client_hello->extensions.supported_versions.header, &buffer[idx], 2);
            memcpy(client_hello->extensions.supported_versions.length, &buffer[idx+2], 2);
            client_hello->extensions.supported_versions.versions = malloc(len * sizeof(u8));
            memcpy(client_hello->extensions.supported_versions.versions, &buffer[idx+4], len);
        }
    }
    else printf("supported_versions extensions not found.\n");

    idx = eidx;
    // Find key_share extension
    while(!(buffer[idx] == 0x00 && buffer[idx+1] == 0x33) && idx < buffer_len){
        len = buffer[idx+2] << 8 | buffer[idx+3];
        idx += len + 4;
    }
    // printf("Find: %02x %02x\n", buffer[i], buffer[i+1]);
    if(idx < buffer_len){

        len = 2;
        memcpy(client_hello->extensions.key_share.header, &buffer[idx], len);
        // print_bytes(client_hello->extensions.key_share.header, len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.key_share.record_length, &buffer[idx], len);
        // print_bytes(client_hello->extensions.key_share.record_length, len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.key_share.keys_length, &buffer[idx], len);
        // print_bytes(client_hello->extensions.key_share.keys_length, len);
        idx += len;

        // Find X25519Kyber768Draft00 public key
        while(!(buffer[idx] == 0x63 && buffer[idx+1] == 0x99) && idx < buffer_len){
            len = buffer[idx+2] << 8 | buffer[idx+3];
            idx += len + 4;
        }
        if(idx < buffer_len){
            len = 2;
            memcpy(client_hello->extensions.key_share.key_change_method, &buffer[idx], len);
            // print_bytes(client_hello->extensions.key_share.key_change_method, len);
            idx += len;

            len = 2;
            memcpy(client_hello->extensions.key_share.key_len, &buffer[idx], len);
            // print_bytes(client_hello->extensions.key_share.key_len, len);
            idx += len;

            len = 32;
            memcpy(client_hello->extensions.key_share.key.x25519.pkey, &buffer[idx], len);
            // print_bytes(client_hello->extensions.key_share.key.x25519.pkey, len);
            idx += len;
            
            len = KYBER_INDCPA_PUBLICKEYBYTES;
            memcpy(client_hello->extensions.key_share.key.kyber768.pkey, &buffer[idx], len);
            // print_bytes(client_hello->extensions.key_share.key.kyber768.pkey, len);
        }
        else printf("X25519Kyber768Draft00 key not found.\n");
    }
    else printf("key_share extension not found.\n");

    idx = eidx;
    // Find pre_share_key extension
    while(!(buffer[idx] == 0x00 && buffer[idx+1] == 0x29) && idx < buffer_len){
        len = buffer[idx+2] << 8 | buffer[idx+3];
        idx += len + 4;
    }
    if(idx < buffer_len){
        len = 2;
        memcpy(client_hello->extensions.pre_share_key.type, &buffer[idx], len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.pre_share_key.record_length, &buffer[idx], len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.pre_share_key.identities_len, &buffer[idx], len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.pre_share_key.identity_len, &buffer[idx], len);
        idx += len;

        len = client_hello->extensions.pre_share_key.identity_len[0] << 8 | client_hello->extensions.pre_share_key.identity_len[1];
        if(len > 0){
            client_hello->extensions.pre_share_key.identity = malloc(len * sizeof(u8));
            memcpy(client_hello->extensions.pre_share_key.identity, &buffer[idx], len);
        }
        else client_hello->extensions.pre_share_key.identity = NULL;
        idx += len;

        len = 4;
        memcpy(client_hello->extensions.pre_share_key.ticket_age, &buffer[idx], len);
        idx += len;

        len = 2;
        memcpy(client_hello->extensions.pre_share_key.psk_binders_len, &buffer[idx], len);
        idx += len;

        len = client_hello->extensions.pre_share_key.psk_binders_len[0] << 8 | client_hello->extensions.pre_share_key.psk_binders_len[1];
        if(len > 0){
            client_hello->extensions.pre_share_key.psk_binders = malloc(len * sizeof(u8));
            memcpy(client_hello->extensions.pre_share_key.psk_binders, &buffer[idx], len);
        }
        idx += len;
    }
    else printf("pre_share_key extension not found.\n");
}

void update_transcript_hash_msg(TRANSCRIPT_HASH_MSG *transcript_hash_msg, u8 *msg, size_t msg_len){
    transcript_hash_msg->msg = concat_uc_str(
        transcript_hash_msg->msg, transcript_hash_msg->msg_len,
        msg, msg_len
    );

    transcript_hash_msg->msg_len += msg_len;

    transcript_hash_msg->hash = sha384(transcript_hash_msg->msg, transcript_hash_msg->msg_len);
    transcript_hash_msg->hash_len = SHA384_DIGEST_LENGTH;
}

int check_session_ticket(HANDSHAKE_HELLO_MSG_CTX *client_hello, const SESSION_POOL **pool, const size_t pool_len){
    // to-do
    int idx = 0;
    client_hello->extensions.session_ticket.valid = 0;
    while(idx < pool_len){
        if(cmp_uc_str(client_hello->extensions.pre_share_key.identity, 
            pool[idx]->session_ticket.ticket, TICKET_SIZE)){
            client_hello->extensions.session_ticket.valid = 1;
            return idx;
        }
        idx++;
    }
    return -1;
}

void add_change_cipher_spec(SERVER_HELLO_MSG *msg){
    u8 change_cipher_spec[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    msg->change_cipher_spec_len = 6;
    memcpy(msg->change_cipher_spec, change_cipher_spec, msg->change_cipher_spec_len);
    msg->all_msg = concat_uc_str(
        msg->all_msg, msg->all_msg_len,
        msg->change_cipher_spec, msg->change_cipher_spec_len
    );
    msg->all_msg_len += msg->change_cipher_spec_len;
}

void TLS13_KEY_EXCHANGE_CTX_INIT(TLS13_KEY_EXCHANGE_CTX *ctx){
    ctx->shared_secret = NULL;
    ctx->handshake_secret = NULL;
    ctx->server_handshake_traffic_secret = NULL;
    ctx->client_handshake_traffic_secret = NULL;
    ctx->server_handshake_key = NULL;
    ctx->client_handshake_key = NULL;
    ctx->server_handshake_iv = NULL;
    ctx->s_hs_seq = 0;
    ctx->client_handshake_iv = NULL;
    ctx->c_hs_seq = 0;
    ctx->server_master_key = NULL;
    ctx->client_master_key = NULL;
    ctx->server_master_iv = NULL;
    ctx->s_ap_seq = 0;
    ctx->client_master_iv = NULL;
    ctx->c_ap_seq = 0;
}

u8 * calc_ss(const HANDSHAKE_HELLO_MSG_CTX client, const HANDSHAKE_HELLO_MSG_CTX server){
    u8 x25519_ss[X25519_KEY_LENGTH];
    curve25519_donna(
        x25519_ss,
        server.extensions.key_share.key.x25519.skey,
        client.extensions.key_share.key.x25519.pkey
    );

    u8 *ss;
    ss = concat_uc_str(
        x25519_ss, X25519_KEY_LENGTH,
        server.extensions.key_share.key.kyber768.ss, KYBER_SSBYTES
    );
    return ss;
}

void handshake_key_calc(const u8 *hello_hash, TLS13_KEY_EXCHANGE_CTX *ctx){
    size_t len = strlen(ZERO_STR) / 2;
    u8 *key = malloc(len * sizeof(u8));
    u8 *salt = malloc(len * sizeof(u8));;
    hexStringToBytes(ZERO_STR, key, strlen(ZERO_STR));
    hexStringToBytes(ZERO_STR, salt, strlen(ZERO_STR));

    u8 *early_secret = hkdf_extract(salt, len, key, len);
    // printf("es: ");
    // print_bytes(early_secret, SHA384_DIGEST_LENGTH);
    u8 *empty_hash = sha384(NULL, 0);
    // printf("eh: ");
    // print_bytes(empty_hash, SHA384_DIGEST_LENGTH);

    u8 *derived_secret = derive_secret(early_secret, SHA384_DIGEST_LENGTH, "derived", empty_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    ctx->handshake_secret = hkdf_extract(derived_secret, SHA384_DIGEST_LENGTH, ctx->shared_secret, SS_LEN);
    ctx->server_handshake_traffic_secret = derive_secret(ctx->handshake_secret, SHA384_DIGEST_LENGTH, "s hs traffic", hello_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    ctx->client_handshake_traffic_secret = derive_secret(ctx->handshake_secret, SHA384_DIGEST_LENGTH, "c hs traffic", hello_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    ctx->server_handshake_key = derive_secret(ctx->server_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "key", (u8 *)"", 0, AES_KEY_LENGTH_256);
    ctx->client_handshake_key = derive_secret(ctx->client_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "key", (u8 *)"", 0, AES_KEY_LENGTH_256);
    ctx->server_handshake_iv = derive_secret(ctx->server_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "iv", (u8 *)"", 0, GCM_IV_LENGTH);
    ctx->client_handshake_iv = derive_secret(ctx->client_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "iv", (u8 *)"", 0, GCM_IV_LENGTH);

    // printf("hs: ");
    // print_bytes(ctx->handshake_secret, 48);
    // printf("ssec: ");
    // print_bytes(ctx->server_handshake_traffic_secret, 48);
    // printf("csec: ");
    // print_bytes(ctx->client_handshake_traffic_secret, 48);
    // printf("skey: ");
    // print_bytes(ctx->server_handshake_key, 32);
    // printf("ckey: ");
    // print_bytes(ctx->client_handshake_key, 32);
    // printf("siv: ");
    // print_bytes(ctx->server_handshake_iv, 12);
    // printf("civ: ");
    // print_bytes(ctx->client_handshake_iv, 12);
    // printf("\n");

    free(key);
    free(salt);
    free(early_secret);
    free(empty_hash);
    free(derived_secret);
}

void enc_server_ext(SERVER_HELLO_MSG *server_hello_msg, TLS13_KEY_EXCHANGE_CTX *key_ctx, TRANSCRIPT_HASH_MSG *transcript_hash_msg){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;

    u8 server_extension[] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};
    size_t server_extension_len = 6;

    length = server_extension_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    // printf("Wrap record header (server extension):\n");
    // print_bytes(wrap_record_header, wrap_record_header_len);

    pt = concat_uc_str(server_extension, server_extension_len, record_type, 1);
    pt_len = server_extension_len + 1;
    // printf("pt:\n");
    // print_bytes(pt, pt_len);

    u8 *ct = malloc(pt_len * sizeof(u8));
    iv = build_iv(key_ctx->server_handshake_iv, &(key_ctx->s_hs_seq));
    // printf("s_hs_seq: %llu\n", key_ctx->s_hs_seq);
    // printf("iv:\n");
    // print_bytes(iv, GCM_IV_LENGTH);
    evp_enc_init(&ctx, key_ctx->server_handshake_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);
    // printf("ct:\n");
    // print_bytes(ct, ct_len);

    // printf("tag:\n");
    // print_bytes(tag, TAG_SIZE);
    // printf("\n");

    if(ct_len + TAG_SIZE != length)
        printf("Wrap record encryption error.\n");
    else{
        server_hello_msg->extensions = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
        server_hello_msg->extensions = concat_uc_str(record_header, record_header_len, server_hello_msg->extensions, length);
    }

    server_hello_msg->extensions_len = record_header_len + length;
    server_hello_msg->all_msg = concat_uc_str(
        server_hello_msg->all_msg, server_hello_msg->all_msg_len,
        server_hello_msg->extensions, server_hello_msg->extensions_len
    );
    server_hello_msg->all_msg_len += server_hello_msg->extensions_len;

    update_transcript_hash_msg(transcript_hash_msg, server_extension, server_extension_len);

    // printf("Wrap record 1 (len: %zu):\n", length);
    // print_bytes(server_hello_msg->extensions, server_hello_msg->extensions_len);
    // printf("\n");

    free(iv);
    free(pt);
    free(ct);
}

static void load_certificates(const char *filepath, u8 **cert, size_t *len){
    FILE *file = fopen(filepath, "rb");
    if (file == NULL)
        printf("Error opening file\n");
    
    fseek(file, 0, SEEK_END);
    *len = ftell(file);
    rewind(file);

    // printf("%d\n", *len);

    u8 *temp = realloc(*cert, (*len) * sizeof(u8));
    if(temp == NULL)
        fputs("Memory error", stderr);
    else
        *cert = temp;
        fread(*cert, 1, *len, file);
    
    fclose(file);
}

void enc_server_cert(SERVER_HELLO_MSG *server_hello_msg, TLS13_KEY_EXCHANGE_CTX *key_ctx, TRANSCRIPT_HASH_MSG *transcript_hash_msg){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;

    u8 *server_cert = NULL;
    u8 cert_handshake_header[] = {0x0b, 0x00, 0x00, 0x00};
    u8 cert_req_ctx[] = {0x00};
    u8 certs_length[] = {0x00, 0x00, 0x00};
    u8 cert_length[] = {0x00, 0x00, 0x00};
    u8 *cert = malloc(CRT_SIZE * sizeof(u8));
    size_t cert_len, server_cert_len;
    u8 cert_extensions[] = {0x00, 0x00};

    load_certificates("../src/cert/www.pqc-demo.xyz.der", &cert, &cert_len);
    server_cert = concat_uc_str(cert, cert_len, cert_extensions, 2);
    server_cert_len = cert_len + 2;
    insert_header_len(cert_length, cert_len, 0, 2); // only cert length
    server_cert = concat_uc_str(cert_length, 3, server_cert, server_cert_len);
    server_cert_len += 3;

    insert_header_len(certs_length, server_cert_len, 0, 2); // crts length
    server_cert = concat_uc_str(certs_length, 3, server_cert, server_cert_len);
    server_cert_len += 3;
    server_cert = concat_uc_str(cert_req_ctx, 1, server_cert, server_cert_len);
    server_cert_len += 1;
    insert_header_len(cert_handshake_header, server_cert_len, 1, 3);
    server_cert = concat_uc_str(cert_handshake_header, 4, server_cert, server_cert_len);
    server_cert_len += 4;

    length = server_cert_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    pt = concat_uc_str(server_cert, server_cert_len, record_type, 1);
    pt_len = server_cert_len + 1;
    // printf("pt:\n");
    // print_bytes(pt, pt_len);

    u8 *ct = malloc(pt_len * sizeof(u8));
    iv = build_iv(key_ctx->server_handshake_iv, &(key_ctx->s_hs_seq));
    // printf("server_hs_seq: %llu\n", server_hs_seq);
    // printf("iv:\n");
    // print_bytes(iv, GCM_IV_LENGTH);
    evp_enc_init(&ctx, key_ctx->server_handshake_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);
    // printf("ct:\n");
    // print_bytes(ct, ct_len);

    // printf("tag:\n");
    // print_bytes(tag, TAG_SIZE);
    // printf("\n");

    if(ct_len + TAG_SIZE != length)
        printf("Wrap record encryption error.\n");
    else{
        server_hello_msg->cert = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
        server_hello_msg->cert = concat_uc_str(record_header, record_header_len, server_hello_msg->cert, length);
    }

    server_hello_msg->cert_len = record_header_len + length;

    server_hello_msg->all_msg = concat_uc_str(
        server_hello_msg->all_msg, server_hello_msg->all_msg_len,
        server_hello_msg->cert, server_hello_msg->cert_len
    );
    server_hello_msg->all_msg_len += server_hello_msg->cert_len;

    update_transcript_hash_msg(transcript_hash_msg, server_cert, server_cert_len);

    // printf("Wrap record 2 (len: %zu):\n", length);
    // print_bytes(server_hello_msg->cert, server_hello_msg->cert_len);
    // printf("\n");

    free(iv);
    free(pt);
    free(ct);
}

void enc_server_cert_verify(SERVER_HELLO_MSG *server_hello_msg, TLS13_KEY_EXCHANGE_CTX *key_ctx, TRANSCRIPT_HASH_MSG *transcript_hash_msg){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;

    u8 *server_cert_verify = NULL;
    u8 cert_verify_handshake_header[] = {0x0f, 0x00, 0x00, 0x00};
    /* signature header type:
     * RSA-PSS-RSAE-SHA256 (0x08, 0x04)
     * RSA-PSS-RSAE-SHA384 (0x08, 0x05)
    */
    u8 signature_header[] = {0x08, 0x04, 0x00, 0x00};
    u8 *to_sign = NULL;
    u8 space_64[64];
    memset(space_64, 0x20, sizeof(space_64));
    u8 sign_fixed_str[] = "TLS 1.3, server CertificateVerify\0";
    u8 *signature = NULL;
    size_t to_sign_len, sign_len, server_cert_verify_len;

    to_sign = concat_uc_str(space_64, 64, sign_fixed_str, strlen((char *)sign_fixed_str) + 1);
    to_sign_len = 64 + strlen((char *)sign_fixed_str) + 1;

    to_sign = concat_uc_str(to_sign, to_sign_len, transcript_hash_msg->hash, SHA384_DIGEST_LENGTH);
    to_sign_len += SHA384_DIGEST_LENGTH;

    signature = sign_msg(to_sign, to_sign_len, SIGN_ALG, &sign_len);

    // printf("signature:\n");
    // print_bytes(signature, sign_len);
    // printf("\n");

    // if(verify_msg(to_sign, to_sign_len, SIGN_ALG, signature, sign_len))
    //     printf("Verification successful.\n\n");
    // else
    //     printf("Verification failed.\n\n");

    insert_header_len(signature_header, sign_len, 2, 3);
    signature = concat_uc_str(signature_header, 4, signature, sign_len);
    sign_len += 4;

    insert_header_len(cert_verify_handshake_header, sign_len, 1, 3);
    server_cert_verify = concat_uc_str(cert_verify_handshake_header, 4, signature, sign_len);
    server_cert_verify_len = 4 + sign_len;

    length =  server_cert_verify_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    pt = concat_uc_str(server_cert_verify, server_cert_verify_len, record_type, 1);
    pt_len = server_cert_verify_len + 1;
    // printf("pt:\n");
    // print_bytes(pt, pt_len);

    u8 *ct = malloc(pt_len * sizeof(u8));
    iv = build_iv(key_ctx->server_handshake_iv, &(key_ctx->s_hs_seq));

    evp_enc_init(&ctx, key_ctx->server_handshake_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);
    // printf("ct:\n");
    // print_bytes(ct, ct_len);

    // printf("tag:\n");
    // print_bytes(tag, TAG_SIZE);
    // printf("\n");

    if(ct_len + TAG_SIZE != length)
        printf("Wrap record encryption error.\n");
    else{
        server_hello_msg->cert_verify = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
        server_hello_msg->cert_verify = concat_uc_str(record_header, record_header_len, server_hello_msg->cert_verify, length);
    }
    
    server_hello_msg->cert_verify_len = record_header_len + length;

    server_hello_msg->all_msg = concat_uc_str(
        server_hello_msg->all_msg, server_hello_msg->all_msg_len,
        server_hello_msg->cert_verify, server_hello_msg->cert_verify_len
    );
    server_hello_msg->all_msg_len += server_hello_msg->cert_verify_len;

    update_transcript_hash_msg(transcript_hash_msg, server_cert_verify, server_cert_verify_len);

    // printf("wrap record 3 (len: %zu):\n", length);
    // print_bytes(server_hello_msg->cert_verify, server_hello_msg->cert_verify_len);
    // printf("\n");

    free(iv);
    free(pt);
    free(ct);
    free(server_cert_verify);
    free(to_sign);
    free(signature);
}

void enc_server_handshake_finished(SERVER_HELLO_MSG *server_hello_msg, TLS13_KEY_EXCHANGE_CTX *key_ctx, TRANSCRIPT_HASH_MSG *transcript_hash_msg){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;

    u8 *finish_key = NULL;
    u8 *verify_data = NULL;
    u8 handshake_finished_header[] = {0x14, 0x00, 0x00, 0x00};
    u8 *server_handshake_finished = NULL;
    size_t verify_data_len, finished_header_len = 4, server_handshake_finished_len;

    finish_key = derive_secret(key_ctx->server_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "finished", (u8 *)"", 0, SHA384_DIGEST_LENGTH);
    verify_data = hmac_sha384(finish_key, SHA384_DIGEST_LENGTH, transcript_hash_msg->hash, transcript_hash_msg->hash_len);
    verify_data_len = SHA384_DIGEST_LENGTH;

    insert_header_len(handshake_finished_header, verify_data_len, 1, 3);
    server_handshake_finished = concat_uc_str(handshake_finished_header, 4, verify_data, verify_data_len);
    server_handshake_finished_len = 4 + verify_data_len;

    length = server_handshake_finished_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    pt = concat_uc_str(server_handshake_finished, server_handshake_finished_len, record_type, 1);
    pt_len = server_handshake_finished_len + 1;
    // printf("pt:\n");
    // print_bytes(pt, pt_len);

    u8 *ct = malloc(pt_len * sizeof(u8));
    iv = build_iv(key_ctx->server_handshake_iv, &(key_ctx->s_hs_seq));

    evp_enc_init(&ctx, key_ctx->server_handshake_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);
    // printf("ct:\n");
    // print_bytes(ct, ct_len);

    // printf("tag:\n");
    // print_bytes(tag, TAG_SIZE);
    // printf("\n");

    if(ct_len + TAG_SIZE != length)
        printf("Wrap record encryption error.\n");
    else{
        server_hello_msg->finished = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
        server_hello_msg->finished = concat_uc_str(record_header, record_header_len, server_hello_msg->finished, length);
    }

    server_hello_msg->finished_len = record_header_len + length;

    server_hello_msg->all_msg = concat_uc_str(
        server_hello_msg->all_msg, server_hello_msg->all_msg_len,
        server_hello_msg->finished, server_hello_msg->finished_len
    );
    server_hello_msg->all_msg_len += server_hello_msg->finished_len;

    update_transcript_hash_msg(transcript_hash_msg, server_handshake_finished, server_handshake_finished_len);

    // printf("wrap record 4 (len: %zu):\n", length);
    // print_bytes(server_hello_msg->finished, server_hello_msg->finished_len);
    // printf("\n");

    free(iv);
    free(pt);
    free(ct);
    free(server_handshake_finished);
    free(finish_key);
    free(verify_data);
}

void master_key_calc(TLS13_KEY_EXCHANGE_CTX *ctx, const TRANSCRIPT_HASH_MSG transcript_hash_msg){
    size_t len = strlen(ZERO_STR) / 2;
    u8 *key = malloc(len * sizeof(u8));
    hexStringToBytes(ZERO_STR, key, strlen(ZERO_STR));

    u8 *empty_hash = sha384(NULL, 0);
    // printf("eh: ");
    // print_bytes(empty_hash, SHA384_DIGEST_LENGTH);

    u8 *derived_secret = derive_secret(ctx->handshake_secret, SHA384_DIGEST_LENGTH, "derived", empty_hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    u8 *ms = hkdf_extract(derived_secret, SHA384_DIGEST_LENGTH, key, len);
    u8 *ssec = derive_secret(ms, SHA384_DIGEST_LENGTH, "s ap traffic", transcript_hash_msg.hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    u8 *csec = derive_secret(ms, SHA384_DIGEST_LENGTH, "c ap traffic", transcript_hash_msg.hash, SHA384_DIGEST_LENGTH, SHA384_DIGEST_LENGTH);
    ctx->server_master_key = derive_secret(ssec, SHA384_DIGEST_LENGTH, "key", (u8 *)"", 0, AES_KEY_LENGTH_256);
    ctx->client_master_key = derive_secret(csec, SHA384_DIGEST_LENGTH, "key", (u8 *)"", 0, AES_KEY_LENGTH_256);
    ctx->server_master_iv = derive_secret(ssec, SHA384_DIGEST_LENGTH, "iv", (u8 *)"", 0, GCM_IV_LENGTH);
    ctx->client_master_iv = derive_secret(csec, SHA384_DIGEST_LENGTH, "iv", (u8 *)"", 0, GCM_IV_LENGTH);

    free(key);
    free(empty_hash);
    free(derived_secret);
    free(ms);
    free(ssec);
    free(csec);
}

int verify_client_finished(u8 *client_finished, size_t client_finished_len, TLS13_KEY_EXCHANGE_CTX *key_ctx, const TRANSCRIPT_HASH_MSG transcript_hash_msg){
    EVP_CIPHER_CTX *ctx;
    u8 aad[5];
    u8 *iv = NULL;
    u8 *ct = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len = 0, ct_len;
    
    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;
    u8 change_cipher_spec[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

    u8 *finished_key = NULL;
    u8 *verify_data = NULL;
    u8 handshake_finished_header[] = {0x14, 0x00, 0x00, 0x00};
    u8 *client_handshake_finished = NULL;
    size_t verify_data_len, client_handshake_finished_len;

    finished_key = derive_secret(key_ctx->client_handshake_traffic_secret, SHA384_DIGEST_LENGTH, "finished", (u8 *)"", 0, SHA384_DIGEST_LENGTH);
    verify_data = hmac_sha384(finished_key, SHA384_DIGEST_LENGTH, transcript_hash_msg.hash, transcript_hash_msg.hash_len);
    verify_data_len = SHA384_DIGEST_LENGTH;

    insert_header_len(handshake_finished_header, verify_data_len, 1, 3);
    client_handshake_finished = concat_uc_str(handshake_finished_header, 4, verify_data, verify_data_len);
    client_handshake_finished_len = 4 + verify_data_len;

    client_handshake_finished = concat_uc_str(client_handshake_finished, client_handshake_finished_len, record_type, 1);
    client_handshake_finished_len++;

    // printf("client handshake finished(len: %zu):\n", client_handshake_finished_len);
    // print_bytes(client_handshake_finished, client_handshake_finished_len);
    
    if(!cmp_uc_str(change_cipher_spec, client_finished, 6)){
        printf("Error: No \"change cipher spec\" message recieved.\n");
        return 0;
    }

    if(cmp_uc_str(record_header, client_finished + 6, 3)){
        // printf("data (len: %d):\n", (client_finished[9] << 8) + client_finished[10]);
        // print_bytes(client_finished + 6, client_finished_len - 6);
        memcpy(aad, client_finished + 6, 5);
        // printf("aad:\n");
        // print_bytes(aad, 5);
        ct_len = (client_finished[9] << 8) + client_finished[10] - TAG_SIZE;
        ct = malloc(ct_len * sizeof(u8));
        memcpy(ct, client_finished + 6 + record_header_len, ct_len);
        // printf("ct (len: %d):\n", ct_len);
        // print_bytes(ct, ct_len);
        memcpy(tag, client_finished + client_finished_len - TAG_SIZE, TAG_SIZE);
        // printf("tag (len: %d)\n", TAG_SIZE);
        // print_bytes(tag, TAG_SIZE);
    }

    u8 *pt = malloc(ct_len * sizeof(u8));
    iv = build_iv(key_ctx->client_handshake_iv, &key_ctx->c_hs_seq);
    evp_dec_init(&ctx, key_ctx->client_handshake_key, iv);
    dec_update(ctx, aad, 5, NULL, &pt_len, &outlen);
    dec_update(ctx, ct, ct_len, pt, &pt_len, &outlen);
    complete_dec(&ctx, pt, &pt_len, &outlen, tag);

    // printf("Decrypted verify data:(len: %d):\n", pt_len);
    // print_bytes(pt, pt_len);
    // printf("\n");

    if( pt_len != client_finished_len ||
        !cmp_uc_str(client_finished, pt, pt_len))
        return 0;

    free(iv);
    free(ct);
    free(pt);
    free(finished_key);
    free(verify_data);
    free(client_handshake_finished);

    return 1;
}

static SESSION_TICKET gen_new_ticket(){
    SESSION_TICKET new_ticket = {
        1,
        {0x04, 0x00, 0x00, 0xd5},
        {0x00, 0x00, 0x1c, 0x20},
        {0x00, 0x00, 0x00, 0x00},
        {0x08, 0x00 ,0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        NULL, 0,
        {0x00, 0x00}};

    new_ticket.ticket = malloc(TICKET_SIZE * sizeof(u8));
    get_random(new_ticket.ticket, TICKET_SIZE);

    u8 ticket_len[] = {0x00, 0xc0};
    new_ticket.ticket = concat_uc_str(ticket_len, 2, new_ticket.ticket, TICKET_SIZE);
    new_ticket.ticket_len = TICKET_SIZE + 2;
    // printf("Session ticket:\n");
    // print_bytes(new_ticket.ticket, new_ticket.ticket_len);
    return new_ticket;
}

u8 * generate_session_ticket(TLS13_KEY_EXCHANGE_CTX *key_ctx, SESSION_POOL *pool, size_t *pool_len, size_t *ticket_msg_len){
    if(*pool_len < MAX_POOL_SIZE){
        pool[*pool_len].session_ticket = gen_new_ticket();
        pool[*pool_len].key_ctx = key_ctx;
    }
    else{
        printf("Error: Session pool is full.\n");
        return NULL;
    }
    // printf("Session ticket:\n");
    // print_bytes(pool[*pool_len].session_ticket.ticket, pool[*pool_len].session_ticket.ticket_len);

    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    u8 record_type[] = {0x16};
    size_t record_header_len = 5, length;

    u8 *session_ticket = NULL;
    size_t session_ticket_len;
    u8 *output = NULL;

    session_ticket = concat_uc_str(
        pool[(*pool_len)].session_ticket.handshake_header, 4,
        pool[(*pool_len)].session_ticket.ticket_lifetime, 4
    );
    session_ticket_len = 4 + 4;

    session_ticket = concat_uc_str(
        session_ticket, session_ticket_len,
        pool[(*pool_len)].session_ticket.ticket_age_add, 4
    );
    session_ticket_len += 4;

    session_ticket = concat_uc_str(
        session_ticket, session_ticket_len,
        pool[(*pool_len)].session_ticket.ticket_nonce, 9
    );
    session_ticket_len += 9;

    session_ticket = concat_uc_str(
        session_ticket, session_ticket_len,
        pool[(*pool_len)].session_ticket.ticket, pool[(*pool_len)].session_ticket.ticket_len
    );
    session_ticket_len += pool[(*pool_len)].session_ticket.ticket_len;

    session_ticket = concat_uc_str(
        session_ticket, session_ticket_len,
        pool[(*pool_len)].session_ticket.extensions, 2
    );
    session_ticket_len += 2;

    // printf("Session ticket:\n");
    // print_bytes(session_ticket, session_ticket_len);

    length = session_ticket_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    pt = concat_uc_str(session_ticket, session_ticket_len, record_type, 1);
    pt_len = session_ticket_len + 1;
    // printf("pt:\n");
    // print_bytes(pt, pt_len);

    u8 *ct = malloc(pt_len * sizeof(u8));
    iv = build_iv(pool[*pool_len].key_ctx->server_master_iv, &(pool[*pool_len].key_ctx->s_ap_seq));
    // printf("server_ap_seq: %llu\n", pool[*pool_len].key_ctx->s_ap_seq);
    evp_enc_init(&ctx, pool[*pool_len].key_ctx->server_master_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);
    // printf("ct:\n");
    // print_bytes(ct, ct_len);

    // printf("tag:\n");
    // print_bytes(tag, TAG_SIZE);
    // printf("\n");

    if(ct_len + TAG_SIZE != length)
        printf("Wrap record encryption error.\n");
    else{
        output = concat_uc_str(ct, ct_len, tag, TAG_SIZE);
        output = concat_uc_str(record_header, record_header_len, output, length);
    }

    *ticket_msg_len = record_header_len + length;
    (*pool_len)++;
    free(iv);
    free(pt);
    free(ct);
    return output;
}

void TRANSCRIPT_HASH_MSG_FREE(TRANSCRIPT_HASH_MSG *ctx){
    if(ctx->msg != NULL){
        free(ctx->msg);
        ctx->msg = NULL;
    }
    ctx->msg_len = 0;
    if(ctx->hash != NULL){
        free(ctx->hash);
        ctx->hash = NULL;
    }
    ctx->hash_len = 0;
}

void SERVER_HELLO_MSG_FREE(SERVER_HELLO_MSG *ctx){
    if(ctx->hello_msg != NULL){
        free(ctx->hello_msg);
        ctx->hello_msg = NULL;
    }
    ctx->hello_msg_len = 0;
    if(ctx->extensions != NULL){
        free(ctx->extensions);
        ctx->extensions = NULL;
    }
    ctx->extensions_len = 0;
    if(ctx->cert != NULL){
        free(ctx->cert);
        ctx->cert = NULL;
    }
    ctx->cert_len = 0;
    if(ctx->cert_verify != NULL){
        free(ctx->cert_verify);
        ctx->cert_verify = NULL;
    }
    ctx->cert_verify_len = 0;
    if(ctx->finished != NULL){
        free(ctx->finished);
        ctx->finished = NULL;
    }
    ctx->finished_len = 0;
    if(ctx->all_msg != NULL){
        free(ctx->all_msg);
        ctx->all_msg = NULL;
    }
    ctx->all_msg_len = 0;
}

void HANDSHAKE_HELLO_MSG_CTX_FREE(HANDSHAKE_HELLO_MSG_CTX *ctx){
    if(ctx->cipher_suites != NULL){
        free(ctx->cipher_suites);
        ctx->cipher_suites = NULL;
    }
    if(ctx->extensions.session_ticket.ticket != NULL){
        free(ctx->extensions.session_ticket.ticket);
        ctx->extensions.session_ticket.ticket = NULL;
    }
    if(ctx->extensions.supported_versions.versions != NULL){
        free(ctx->extensions.supported_versions.versions);
        ctx->extensions.supported_versions.versions = NULL;
    }
    if(ctx->extensions.pre_share_key.identity != NULL){
        free(ctx->extensions.pre_share_key.identity );
        ctx->extensions.pre_share_key.identity  = NULL;
    }
    if(ctx->extensions.pre_share_key.psk_binders != NULL){
        free(ctx->extensions.pre_share_key.psk_binders);
        ctx->extensions.pre_share_key.psk_binders = NULL;
    }
}

void TLS13_KEY_EXCHANGE_CTX_FREE(TLS13_KEY_EXCHANGE_CTX *ctx){
    if(ctx->shared_secret != NULL){
        free(ctx->shared_secret);
        ctx->shared_secret = NULL;
    }
    if(ctx->handshake_secret != NULL){
        free(ctx->handshake_secret);
        ctx->handshake_secret = NULL;
    }
    if(ctx->server_handshake_traffic_secret != NULL){
        free(ctx->server_handshake_traffic_secret);
        ctx->server_handshake_traffic_secret = NULL;
    }
    if(ctx->client_handshake_traffic_secret != NULL){
        free(ctx->client_handshake_traffic_secret);
        ctx->client_handshake_traffic_secret = NULL;
    }
    if(ctx->server_handshake_key != NULL){
        free(ctx->server_handshake_key);
        ctx->server_handshake_key = NULL;
    }
    if(ctx->client_handshake_key != NULL){
        free(ctx->client_handshake_key);
        ctx->client_handshake_key = NULL;
    }
    if(ctx->server_handshake_iv != NULL){
        free(ctx->server_handshake_iv);
        ctx->server_handshake_iv = NULL;
    }
    if(ctx->client_handshake_iv != NULL){
        free(ctx->client_handshake_iv);
        ctx->client_handshake_iv = NULL;
    }
    if(ctx->server_master_key != NULL){
        free(ctx->server_master_key);
        ctx->server_master_key = NULL;
    }
    if(ctx->client_master_key != NULL){
        free(ctx->shared_secret);
        ctx->client_master_key = NULL;
    }
    if(ctx->server_master_iv != NULL){
        free(ctx->server_master_iv);
        ctx->server_master_iv = NULL;
    }
    if(ctx->client_master_iv != NULL){
        free(ctx->client_master_iv);
        ctx->client_master_iv = NULL;
    }
}

void SESSION_POOL_FREE(SESSION_POOL *ctx, size_t size){
    for(int i = 0; i < size; i++){
        if(ctx[i].key_ctx != NULL){
            TLS13_KEY_EXCHANGE_CTX_FREE(ctx[i].key_ctx);
            ctx[i].key_ctx = NULL;
        }
        if(ctx[i].session_ticket.ticket != NULL){
            free(ctx[i].session_ticket.ticket);
            ctx[i].session_ticket.ticket = NULL;
        }
    }
}