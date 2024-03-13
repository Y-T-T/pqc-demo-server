#include <tls/tls13_enc_dec.h>
#include <crypto/aes_256_gcm.h>
#include <crypto/openssl_base.h>

size_t server_msg_enc(u8 *msg, size_t msg_len, TLS13_KEY_EXCHANGE_CTX *key_ctx, u8 *output){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len, ct_len = 0;
    size_t output_len = 0;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    size_t record_header_len = 5, length;
    u8 app_data_record_type[] = {0x17};

    length =  msg_len + 1 + TAG_SIZE;
    insert_header_len(record_header, length, 3, 4);

    pt = concat_uc_str(msg, msg_len, app_data_record_type, 1);
    pt_len = msg_len + 1;
    u8 *ct = malloc(pt_len * sizeof(u8));

    // print_bytes(pt, pt_len);

    iv = build_iv(key_ctx->server_master_iv, &key_ctx->s_ap_seq);

    evp_enc_init(&ctx, key_ctx->server_master_key, iv);
    enc_update(ctx, record_header, record_header_len, NULL, &ct_len, &outlen);
    enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
    complete_enc(&ctx, ct, &ct_len, &outlen, tag);

    memset(output, 0, BUFFER_SIZE);
    if(ct_len + TAG_SIZE != length)
        printf("Application data encryption error.\n");
    else{
        memcpy(output, record_header, record_header_len);
        output_len += record_header_len;
        memcpy(output + output_len, ct, ct_len);
        output_len += ct_len;
        memcpy(output + output_len, tag, TAG_SIZE);
        output_len += TAG_SIZE;
    }
    
    return output_len;
}

size_t client_msg_dec(u8 *msg, size_t msg_len, TLS13_KEY_EXCHANGE_CTX *key_ctx, u8 *output){
    EVP_CIPHER_CTX *ctx;
    u8 aad[5];
    u8 *iv = NULL;
    u8 *ct = NULL;
    u8 tag[TAG_SIZE];
    int outlen = 0, pt_len = 0, ct_len;
    
    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    size_t record_header_len = 5;
    // u8 app_data_record_type[] = {0x17};

    if(cmp_uc_str(record_header, msg, 3)){
        memcpy(aad, msg, record_header_len);
        // printf("aad:\n");
        // print_bytes(aad, 5);
        ct_len = (msg[3] << 8) + msg[4] - TAG_SIZE;
        ct = malloc(ct_len * sizeof(u8));
        memcpy(ct, msg + record_header_len, ct_len);
        // printf("ct (len: %d):\n", ct_len);
        // print_bytes(ct, ct_len);
        memcpy(tag, msg + msg_len - TAG_SIZE, TAG_SIZE);
    }

    u8 *pt = malloc(ct_len * sizeof(u8));
    iv = build_iv(key_ctx->client_master_iv, &key_ctx->c_ap_seq);
    evp_dec_init(&ctx, key_ctx->client_master_key, iv);
    dec_update(ctx, aad, 5, NULL, &pt_len, &outlen);
    dec_update(ctx, ct, ct_len, pt, &pt_len, &outlen);
    complete_dec(&ctx, pt, &pt_len, &outlen, tag);

    pt_len--;
    memset(output, 0, BUFFER_SIZE);
    memcpy(output, pt, pt_len);
    
    free(iv);
    free(ct);
    free(pt);
    return pt_len;
}