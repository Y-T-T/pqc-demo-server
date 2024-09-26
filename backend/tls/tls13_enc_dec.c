#include <tls/tls13_enc_dec.h>
#include <base/base.h>
#include <crypto/crypto_meth.h>
#include <crypto/openssl_base.h>

size_t server_msg_enc(BUFFER_POOL *pool, const size_t pool_idx, TLS13_KEY_EXCHANGE_CTX *key_ctx){
    EVP_CIPHER_CTX *ctx;
    u8 *iv = NULL;
    u8 *pt = NULL;
    u8 *ct = NULL;
    u8 tag[TAG_SIZE];
    int outlen, pt_len, ct_len;

    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    size_t length;
    u8 app_data_record_type[] = {0x17};
    
    for(int i = 0; i < pool_idx; i++){
        outlen = 0, ct_len = 0;
        length = pool[i].length + 1 + TAG_SIZE;
        if(length > MAX_POOL_BUFFER_SIZE){
            printf("Error: data too long.\n");
            printf("pool[%d]: len:%zd\n%s\n", i, pool[i].length, pool[i].buffer);
            return 0;
        }
        insert_header_len(record_header, length, 3, 4);

        pt = concat_uc_str(pool[i].buffer, pool[i].length, app_data_record_type, 1);
        pt_len = pool[i].length + 1;
        ct = malloc(pt_len * sizeof(u8));

        iv = GEN_IV(key_ctx->server_master_iv, &key_ctx->s_ap_seq);

        evp_enc_init(&ctx, key_ctx->server_master_key, iv);
        enc_update(ctx, record_header, TLS_RECORDER_HEADER_LENGTH, NULL, &ct_len, &outlen);
        enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
        complete_enc(&ctx, ct, &ct_len, &outlen, tag);

        if(ct_len + TAG_SIZE != length)
            printf("Application data encryption error.\n");
        else{
            memset(pool[i].buffer, 0, pool[i].length);
            pool[i].length = 0;
            memcpy(pool[i].buffer, record_header, TLS_RECORDER_HEADER_LENGTH);
            pool[i].length += TLS_RECORDER_HEADER_LENGTH;
            memcpy(pool[i].buffer + pool[i].length, ct, ct_len);
            pool[i].length += ct_len;
            memcpy(pool[i].buffer + pool[i].length, tag, TAG_SIZE);
            pool[i].length += TAG_SIZE;
        }

        free(ct);
        ct = NULL;
    }

    free(iv);
    iv = NULL;
    free(pt);
    pt = NULL;
    return 1;
}

size_t client_msg_dec(BUFFER_POOL *pool, const size_t pool_idx, TLS13_KEY_EXCHANGE_CTX *key_ctx){
    EVP_CIPHER_CTX *ctx;
    u8 aad[5];
    u8 *iv = NULL;
    u8 *ct = NULL;
    u8 *pt = NULL;
    u8 tag[TAG_SIZE];
    int outlen, pt_len, ct_len;
    
    u8 record_header[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    // u8 app_data_record_type[] = {0x17};

    for(int i = 0; i < pool_idx; i++){
        if(cmp_uc_str(record_header, pool[i].buffer, 3)){
            outlen = 0, pt_len = 0;
            memcpy(aad, pool[i].buffer, TLS_RECORDER_HEADER_LENGTH);
            // printf("aad:\n");
            // print_bytes(aad, 5);
            ct_len = (pool[i].buffer[3] << 8) + pool[i].buffer[4] - TAG_SIZE;
            ct = malloc(ct_len * sizeof(u8));
            memcpy(ct, pool[i].buffer + TLS_RECORDER_HEADER_LENGTH, ct_len);
            // printf("ct (len: %d):\n", ct_len);
            // print_bytes(ct, ct_len);
            memcpy(tag, pool[i].buffer + pool[i].length - TAG_SIZE, TAG_SIZE);
            // printf("tag (len: %d):\n", TAG_SIZE);
            // print_bytes(tag, TAG_SIZE);

            pt = malloc(ct_len * sizeof(u8));
            iv = GEN_IV(key_ctx->client_master_iv, &key_ctx->c_ap_seq);
            evp_dec_init(&ctx, key_ctx->client_master_key, iv);
            dec_update(ctx, aad, 5, NULL, &pt_len, &outlen);
            dec_update(ctx, ct, ct_len, pt, &pt_len, &outlen);
            complete_dec(&ctx, pt, &pt_len, &outlen, tag);

            // printf("pt (len: %d):\n", pt_len);
            // print_bytes(pt, pt_len);
            pt_len--; // remove record type
            memset(pool[i].buffer, 0, pool[i].length);
            memcpy(pool[i].buffer, pt, pt_len);

            free(pt);
            pt = NULL;
            memset(aad, 0, 5);
            memset(iv, 0, GCM_IV_LENGTH);
            memset(ct, 0, ct_len);
            memset(tag, 0, TAG_SIZE);
        }
        else{
            printf("Pool[%d]: Bad Record MAC.\n", i);
            EVP_CIPHER_CTX_free(ctx);
        }
        
    }
    
    free(iv);
    iv = NULL;
    free(ct);
    ct = NULL;
    return 1;
}