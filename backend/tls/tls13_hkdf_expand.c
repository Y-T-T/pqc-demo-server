#include <tls/tls13_hkdf_expand.h>
#include <crypto/openssl_base.h>
#include <base/serving.h>

u8 * sha256(const u8 *message, const size_t message_len) {
    u8 *md = malloc(SHA256_DIGEST_LENGTH * sizeof(u8));
    unsigned int md_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    EVP_MD_CTX_free(mdctx);

    return md;
}

u8 * sha384(const u8 *message, const size_t message_len) {
    u8 *md = malloc(SHA384_DIGEST_LENGTH * sizeof(u8));
    unsigned int md_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    EVP_MD_CTX_free(mdctx);

    return md;
}

u8 * hmac_sha384(const u8 *key, const size_t key_len, const u8 *data, const size_t data_len) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    
    unsigned int len = EVP_MAX_MD_SIZE;
    u8 *md = malloc(len * sizeof(u8));
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    
    HMAC_CTX_reset(ctx);
    
    HMAC_Init_ex(ctx, key, key_len, EVP_sha384(), NULL);
    
    HMAC_Update(ctx, data, data_len);
    
    HMAC_Final(ctx, md, &len);
    
    // printf("HMAC SHA-384: ");
    // print_bytes(md, len);
    
    HMAC_CTX_free(ctx);

    #pragma GCC diagnostic pop
    
    return md;
}

u8 * hkdf_extract(const u8 *salt, const size_t salt_len, const u8 *ikm,const size_t key_len){

    size_t prk_len = EVP_MD_size(EVP_sha384());
    u8 *prk = malloc(EVP_MAX_MD_SIZE);

    // EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    // if (!pctx) {
    //     fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
    //     return NULL;
    // }

    // if (EVP_PKEY_derive_init(pctx) <= 0) {
    //     fprintf(stderr, "Failed to initialize derive operation\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }

    // if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
    //     printf("Set EVP_PKEY_CTX_hkdf_mode error\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }

    // if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384()) <= 0 ||
    //     EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, 0) <= 0 ||
    //     EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, key_len) <= 0) {
    //     fprintf(stderr, "Failed to set HKDF parameters\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }

    // if (EVP_PKEY_derive(pctx, prk, &prk_len) <= 0) {
    //     fprintf(stderr, "HKDF-Extract failed\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }

    // EVP_PKEY_CTX_free(pctx);

    prk = hmac_sha384(salt, salt_len, ikm, key_len);

    return prk;
}

static u8 * hkdf_expand(const u8 *ss, const size_t ss_len, struct HkdfLabel hkdf_label, const uint16_t context_len, const uint16_t out_len){

    u8 *info = malloc(516 * sizeof(u8));
    size_t info_len = 0;

    memcpy(info + info_len, &hkdf_label.length, sizeof(hkdf_label.length));
    info_len += sizeof(hkdf_label.length);
    // printf("bytes: %zu\ninfo: ", info_len);
    // print_bytes(info, info_len);

    uint8_t label_len = strlen(hkdf_label.label);
    // printf("Label len: %d\n", label_len);
    memcpy(info + info_len, &label_len, sizeof(label_len));
    info_len += sizeof(label_len);
    // printf("bytes: %zu\ninfo: ", info_len);
    // print_bytes(info, info_len);

    memcpy(info + info_len, hkdf_label.label, label_len);
    info_len += label_len;
    // printf("bytes: %zu\ninfo: ", info_len);
    // print_bytes(info, info_len);

    uint8_t ctx_len = context_len;
    // printf("ctx len: %d\n", ctx_len);
    memcpy(info + info_len, &ctx_len, sizeof(ctx_len));
    info_len += sizeof(ctx_len);
    // printf("bytes: %zu\ninfo: ", info_len);
    // print_bytes(info, info_len);

    memcpy(info + info_len, hkdf_label.context, context_len);
    info_len += context_len;
    // printf("bytes: %zu\ninfo: ", info_len);
    // print_bytes(info, info_len);

    uint8_t i = 0;
    size_t res_len = 0;

    u8 *hexin, *md;
    u8 *res = malloc((out_len / (SHA384_DIGEST_LENGTH + 1) + 1) * SHA384_DIGEST_LENGTH * sizeof(u8));
    // memcpy(res, info, info_len);
    // res_len = info_len;

    while(res_len < out_len){
        i++;
        hexin = concat_uc_str(res, res_len, info, info_len);
        hexin = concat_uc_str(hexin, res_len + info_len, (u8 *)&i, 1);
        // printf("hexin: ");
        // print_bytes(hexin, res_len + info_len + 1);

        md = hmac_sha384(ss, ss_len, hexin, res_len + info_len + 1);
        // printf("md: ");
        // print_bytes(md, SHA384_DIGEST_LENGTH);

        memcpy(res + res_len, md, SHA384_DIGEST_LENGTH);
        
        res_len += SHA384_DIGEST_LENGTH;
        // printf("res: ");
        // print_bytes(res, res_len);
    }
    // printf("bytes: %zu\nres: ", res_len);
    // print_bytes(res, res_len);
    free(hexin);
    free(md);

    // EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    // if (!pctx) {
    //     printf("EVP_PKEY_CTX_new_id failed\n");
    //     return NULL;
    // }
    // if (EVP_PKEY_derive_init(pctx) <= 0) {
    //     printf("EVP_PKEY_derive_init failed\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }
    // if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha384()) <= 0 ||
    //     EVP_PKEY_CTX_set1_hkdf_key(pctx, ss, ss_len) <= 0 ||
    //     EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
    //     EVP_PKEY_CTX_add1_hkdf_info(pctx, res, out_len) <= 0) {
    //         printf("set error\n");
    //         EVP_PKEY_CTX_free(pctx);
    //         return NULL;
    // }

    // size_t outlen = out_len;
    // u8 *output = malloc(outlen);
    // if (EVP_PKEY_derive(pctx, output, &outlen) <= 0) {
    //     printf("EVP_PKEY_derive failed\n");
    //     EVP_PKEY_CTX_free(pctx);
    //     return NULL;
    // }

    // EVP_PKEY_CTX_free(pctx);
    return res;
}

static u8 * hkdf_expand_label(const u8 *ss, const size_t ss_len, const char *label, const u8 *context, const uint16_t context_len, const uint16_t out_len){
    
    struct HkdfLabel hkdf_label;
    hkdf_label.length = htons(out_len);

    // printf("length: %hu\n", hkdf_label.length);

    const char *label_prefix = "tls13 ";
    strcpy(hkdf_label.label, label_prefix);
    strcat(hkdf_label.label, label);
    // printf("label: %s = ", hkdf_label.label);
    // print_bytes((u8 *)hkdf_label.label, strlen(hkdf_label.label));

    memcpy(hkdf_label.context, context, context_len);
    // printf("context: ");
    // print_bytes(hkdf_label.context, context_len);

    u8 *output = hkdf_expand(ss, ss_len, hkdf_label, context_len, out_len);

    return output;
}

u8 * derive_secret(const u8 *ss, const size_t ss_len, const char *label, const u8 *msg,  const uint16_t context_len, const uint16_t out_len){
    // u8 *context = sha384(msg, context_len);

    u8 *output = hkdf_expand_label(ss, ss_len, label, msg, context_len, out_len);

    return output;
}

// int main() {

//     /****** Test refrence: https://tls13.xargs.org/ *****/

//     const char *hello_hash_str = "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd";
//     const char *shared_secret_str = "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624";
//     size_t hello_hash_length = strlen(hello_hash_str) / 2;
//     u8 *hello_hash = malloc(hello_hash_length * sizeof(u8));
//     size_t shared_secret_length = strlen(shared_secret_str) / 2;
//     u8 *shared_secret = malloc(shared_secret_length * sizeof(u8));

//     hexStringToBytes(hello_hash_str, hello_hash, strlen(hello_hash_str));
//     hexStringToBytes(shared_secret_str, shared_secret, strlen(shared_secret_str));

//     printf("hh: ");
//     print_bytes(hello_hash, hello_hash_length);

//     printf("ss: ");
//     print_bytes(shared_secret, shared_secret_length);

//     // char *zero_str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
//     size_t len = strlen(ZERO_STR) / 2;

//     u8 *key = malloc(len);
//     hexStringToBytes(ZERO_STR, key, strlen(ZERO_STR));
//     u8 *salt = malloc(len);
//     hexStringToBytes(ZERO_STR, salt, strlen(ZERO_STR));
//     u8 *early_secret = hkdf_extract(salt, len, key, len);
//     printf("es: ");
//     print_bytes(early_secret, 48);

//     u8 *empty_hash = sha384(NULL, 0);
//     printf("eh: ");
//     print_bytes(empty_hash, 48);

//     u8 *derived_secret = derive_secret(early_secret, 48, "derived", empty_hash, 48, 48);
//     printf("ds: ");
//     print_bytes(derived_secret, 48);

//     u8 *handshake_secret = hkdf_extract(derived_secret, 48, shared_secret, shared_secret_length);
//     printf("hs: ");
//     print_bytes(handshake_secret, 48);

//     u8 *server_secret = derive_secret(handshake_secret, 48, "s hs traffic", hello_hash, 48, 48);
//     printf("ssec: ");
//     print_bytes(server_secret, 48);

//     u8 *client_secret = derive_secret(handshake_secret, 48, "c hs traffic", hello_hash, 48, 48);
//     printf("csec: ");
//     print_bytes(client_secret, 48);

//     u8 *server_handshake_key = derive_secret(server_secret, 48, "key", (u8 *)"", 0, 32);
//     printf("skey: ");
//     print_bytes(server_handshake_key, 32);

//     u8 *client_handshake_key = derive_secret(client_secret, 48, "key", (u8 *)"", 0, 32);
//     printf("ckey: ");
//     print_bytes(client_handshake_key, 32);

//     u8 *server_handshake_iv = derive_secret(server_secret, 48, "iv", (u8 *)"", 0, 12);
//     printf("siv: ");
//     print_bytes(server_handshake_iv, 12);

//     u8 *client_handshake_iv = derive_secret(client_secret, 48, "iv", (u8 *)"", 0, 12);
//     printf("civ: ");
//     print_bytes(client_handshake_iv, 12);

//     free(hello_hash);
//     free(shared_secret);
//     free(key);
//     free(salt);
//     free(empty_hash);
//     free(derived_secret);
//     free(handshake_secret);
//     free(server_secret);
//     free(client_secret);
//     free(server_handshake_key);
//     free(client_handshake_key);
//     free(server_handshake_iv);
//     free(client_handshake_iv);
//     return 0;
// }
