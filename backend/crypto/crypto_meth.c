#include <crypto/crypto_meth.h>

#include <base/base.h>

static const EVP_CIPHER * get_cipher_suite_alg() {
    return TLS_CIPHER_SUITE();
}

u8 * build_nonce(u8 *iv, uint64_t *seq){

    u8 *nonce = malloc(_NONCE_LENGTH * sizeof(u8));
    memcpy(nonce, iv, 4);
    for(int i = 0; i < 8; i++)
        nonce[4 + i] = iv[4 + i] ^ (((*seq) >> ((7-i) * 8))&0xFF);
    (*seq)++;

    return nonce;
}

int evp_enc_init(EVP_CIPHER_CTX **ctx, u8 key[EVP_MAX_KEY_LENGTH], u8 iv[EVP_MAX_IV_LENGTH]){
    if(!(*ctx = EVP_CIPHER_CTX_new())) return 0;
    if(!EVP_EncryptInit_ex(*ctx, get_cipher_suite_alg(), NULL, NULL, NULL)) return 0;
    if(!EVP_EncryptInit_ex(*ctx, NULL, NULL, key, iv)) return 0;
    return 1;
}

int evp_dec_init(EVP_CIPHER_CTX **ctx, u8 key[EVP_MAX_KEY_LENGTH], u8 iv[EVP_MAX_IV_LENGTH]){
    if(!(*ctx = EVP_CIPHER_CTX_new())) return 0;
    if(!EVP_DecryptInit_ex(*ctx, get_cipher_suite_alg(), NULL, NULL, NULL)) return 0;
    if(!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, _NONCE_LENGTH, NULL)) return 0;
    if(!EVP_DecryptInit_ex(*ctx, NULL, NULL, key, iv)) return 0;
    return 1;
}

int enc_update(EVP_CIPHER_CTX *ctx, u8 *plaintext, int pt_len, u8 *ciphertext, int *ciphertext_len, int *outlen){
    if(!EVP_EncryptUpdate(ctx, ciphertext + (*ciphertext_len), &(*outlen), plaintext, pt_len)) return 0;
    if(ciphertext != NULL) *ciphertext_len += *outlen;
    return 1;
}

int dec_update(EVP_CIPHER_CTX *ctx, u8 *ciphertext, int ciphertext_len, u8 *plaintext, int *plaintext_len, int *outlen){
    if(!EVP_DecryptUpdate(ctx, plaintext, &(*outlen), ciphertext, ciphertext_len)) return 0;
    if(plaintext != NULL) *plaintext_len += *outlen;
    return 1;
}

int complete_enc(EVP_CIPHER_CTX **ctx, u8 *ciphertext, int *ciphertext_len, int *outlen, u8 *tag){
    if(!EVP_EncryptFinal_ex(*ctx, ciphertext + *ciphertext_len, &(*outlen))) return 0;
    *ciphertext_len += *outlen;

    if(!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) return 0;

    EVP_CIPHER_CTX_free(*ctx);
    *ctx = NULL;
    return 1;
}

int complete_dec(EVP_CIPHER_CTX **ctx, u8 *plaintext, int *plaintext_len, int *outlen, u8 *tag){
    if(!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag)){
        printf("Set tag error.\n");
        return 0;
    }

    if(!EVP_DecryptFinal_ex(*ctx, plaintext + *plaintext_len, &(*outlen))){
        printf("Decryption failed.\n");
        EVP_CIPHER_CTX_free(*ctx);
        return 0;
    }
    else{
        // plaintext[*outlen] = '\0';
        *plaintext_len += *outlen;
        // plaintext[*plaintext_len] = '\0';
        // printf("Decrypted text is:\n%s\n", plaintext);
    }

    EVP_CIPHER_CTX_free(*ctx);
    *ctx = NULL;
    return 1;
}

// int main(int argc, char const *argv[])
// {   
//     // char *skey = "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f";
//     char *siv = "9563bc8b590f671f488d2da3";
    
//     // u8 key[EVP_MAX_KEY_LENGTH];
//     u8 iv[EVP_MAX_IV_LENGTH];
//     // printf("%d %d\n", EVP_MAX_KEY_LENGTH, EVP_MAX_IV_LENGTH);
//     // hexStringToBytes(skey, key, strlen(skey));
//     // print_bytes(key, strlen(skey)/2);
//     hexStringToBytes(siv, iv, strlen(siv));
//     print_bytes(iv, strlen(siv)/2);
    
//     // u8 *tag = malloc(TAG_SIZE * sizeof(u8));
//     // u8 add[] = {0x17, 0x03, 0x03, 0x00, 0x17};
//     // u8 pt[] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x16};
//     // u8 *ct = malloc(BUFFER_SIZE * sizeof(u8));
//     // int outlen, pt_len, ct_len, add_len;

//     // add_len = 5;
//     // pt_len = 7;
//     // EVP_CIPHER_CTX *ctx;
//     // evp_enc_init(&ctx, key, iv);
//     // enc_update(ctx, add, add_len, NULL, &ct_len, &outlen);
//     // enc_update(ctx, pt, pt_len, ct, &ct_len, &outlen);
//     // complete_enc(&ctx, ct, &ct_len, &outlen, tag);

//     // print_bytes(ct, ct_len);
//     // print_bytes(tag, 16);

//     // u8 *decrypted_pt = malloc(BUFFER_SIZE * sizeof(u8));
//     // pt_len = 0;

//     // evp_dec_init(&ctx, key, iv);
//     // dec_update(ctx, add, add_len, NULL, &pt_len, &outlen);
//     // dec_update(ctx, ct, ct_len, decrypted_pt, &pt_len, &outlen);
//     // complete_dec(&ctx, decrypted_pt, &pt_len, &outlen, tag);

//     // print_bytes(decrypted_pt, pt_len);
    
//     // u8 *res = malloc(_NONCE_LENGTH * sizeof(u8));
//     // uint64_t seq = 0;
//     // for(;seq < 10; seq++){
//     //     // build_iv_o(iv, seq);
        
//     //     res = build_iv(iv, seq);
//     //     printf("%llu: ", seq);
//     //     print_bytes(res, _NONCE_LENGTH);

//     //     // print_bytes(iv, _NONCE_LENGTH);
//     // }

//     // free(res);
//     // free(tag);
//     // free(ct);
//     // free(decrypted_pt);
//     return 0;
// }
