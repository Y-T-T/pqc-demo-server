#include <base/base.h>
#include <base/param.h>
#include <server/serving.h>
#include <openssl/evp.h>
#include "include/AES_256_GCM.h"

int proxy_sock, client_sock, server_sock;
struct sockaddr_in proxy_addr, client_addr, server_addr;

void sigint_handler(int sig){
    printf("\nClosing proxy socket...");
    close(proxy_sock);
    printf("Done.\nExit.\n");
    exit(0);
}

void loadProxySetting(){
    int yes = 1;
    if(setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) error("Error on setsockopt.\n");
}

void loadTimeoutSetting(int sockfd){
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) == -1) error("Error on setsockopt.\n");
}

void createProxySocket(){
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    loadProxySetting();
    if (proxy_sock < 0) error("ERROR creating proxy socket.\n");
    else printf("Proxy socket created.\n");

    memset((char *)&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(PROXY_PORT);

    if (bind(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) error("ERROR on binding.\n");
    else printf("Proxy socket bind on port %d.\n", PROXY_PORT);

    if (listen(proxy_sock, 10) < 0) error("Listen failed");
    else printf("Listening on port %d...\n", PROXY_PORT);
}

void connectToGunicornServer(){
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    loadTimeoutSetting(server_sock);
    if (server_sock < 0) error("ERROR creating socket to server.\n");
    else printf("The socket to server created.\n");

    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(SERVER_PORT);

    if (connect(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) error("ERROR connecting to server.\n");
    else printf("Connected to server.\n");
}

char * getHeaderExtension(char *client_ip){
    char *headerOpt = "\r\nX-Forwarded-For: ";
    char *headerStr = concatString(headerOpt, client_ip);
    return headerStr;
}

char * insertXFor(char *buffer, char client_ip[INET_ADDRSTRLEN]){
    char *headerStr = getHeaderExtension(client_ip);
    char *newBuffer = (char *)malloc(strlen(buffer)+strlen(headerStr)+1);
    char *pch = strstr(buffer, SPLIT_STR);
    if(pch != NULL){
        int index = pch - buffer;
        strncpy(newBuffer, buffer, index);
        strcpy(newBuffer + index, headerStr);
        strcat(newBuffer, pch);
        free(headerStr);
    }
    else
        newBuffer = NULL;
    return newBuffer;
}

int main() {
    socklen_t client_addr_size = sizeof(client_addr);
    char *buffer = malloc(BUFFER_SIZE);
    char client_ip[INET_ADDRSTRLEN];
    ssize_t bytes;
    int connectionCount = 0;
    char *testHttpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World!";

    // init encryption args
    // EVP_CIPHER_CTX *ctx;
    // unsigned char key[EVP_MAX_KEY_LENGTH] = "your-256-bit-key"; // 256 bits key
    // unsigned char iv[EVP_MAX_IV_LENGTH] = "your-iv"; // init iv
    // unsigned char *tag = malloc(TAG_SIZE * sizeof(unsigned char));  // tag
    // char *plaintext = malloc(BUFFER_SIZE * sizeof(unsigned char));
    // unsigned char *ciphertext = malloc(BUFFER_SIZE * sizeof(unsigned char));
    // int outlen, plaintext_len, ciphertext_len;

    createProxySocket();
    signal(SIGINT, sigint_handler);
    
    while(1) {
        client_sock = accept(proxy_sock, (struct sockaddr *)&client_addr, &client_addr_size);
        loadTimeoutSetting(client_sock);
        if(client_sock < 0) error("ERROR on accept.");
        else {
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("\n(Connection count:%d)\n==============================\n", ++connectionCount);
            printf("Accept client IP:%s\n", client_ip);
        }
        
        connectToGunicornServer();
        memset(buffer, 0, BUFFER_SIZE);

        // while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
        //     printf("(Client)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
        //     parseRequest(buffer);
        //     memset(buffer, 0, sizeof(buffer));
        // }

        // plaintext_len = 0;
        // if(!evp_dec_init(&ctx, key, iv, tag)){
        //     printf("Decryption init error.\n");
        //     EVP_CIPHER_CTX_free(ctx);
        // }
        // else{
            int update_forwarded_header = 0;
            while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
                // if(bytes == BUFFER_SIZE)
                //     if(!dec_update(ctx, buffer, strlen(buffer), plaintext, &plaintext_len, &outlen)){
                //         printf("Decryption failed.\n");
                //         EVP_CIPHER_CTX_free(ctx);
                //         // send error to client
                //         break;
                //     }
                //     else{
                //         strcpy(buffer, plaintext);
                        if(update_forwarded_header == 0){
                            char *newBuffer = insertXFor(buffer, client_ip);
                            if(newBuffer != NULL){
                                update_forwarded_header = 1;
                                printf("(Client)\nBUFFER bytes:%ld\n%s\n", strlen(newBuffer), newBuffer);
                                send(server_sock, newBuffer, strlen(newBuffer), 0);
                            }
                            else
                                printf("Pattern not found\n");
                            
                            free(newBuffer);
                        }
                        else{
                            printf("(Client)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
                            send(server_sock, buffer, bytes, 0);
                        }
                        memset(buffer, 0, BUFFER_SIZE);
        //             }
        //         }
        //         else {
        //             if(!dec_update(ctx, buffer, strlen(buffer), plaintext, &plaintext_len, &outlen)){
        //                 printf("Decryption failed.\n");
        //                 EVP_CIPHER_CTX_free(ctx);
        //                 // send error to client
        //                 break;
        //             }
        //             if(!complete_dec(&ctx, plaintext, &plaintext_len, &outlen, tag)){
        //                 printf("Failed to complete decryption.\n");
        //                 EVP_CIPHER_CTX_free(ctx);
        //                 // send error to client
        //                 break;
        //             }
        //             printf("(Client)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
        //             send(server_sock, buffer, bytes, 0);
        //         }
            }

        // }

        while((bytes = recv(server_sock, buffer, BUFFER_SIZE, 0)) > 0){
            printf("(Server)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
            send(client_sock, buffer, bytes, 0);
            memset(buffer, 0, BUFFER_SIZE);
        }
        
        // send(client_sock, testHttpResponse, strlen(testHttpResponse), 0);
        printf("Closing client(IP:%s) socket...", client_ip);
        close(client_sock);
        printf("Done.\nClosing server socket...");
        close(server_sock);
        printf("Done.\n==============================\n");
    }

    close(proxy_sock);
    
    free(buffer);
    free(tag);
    free(plaintext);
    free(ciphertext);

    return 0;
}
