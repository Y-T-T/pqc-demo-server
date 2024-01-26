#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define PROXY_PORT 80
#define SERVER_PORT 8080
#define BUFFER_SIZE 4096
#define SPLIT_STR "\r\n\r\n"

int proxy_sock, client_sock, server_sock;
struct sockaddr_in proxy_addr, client_addr, server_addr;

void sigint_handler(int sig){
    printf("\nClosing proxy socket...");
    close(proxy_sock);
    printf("Done.\nExit.\n");
    exit(0);
}

void error(const char *msg){
    perror(msg);
    exit(1);
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

char * concatString(const char *str1, const char *str2){
    char *res = (char *)malloc(strlen(str1)+strlen(str2)+1);
    if(res == NULL) error("Failed to allocate memory.\n");
    strcpy(res, str1);
    strcat(res, str2);
    return res;
}

void sendResponse(int sockfd, const char *filename, const char *filetype){
    char *dir = "../frontend/build";
    char *filepath = concatString(dir, filename);

    FILE *file = fopen(filepath, "r");
    if(file == NULL) {
        const char *header = "HTTP/1.1 404 Not Found\r\n\r\n";
        send(sockfd, header, strlen(header), 0);
        return;
    }

    char *header = concatString("HTTP/1.1 200 OK\r\nContent-Type:", filetype);
    send(sockfd, header, strlen(header), 0);

    char buffer[1024] = {0};
    while(fgets(buffer, 1024, file) != NULL) 
        send(sockfd, buffer, strlen(buffer), 0);

    fclose(file);
    free(header);
    free(filepath);
}

char * getFileType(char *filename){
    size_t i = strlen(filename) - 1;
    while(filename[i--] != '.' && i > 0);
    if(filename[i+1] != '.' && i == 0){
        printf("Failed to parse requested file.\n");
        return "none";
    }
    char *filetype = (char *)filename + i + 2;
    if(strcmp(filetype, "map") == 0){
        char *temp = malloc(i + 1);
        strncpy(temp, filename, i + 1);
        temp[i + 1] = '\0';
        char *res = getFileType(temp);
        free(temp);
        return res;
    }
    if(strcmp(filetype, "html") == 0)
        return "text/html";
    else if(strcmp(filetype, "css") == 0)
        return "text/css";
    else if(strcmp(filetype, "js") == 0)
        return "application/javascript";
    else if(strcmp(filetype, "json") == 0)
        return "application/json";
    else if(strcmp(filetype, "png") == 0)
        return "image/png";
    else if(strcmp(filetype, "jpg") == 0)
        return "image/jpeg";
    else if(strcmp(filetype, "svg") == 0)
        return "image/svg+xml";
    else if(strcmp(filetype, "ico") == 0)
        return "image/x+icon";
    else
        return "text/plain";
}

void parseRequest(char *buffer){
    int i = 0, spaceCount = 0, methodLenCount = 0, fileLenCount = 0;
    while(spaceCount < 2 && buffer[i]!='\0'){
        if(buffer[i++] == ' ')
            spaceCount++;
        else if(spaceCount == 0)
            methodLenCount++;
        else fileLenCount++;
    }
    char *method = (char *)malloc(methodLenCount);
    char *filename = (char *)malloc(fileLenCount);

    if(sscanf(buffer, "%s %s", method, filename) == 2)
        printf("Method: %s\nFile: %s\n", method, filename);
    else
        printf("Failed to pharse the request.\n");
    
    char *filetype = concatString(getFileType(filename), "\r\n\r\n");
    
    if(strcmp(method, "GET") == 0){
        if(strcmp(filename, "/") == 0)
            sendResponse(client_sock, "/index.html", "text/html\r\n\r\n");
        else
            sendResponse(client_sock, filename, filetype);
    }

    free(method);
    free(filename);
    free(filetype);
}

char * getHeaderExtension(char *client_ip){
    char *headerOpt = "\r\nX-Forwarded-For: ";
    char *headerStr = concatString(headerOpt, client_ip);
    return headerStr;
}

int main() {
    socklen_t client_addr_size = sizeof(client_addr);
    char buffer[BUFFER_SIZE], client_ip[INET_ADDRSTRLEN];
    ssize_t bytes;
    int connectionCount = 0;
    char *testHttpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello World!";

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
        memset(buffer, 0, sizeof(buffer));

        // while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
        //     printf("(Client)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
        //     parseRequest(buffer);
        //     memset(buffer, 0, sizeof(buffer));
        // }

        int update_forwarded_header = 0;
        char *headerStr = getHeaderExtension(client_ip);
        while((bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0){
            if(update_forwarded_header == 0){
                char *newBuffer = (char *)malloc(strlen(buffer)+strlen(headerStr)+1);
                char *pch = strstr(buffer, SPLIT_STR);
                if(pch != NULL){
                    int index = pch - buffer;
                    strncpy(newBuffer, buffer, index);
                    strcpy(newBuffer + index, headerStr);
                    strcat(newBuffer, pch);
                    update_forwarded_header = 1;

                    printf("(Client)\nBUFFER bytes:%ld\n%s\n", strlen(newBuffer), newBuffer);
                    send(server_sock, newBuffer, strlen(newBuffer), 0);
                    free(headerStr);
                    free(newBuffer);
                }
                else printf("Pattern not found\n");
            }
            else{
                printf("(Client)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
                send(server_sock, buffer, bytes, 0);
            }
            memset(buffer, 0, sizeof(buffer));
        }

        while((bytes = recv(server_sock, buffer, BUFFER_SIZE, 0)) > 0){
            printf("(Server)\nBUFFER bytes:%ld\n%s\n", bytes, buffer);
            send(client_sock, buffer, bytes, 0);
            memset(buffer, 0, sizeof(buffer));
        }
        
        // send(client_sock, testHttpResponse, strlen(testHttpResponse), 0);
        printf("Closing client(IP:%s) socket...", client_ip);
        close(client_sock);
        printf("Done.\nClosing server socket...");
        close(server_sock);
        printf("Done.\n==============================\n");
    }
    close(proxy_sock);

    return 0;
}
