#include <base/serving.h>

static void clear_pool(BUFFER_POOL *pool, const size_t pool_idx)
{
    for(int i = 0; i < pool_idx; i++){
        memset(pool[i].buffer, 0, MAX_POOL_BUFFER_SIZE);
        pool[i].length = 0;
    }    
}

size_t send_msg(int sockfd, BUFFER_POOL *pool, const size_t pool_idx){
    for(int i = 0; i < pool_idx; i++){
        send(sockfd, pool[i].buffer, pool[i].length, 0);
        printf("Send msg (length:%zd):\n", pool[i].length);
        if(pool[i].length < MAX_PRINT_BYTES)
            print_bytes(pool[i].buffer, pool[i].length);
        else printf("Omitted... (too long to print)\n");
        printf("\n");
    }
    return 1;
}

ssize_t send_response(int sockfd, const u8* data, size_t data_len) {
    size_t to_send;
    ssize_t sent, total_sent = 0;
    while (total_sent < data_len) {
        to_send = min(BUFFER_SIZE, data_len - total_sent);
        sent = send(sockfd, data + total_sent, to_send, 0);
        if (sent == -1) {
            fprintf(stderr, "%s\n", "Send error");
            break;
        }
        total_sent += sent;
    }
    return total_sent;
}

size_t recv_msg(int sockfd, BUFFER_POOL *pool, size_t *pool_idx){
    
    clear_pool(pool, *pool_idx);
    *pool_idx = 0;
    ssize_t bytes;

    while((bytes = recv(sockfd, pool[*pool_idx].buffer, BUFFER_SIZE, 0)) > 0){
        printf("Receive msg (length:%zd):\n", bytes);
        if(bytes < MAX_PRINT_BYTES)
            print_bytes(pool[*pool_idx].buffer, bytes);
        else printf("Omitted... (too long to print)\n");
        printf("\n");
        pool[*pool_idx].length = bytes;
        (*pool_idx)++;
    }
    return 1;
}

char * getHeaderExtension(const char *client_ip){
    char *headerOpt = "\r\nX-Forwarded-For: ";
    char *headerStr = concatString(headerOpt, client_ip);
    return headerStr;
}

char * insertXFor(char *buffer, const char *client_ip){
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

size_t update_forwarded_header(BUFFER_POOL *pool, const size_t pool_idx, const char *ip){
    char *buffer = NULL;
    for(int i = 0; i < pool_idx; i++){
        buffer = insertXFor((char *)pool[i].buffer, ip);
        memset(pool[i].buffer, 0, pool[i].length);
        pool[i].length = strlen(buffer);
        memcpy(pool[i].buffer, buffer, strlen(buffer));
        free(buffer);
        buffer = NULL;
    }
    return 1;
}

void send_backend_response(int sockfd, const char *filename, const char *filetype){
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

void read_file(u8 **data, uint64_t *len, const char *filename, int type){
    FILE* file = NULL;
    if(type == 1){
        file = fopen(filename, "r");
        if (file == NULL) {
            perror("Unable to open file");
            return;
        }

        uint32_t temp;
        int i = 0;

        while (fscanf(file, "%x", &temp) == 1)
            (*data)[i++] = (u8)temp;

        *len = i;

        printf("file len:%llu\n", *len);
    }
    else if(type == 0){
        file = fopen(filename, "rb");
        if (file == NULL) {
            perror("Unable to open file");
            return;
        }
        fseek(file, 0, SEEK_END);
        *len = ftell(file);
        fseek(file, 0, SEEK_SET);

        int i = 0;

        u8 *temp = realloc(*data, (*len) * sizeof(u8));
        if(temp == NULL)
            fputs("Memory error", stderr);
        else
            *data = temp;
            fread(*data, 1, *len, file);

        printf("file len:%llu\n", *len);
    }

    fclose(file);
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

void parseRequest(int sockfd, char *buffer){
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
            send_backend_response(sockfd, "/index.html", "text/html\r\n\r\n");
        else
            send_backend_response(sockfd, filename, filetype);
    }

    free(method);
    free(filename);
    free(filetype);
}