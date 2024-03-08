#include <server/serving.h>
#include <base/param.h>

void error(const char *msg){
    perror(msg);
    exit(1);
}

void print_bytes(uchar *data, size_t len){
    for (int i = 0; i < len; i++){
        // printf("%02x", data[i]);
        printf("%02x ", data[i]);
        if((i + 1) % 32 == 0)
            printf("\n");
    }
    printf("\n");
}

void get_ct_tag(uchar *ct, int *ct_len, uchar *tag, uchar *buffer, size_t len){
    *ct_len = len - TAG_SIZE;
    memcpy(ct, buffer, *ct_len);
    memcpy(tag, buffer + (len - TAG_SIZE), TAG_SIZE);
}

uchar * concat_uc_str(const uchar *arr1, const size_t len1, const uchar *arr2, const size_t len2) {
    uchar *result = malloc(len1 + len2);
    if (result == NULL)
        return NULL;
    memcpy(result, arr1, len1);
    memcpy(result + len1, arr2, len2);

    return result;
}

int cmp_uc_str(const uchar *arr1, const uchar *arr2, const size_t len){
    for(size_t i = 0; i < len; i++){
        if(arr1[i] != arr2[i])
            return 0;
    }
    return 1;
}

char * concatString(const char *str1, const char *str2){
    char *res = (char *)malloc(strlen(str1)+strlen(str2)+1);
    if(res == NULL) error("Failed to allocate memory.\n");
    strcpy(res, str1);
    strcat(res, str2);
    return res;
}

static uchar hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return 0;
}

void hexStringToBytes(const char *str, uchar *bytes, size_t length) {
    for (size_t i = 0; i < length; i += 2) {
        bytes[i / 2] = (hexCharToByte(str[i]) << 4) + hexCharToByte(str[i + 1]);
    }
}

void insert_header_len(uchar *header, uint32_t len, int start, int end){
    for(int i = end; i >= start; i--){
        header[i] = len & 0xFF;
        len >>= 8;
    }
}

ssize_t send_response(int sockfd, const uchar* data, size_t data_len) {
    size_t total_sent = 0;
    while (total_sent < data_len) {
        size_t to_send = min(BUFFER_SIZE, data_len - total_sent);
        ssize_t sent = send(sockfd, data + total_sent, to_send, 0);
        if (sent == -1) {
            fprintf(stderr, "%s\n", "Send error");
            break;
        }
        total_sent += sent;
    }
    return total_sent;
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

void read_file(uchar **data, uint64_t *len, const char *filename, int type){
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
            (*data)[i++] = (uchar)temp;

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

        uchar *temp = realloc(*data, (*len) * sizeof(uchar));
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