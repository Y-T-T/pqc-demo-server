#include <base/base.h>

void error(const char *msg){
    perror(msg);
    exit(1);
}

void print_bytes(u8 *data, size_t len){
    for (int i = 0; i < len; i++){
        // printf("%02x", data[i]);
        printf("%02x ", data[i]);
        if((i + 1) % 32 == 0)
            printf("\n");
    }
    if(len % 32 != 0) printf("\n");
}

u8 * concat_uc_str(const u8 *arr1, const size_t len1, const u8 *arr2, const size_t len2) {
    u8 *result = malloc(len1 + len2);
    if (result == NULL)
        return NULL;
    memcpy(result, arr1, len1);
    memcpy(result + len1, arr2, len2);

    return result;
}

int cmp_uc_str(const u8 *arr1, const u8 *arr2, const size_t len){
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

static u8 hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return 0;
}

void hexStringToBytes(const char *str, u8 *bytes, size_t length) {
    for (size_t i = 0; i < length; i += 2) {
        bytes[i / 2] = (hexCharToByte(str[i]) << 4) + hexCharToByte(str[i + 1]);
    }
}

void get_random(u8 *random, size_t bytes){
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        return;
    }
    if (read(fd, random, bytes) != bytes) {
        perror("Failed to read random data");
        close(fd);
        return;
    }
    close(fd);
}

void get_ct_tag(u8 *ct, int *ct_len, u8 *tag, u8 *buffer, size_t len){
    *ct_len = len - TAG_SIZE;
    memcpy(ct, buffer, *ct_len);
    memcpy(tag, buffer + (len - TAG_SIZE), TAG_SIZE);
}

void insert_header_len(u8 *header, uint32_t len, int start, int end){
    for(int i = end; i >= start; i--){
        header[i] = len & 0xFF;
        len >>= 8;
    }
}

char * load_setting(char *pattern){
    char line[255];
    char key[255], value[255];
    char *res = malloc(255 * sizeof(char));
    char *prefix = "../src/cert/";
    memset(res, 0, 255);
    FILE *file = fopen("../setting.conf", "r");
    if (file == NULL)
        printf("Error opening file\n");

    while (fgets(line, sizeof(line), file) != NULL) {
        if (line[0] == '#' || strlen(line) <= 1) continue;

        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
            if(strcmp(key, pattern) == 0){
                // printf("Key: %s, Value: %s\n", key, value);
                strncat(res, prefix, strlen(prefix));
                strncat(res, value, strlen(value));
                break;
            }
        }
    }

    fclose(file);
    if(strlen(res) == 0){
        fprintf(stderr, "setting.conf error: pattern [%s] not found or value is empty.\n", pattern);
        return NULL;
    }
    return res;
}