/* base.h */

/* ====================================================================
 * include all c standard lib & self define variable
 */

#ifndef BASE_H
#define BASE_H


#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>

#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

typedef u_int8_t u8;


#define min(a, b) ((a) < (b) ? (a) : (b))

void error(const char *msg);
void print_bytes(u8 *data, size_t len);
u8 * concat_uc_str(const u8 *arr1, const size_t len1, const u8 *arr2, const size_t len2);
int cmp_uc_str(const u8 *arr1, const u8 *arr2, const size_t len);
char * concatString(const char *str1, const char *str2);
void hexStringToBytes(const char *str, u8 *bytes, size_t length);
void get_random(u8 *random, size_t);
void get_ct_tag(u8 *ct, int *ct_len, u8 *tag, u8 *buffer, size_t len);
void insert_header_len(u8 *header, uint32_t len, int start, int end);

#endif