#ifndef WORDSHELL_RC4_H
#define WORDSHELL_RC4_H

#include <stddef.h>

typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_State;

void rc4_init(RC4_State* rc4, const unsigned char* key, size_t key_len);
unsigned char rc4_byte(RC4_State* rc4);

#endif
