#include "rc4.h"

void rc4_init(RC4_State* rc4, const unsigned char* key, size_t key_len) {
    for (int i = 0; i < 256; i++) rc4->S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + rc4->S[i] + key[i % key_len]) % 256;
        unsigned char t = rc4->S[i];
        rc4->S[i] = rc4->S[j];
        rc4->S[j] = t;
    }
    rc4->i = rc4->j = 0;
}

unsigned char rc4_byte(RC4_State* rc4) {
    rc4->i = (rc4->i + 1) % 256;
    rc4->j = (rc4->j + rc4->S[rc4->i]) % 256;
    unsigned char t = rc4->S[rc4->i];
    rc4->S[rc4->i] = rc4->S[rc4->j];
    rc4->S[rc4->j] = t;
    return rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j]) % 256];
}
