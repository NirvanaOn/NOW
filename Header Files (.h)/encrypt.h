#ifndef WORDSHELL_ENCRYPT_H
#define WORDSHELL_ENCRYPT_H

#include "common.h"

char* encrypt_shellcode(const unsigned char* sc, size_t len, NoiseLevel noise, size_t* out_len);
int roundtrip_self_test(const unsigned char* sc, size_t len, NoiseLevel noise);

#endif
