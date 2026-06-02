#ifndef WORDSHELL_DECRYPT_H
#define WORDSHELL_DECRYPT_H

#include "common.h"

size_t decrypt_shellcode(const char* text, unsigned char** output, int verbose, DecryptStats* stats);

#endif
