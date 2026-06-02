#ifndef WORDSHELL_WORD_MAPPING_H
#define WORDSHELL_WORD_MAPPING_H

#include "common.h"

extern const char* g_byte_to_word[256];
extern CipherMode g_cipher_mode;
extern int g_num_safe_connectors;

int init_word_mapping(const char* sentence, const char* password, CipherMode cipher);
int lookup_codeword(const char* word, unsigned char* out_byte);
void verify_full_byte_coverage(void);
const char* cipher_name(CipherMode c);
const char* pick_safe_connector(void);

#endif
