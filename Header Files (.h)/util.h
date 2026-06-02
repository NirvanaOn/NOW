#ifndef WORDSHELL_UTIL_H
#define WORDSHELL_UTIL_H

#include "common.h"

void trim_newline(char* s);
void clean_alpha_token(const char* token, char* clean, size_t clean_sz);
char* read_line_alloc(size_t max_len, const char* prompt);

#endif
