#ifndef WORDSHELL_IO_H
#define WORDSHELL_IO_H

#include "common.h"

size_t parse_hex_string(const char* input, unsigned char* out, size_t out_max);
int read_file_binary(const char* path, unsigned char** data, size_t* len);
int read_file_text(const char* path, char** text);
int write_text_file(const char* path, const char* text);
void save_decrypted_outputs(unsigned char* sc, size_t len, const char* prefix);
char* read_multiline_input(const char* prompt);
char* read_multiline_stdin(void);

#endif
