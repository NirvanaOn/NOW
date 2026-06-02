#ifndef WORDSHELL_COMMON_H
#define WORDSHELL_COMMON_H

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_WORD_LEN       64
#define MAX_WORDS          256
#define MAX_SHELLCODE_SIZE 65536
#define MAX_FILE_TEXT_SIZE (256 * 1024)
#define MAX_SENTENCE_SIZE  16384
#define MAX_HEX_INPUT      262144
#define MAX_LINE           512
#define MAX_NOISE_WORDS    128

#define PUNCT_PERIOD '.'
#define PUNCT_COMMA  ','
#define PUNCT_BANG   '!'
#define PUNCT_QUEST  '?'

extern const char* TOKEN_SEP;

typedef enum { NOISE_OFF = 0, NOISE_LOW = 1, NOISE_MEDIUM = 2, NOISE_HIGH = 3 } NoiseLevel;
typedef enum { CIPHER_RC4 = 0, CIPHER_AES = 1 } CipherMode;

typedef struct {
    size_t bytes_out;
    int codewords;
    int noise_skipped;
    int empty_skipped;
} DecryptStats;

#endif
