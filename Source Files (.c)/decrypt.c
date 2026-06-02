#include "decrypt.h"
#include "word_mapping.h"
#include "util.h"

size_t decrypt_shellcode(const char* text, unsigned char** output, int verbose, DecryptStats* stats) {
    if (!text || !output || !stats) return 0;

    *output = (unsigned char*)malloc(MAX_SHELLCODE_SIZE);
    if (!*output) return 0;
    memset(stats, 0, sizeof(*stats));

    char* copy = _strdup(text);
    if (!copy) { free(*output); *output = NULL; return 0; }

    size_t out_pos = 0;
    char* tok = strtok(copy, TOKEN_SEP);
    int truncated = 0;

    while (tok) {
        if (out_pos >= MAX_SHELLCODE_SIZE) {
            truncated = 1;
            break;
        }

        char clean[MAX_WORD_LEN];
        clean_alpha_token(tok, clean, sizeof(clean));

        if (clean[0] == '\0') {
            stats->empty_skipped++;
            tok = strtok(NULL, TOKEN_SEP);
            continue;
        }

        unsigned char byte_val;
        if (lookup_codeword(clean, &byte_val)) {
            (*output)[out_pos++] = byte_val;
            stats->codewords++;
            if (verbose && out_pos <= 32)
                printf("  [%3zu] %-20s -> 0x%02X\n", out_pos, clean, byte_val);
        }
        else {
            stats->noise_skipped++;
            if (verbose && stats->noise_skipped <= 20)
                printf("  [noise] %s\n", clean);
        }

        tok = strtok(NULL, TOKEN_SEP);
    }

    if (truncated)
        printf("[!] Warning: decrypted output truncated at %d bytes.\n", MAX_SHELLCODE_SIZE);

    stats->bytes_out = out_pos;
    free(copy);
    return out_pos;
}
