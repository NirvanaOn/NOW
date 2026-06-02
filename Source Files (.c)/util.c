#include "util.h"

const char* TOKEN_SEP = " \t\n\r,.;:!?()[]{}\"'-";

void trim_newline(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

void clean_alpha_token(const char* token, char* clean, size_t clean_sz) {
    size_t j = 0;
    for (size_t i = 0; token[i] && j + 1 < clean_sz; i++) {
        if (isalpha((unsigned char)token[i]))
            clean[j++] = (char)tolower((unsigned char)token[i]);
    }
    clean[j] = '\0';
}

char* read_line_alloc(size_t max_len, const char* prompt) {
    if (prompt && prompt[0]) printf("%s", prompt);
    char* buf = (char*)malloc(max_len);
    if (!buf) return NULL;
    if (!fgets(buf, (int)max_len, stdin)) { free(buf); return NULL; }
    trim_newline(buf);
    return buf;
}
