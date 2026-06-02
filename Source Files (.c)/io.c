#include "io.h"
#include "util.h"

size_t parse_hex_string(const char* input, unsigned char* out, size_t out_max) {
    size_t out_len = 0;
    for (size_t i = 0; input[i] && out_len < out_max; ) {
        while (input[i] && isspace((unsigned char)input[i])) i++;
        if (!input[i]) break;
        if (input[i] == '0' && (input[i + 1] == 'x' || input[i + 1] == 'X')) i += 2;
        if (!isxdigit((unsigned char)input[i])) { i++; continue; }
        if (!isxdigit((unsigned char)input[i + 1])) { i++; continue; }
        unsigned int byte = 0;
        char pair[3] = { input[i], input[i + 1], '\0' };
        if (sscanf(pair, "%02x", &byte) == 1) {
            out[out_len++] = (unsigned char)byte;
            i += 2;
        }
        else {
            i++;
        }
    }
    return out_len;
}

int read_file_binary(const char* path, unsigned char** data, size_t* len) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (long)MAX_SHELLCODE_SIZE) { fclose(f); return 0; }
    *data = (unsigned char*)malloc((size_t)sz);
    if (!*data) { fclose(f); return 0; }
    if (fread(*data, 1, (size_t)sz, f) != (size_t)sz) {
        free(*data); fclose(f); return 0;
    }
    fclose(f);
    *len = (size_t)sz;
    return 1;
}

int read_file_text(const char* path, char** text) {
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char* buf = (char*)malloc(MAX_FILE_TEXT_SIZE);
    if (!buf) { fclose(f); return 0; }
    size_t n = fread(buf, 1, MAX_FILE_TEXT_SIZE - 1, f);
    buf[n] = '\0';
    if (n >= MAX_FILE_TEXT_SIZE - 1) {
        int extra = fgetc(f);
        if (extra != EOF)
            printf("[!] Warning: file truncated at %d characters.\n", MAX_FILE_TEXT_SIZE - 1);
    }
    fclose(f);
    *text = buf;
    return 1;
}

int write_text_file(const char* path, const char* text) {
    FILE* f = fopen(path, "w");
    if (!f) return 0;
    fputs(text, f);
    fclose(f);
    return 1;
}

void save_decrypted_outputs(unsigned char* sc, size_t len, const char* prefix) {
    char path[MAX_LINE];
    snprintf(path, sizeof(path), "%s.bin", prefix);
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(sc, 1, len, f); fclose(f); printf("  [+] %s\n", path); }

    snprintf(path, sizeof(path), "%s.c", prefix);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "unsigned char shellcode[] = {\n    ");
        for (size_t i = 0; i < len; i++) {
            fprintf(f, "0x%02X%s", sc[i], (i + 1 < len) ? ", " : "");
            if ((i + 1) % 12 == 0 && i + 1 < len) fprintf(f, "\n    ");
        }
        fprintf(f, "\n};\nunsigned int shellcode_len = %zu;\n", len);
        fclose(f);
        printf("  [+] %s\n", path);
    }

    snprintf(path, sizeof(path), "%s.hex", prefix);
    f = fopen(path, "w");
    if (f) {
        for (size_t i = 0; i < len; i++) fprintf(f, "%02X", sc[i]);
        fprintf(f, "\n");
        fclose(f);
        printf("  [+] %s\n", path);
    }
}

char* read_multiline_input(const char* prompt) {
    char* buf = (char*)calloc(1, MAX_FILE_TEXT_SIZE);
    if (!buf) return NULL;
    if (prompt && prompt[0]) printf("%s", prompt);
    char line[1024];
    int empty = 0;
    size_t total = 0;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\0' || (line[0] == '\n' && line[1] == '\0') ||
            (line[0] == '\r' && (line[1] == '\n' || line[1] == '\0'))) {
            if (++empty >= 2) break;
            continue;
        }
        empty = 0;
        size_t l = strlen(line);
        if (total + l + 1 >= MAX_FILE_TEXT_SIZE) {
            printf("[!] Warning: input truncated at %d characters.\n", MAX_FILE_TEXT_SIZE - 1);
            break;
        }
        memcpy(buf + total, line, l);
        total += l;
        buf[total] = '\0';
    }
    return buf;
}

char* read_multiline_stdin(void) {
    return read_multiline_input("Paste encrypted text (empty line twice to finish):\n");
}
