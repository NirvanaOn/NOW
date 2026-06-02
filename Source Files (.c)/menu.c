#include "menu.h"
#include "encrypt.h"
#include "decrypt.h"
#include "word_mapping.h"
#include "io.h"
#include "platform.h"
#include "util.h"

CipherMode ask_cipher_mode(void) {
    printf("\nStream cipher for byte shuffle (must match on decrypt):\n");
    printf("  1 = RC4          (RC4ENC / RC4DEC compatible)\n");
    printf("  2 = AES-256-CTR  (AESENC / AESDEC compatible, Windows)\n");
    printf("Choice [1]: ");
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return CIPHER_RC4;
    trim_newline(buf);
    if (buf[0] == '2') {
#ifndef _WIN32
        printf("[!] AES is Windows-only on this platform.\n");
        return CIPHER_RC4;
#else
        return CIPHER_AES;
#endif
    }
    return CIPHER_RC4;
}

NoiseLevel ask_noise_level(void) {
    printf("\nOutput style:\n");
    printf("  0 = Plain words only (RC4ENC/RC4DEC compatible)\n");
    printf("  1 = Natural prose (light)  - longer sentences, fewer fillers\n");
    printf("  2 = Natural prose (medium) - balanced paragraphs [default]\n");
    printf("  3 = Natural prose (heavy)  - more connectors and breaks\n");
    printf("Choice [2]: ");
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return NOISE_MEDIUM;
    trim_newline(buf);
    if (buf[0] == '\0') return NOISE_MEDIUM;
    int v = atoi(buf);
    if (v < 0) v = 0;
    if (v > 3) v = 3;
    return (NoiseLevel)v;
}

void action_encrypt(void) {
    char password[256];
    char in_path[MAX_LINE] = { 0 };
    char out_path[MAX_LINE] = "encrypted_words.txt";

    printf("\n--- ENCRYPT SHELLCODE TO WORDS ---\n");
    char* sentence = read_multiline_input(
        "Secret sentence (paste text, blank line twice to finish):\n> ");
    if (!sentence) return;

    if (sentence[0] == '\0') {
        free(sentence);
        sentence = _strdup("the quick brown fox jumps over the lazy dog");
        if (!sentence) return;
        printf("(default sentence)\n");
    }

    printf("Password (min 4 chars): ");
    if (!fgets(password, sizeof(password), stdin)) { free(sentence); return; }
    trim_newline(password);
    while (strlen(password) < 4) {
        printf("Too short. Password: ");
        if (!fgets(password, sizeof(password), stdin)) { free(sentence); return; }
        trim_newline(password);
    }

    CipherMode cipher = ask_cipher_mode();

    if (!init_word_mapping(sentence, password, cipher)) {
        printf("ERROR: Mapping failed.\n");
        free(sentence);
        return;
    }
    free(sentence);
    verify_full_byte_coverage();
    printf("Stream: %s | Word pool: %d | Safe connectors: %d\n",
        cipher_name(g_cipher_mode), MAX_WORDS, g_num_safe_connectors);

    NoiseLevel noise = ask_noise_level();
    srand((unsigned)time(NULL) ^ (unsigned)strlen(password));

    printf("\nShellcode input: 1=Hex  2=Binary .bin\nChoice [1]: ");
    char mode[16];
    if (!fgets(mode, sizeof(mode), stdin)) return;
    trim_newline(mode);

    unsigned char* sc = NULL;
    size_t sc_len = 0;

    if (mode[0] == '2') {
        printf("Path to .bin: ");
        if (!fgets(in_path, sizeof(in_path), stdin)) return;
        trim_newline(in_path);
        if (!read_file_binary(in_path, &sc, &sc_len)) {
            printf("ERROR: Cannot read file.\n");
            return;
        }
    }
    else {
        char* hex_buf = read_line_alloc(MAX_HEX_INPUT, "Hex bytes: ");
        if (!hex_buf) return;
        sc = (unsigned char*)malloc(MAX_SHELLCODE_SIZE);
        if (!sc) { free(hex_buf); return; }
        sc_len = parse_hex_string(hex_buf, sc, MAX_SHELLCODE_SIZE);
        free(hex_buf);
        if (sc_len == 0) { printf("ERROR: No valid hex.\n"); free(sc); return; }
    }

    printf("Input shellcode: %zu bytes\n", sc_len);

    if (!roundtrip_self_test(sc, sc_len, noise)) {
        printf("ERROR: Internal round-trip test failed. Not saving output.\n");
        free(sc);
        return;
    }
    printf("[+] Round-trip self-test passed (%zu bytes verified).\n", sc_len);

    size_t enc_len = 0;
    char* encrypted = encrypt_shellcode(sc, sc_len, noise, &enc_len);
    free(sc);
    if (!encrypted) {
        printf("ERROR: Encryption failed.\n");
        return;
    }

    printf("\nOutput file [%s]: ", out_path);
    char opath[MAX_LINE];
    if (fgets(opath, sizeof(opath), stdin)) {
        trim_newline(opath);
        if (opath[0]) strcpy(out_path, opath);
    }

    if (write_text_file(out_path, encrypted)) {
        printf("[+] Saved: %s (%zu chars)\n", out_path, enc_len);
        if (noise == NOISE_OFF)
            printf("[+] Format: plain word list (RC4 compatible)\n");
        else
            printf("[+] Format: natural prose (level %d)\n", (int)noise);
    }
    else {
        printf("ERROR: Could not write file: %s\n", out_path);
    }

    printf("\n--- PREVIEW ---\n%.*s%s\n", (int)(enc_len > 800 ? 800 : enc_len), encrypted, enc_len > 800 ? "..." : "");
    free(encrypted);
}

void action_decrypt(void) {
    char password[256];
    char* text = NULL;
    char in_path[MAX_LINE] = { 0 };
    char out_prefix[MAX_LINE] = "decrypted_shellcode";

    printf("\n--- DECRYPT WORDS TO SHELLCODE ---\n");
    char* sentence = read_multiline_input(
        "Secret sentence (paste text, blank line twice to finish):\n> ");
    if (!sentence) return;
    if (sentence[0] == '\0') { printf("ERROR: Sentence required.\n"); free(sentence); return; }

    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin)) { free(sentence); return; }
    trim_newline(password);
    if (strlen(password) < 4) { printf("ERROR: Password too short.\n"); free(sentence); return; }

    CipherMode cipher = ask_cipher_mode();

    if (!init_word_mapping(sentence, password, cipher)) {
        printf("ERROR: Mapping failed.\n");
        free(sentence);
        return;
    }
    free(sentence);
    printf("Stream: %s\n", cipher_name(g_cipher_mode));

    printf("\nCiphertext: 1=Paste  2=File\nChoice [1]: ");
    char mode[16];
    if (!fgets(mode, sizeof(mode), stdin)) return;
    trim_newline(mode);

    if (mode[0] == '2') {
        printf("File path: ");
        if (!fgets(in_path, sizeof(in_path), stdin)) return;
        trim_newline(in_path);
        if (!read_file_text(in_path, &text)) { printf("ERROR: Cannot read file.\n"); return; }
    }
    else {
        text = read_multiline_stdin();
    }

    if (!text || !text[0]) { printf("ERROR: Empty input.\n"); free(text); return; }

    printf("Verbose log? (y/N): ");
    char vb[16];
    int verbose = 0;
    if (fgets(vb, sizeof(vb), stdin) && (vb[0] == 'y' || vb[0] == 'Y')) verbose = 1;

    unsigned char* decrypted = NULL;
    DecryptStats stats;
    size_t dlen = decrypt_shellcode(text, &decrypted, verbose, &stats);
    free(text);

    if (dlen == 0) {
        printf("\nERROR: No bytes decoded.\n");
        free(decrypted);
        return;
    }

    printf("\n[+] Decrypted %zu bytes from %d codewords\n", dlen, stats.codewords);
    printf("    Noise tokens skipped: %d\n", stats.noise_skipped);

    if (stats.codewords != (int)dlen)
        printf("[!] Warning: codeword count != byte count (unexpected).\n");

    printf("Hex (first 64 bytes): ");
    for (size_t i = 0; i < dlen && i < 64; i++) printf("%02X ", decrypted[i]);
    if (dlen > 64) printf("...");
    printf("\n");

    printf("\nOutput prefix [%s]: ", out_prefix);
    char pref[MAX_LINE];
    if (fgets(pref, sizeof(pref), stdin)) {
        trim_newline(pref);
        if (pref[0]) strcpy(out_prefix, pref);
    }

    printf("\nSaving:\n");
    save_decrypted_outputs(decrypted, dlen, out_prefix);

    maybe_execute_shellcode(decrypted, dlen);
    free(decrypted);
}

void print_help(void) {
    printf("\n======== NØW v2.2 ========\n");
    printf("Each shellcode byte (0x00-0xFF) maps to one codeword.\n");
    printf("\nStream cipher (shuffles which word = which byte):\n");
    printf("  RC4          -> same as RC4ENC.exe / RC4DEC.exe\n");
    printf("  AES-256-CTR  -> same as AESENC.exe / AESDEC.exe (Windows)\n");
    printf("Use the SAME stream + sentence + password to decrypt.\n");
    printf("\nOutput style 0 = plain words (closest to RC4ENC when using RC4).\n");
    printf("Styles 1-3 = natural prose (. , ! ? only).\n");
    printf("\nNote: Word pool padding differs from RC4ENC/AESENC (extended word list).\n");
    printf("Use NØW for both encrypt and decrypt for reliable results.\n");
    printf("================================\n");
}

void print_banner(void) {
    printf("\n  NØW v2.2 - Word-Based Shellcode Tool\n");
    printf("  RC4 or AES stream | Natural prose output\n\n");
}
