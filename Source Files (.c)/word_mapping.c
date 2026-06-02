#include "word_mapping.h"
#include "rc4.h"
#include "util.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#ifndef CRYPT_MODE_CTR
#define CRYPT_MODE_CTR 4
#endif
#endif

static char g_words[MAX_WORDS][MAX_WORD_LEN];
const char* g_byte_to_word[256];
static unsigned char g_shuffled_opcodes[256];

static char g_lookup_words[256][MAX_WORD_LEN];
static unsigned char g_lookup_bytes[256];
static int g_lookup_count = 0;

CipherMode g_cipher_mode = CIPHER_RC4;
int g_num_safe_connectors = 0;

static const char* natural_words[] = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he",
    "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an",
    "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which",
    "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think", "also",
    "back", "after", "use", "two", "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "water", "sun", "moon", "star", "sky", "cloud", "rain", "wind", "snow", "ice", "fire", "earth",
    "tree", "flower", "grass", "leaf", "plant", "bird", "fish", "animal", "cat", "dog", "horse", "cow", "pig", "chicken", "duck", "goose",
    "rabbit", "mouse", "house", "home", "room", "door", "window", "wall", "floor", "ceiling", "roof", "garden", "happy", "sad", "angry", "calm",
    "peace", "love", "hate", "joy", "fear", "hope", "dream", "sleep", "wake", "night", "day", "morning", "evening", "noon", "midnight", "dawn",
    "red", "blue", "green", "yellow", "black", "white", "purple", "orange", "pink", "brown", "big", "small", "large", "tiny", "huge", "little",
    "fast", "slow", "quick", "rapid", "steady", "wild", "tame", "soft", "hard", "hot", "cold", "warm", "cool", "dry", "wet", "clean",
    "dirty", "old", "young", "new", "ancient", "modern", "early", "late", "final", "first", "last", "next", "same", "different", "simple", "complex",
    "easy", "real", "fake", "true", "false", "right", "wrong", "correct", "proper", "public", "private", "open", "closed", "free", "busy",
    "full", "empty", "complete", "total", "whole", "partial", "broken", "fixed", "beautiful", "ugly", "pretty", "lovely", "wonderful", "terrible", "excellent", "perfect"
};
static const int num_natural_words = (int)(sizeof(natural_words) / sizeof(natural_words[0]));

static const char* connector_candidates[] = {
    "however", "therefore", "although", "whereas", "moreover", "furthermore", "nevertheless",
    "meanwhile", "indeed", "basically", "obviously", "certainly", "probably", "perhaps",
    "specifically", "particularly", "especially", "importantly", "notably", "initially",
    "originally", "previously", "subsequently", "recently", "currently", "eventually",
    "immediately", "indirectly", "similarly", "differently", "otherwise", "anyhow",
    "elsewhere", "everywhere", "somewhere", "anywhere", "nowhere", "likewise",
    "nonetheless", "regardless", "consequently", "accordingly", "alternatively",
    "additionally", "equally", "namely", "chiefly", "mainly", "mostly", "partly"
};
static const int num_connector_candidates = (int)(sizeof(connector_candidates) / sizeof(connector_candidates[0]));

static const char* g_safe_connectors[MAX_NOISE_WORDS];

static int word_in_pool(const char* word, int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(g_words[i], word) == 0) return 1;
    }
    return 0;
}

static int extract_unique_words(const char* sentence) {
    char* copy = _strdup(sentence);
    if (!copy) return 0;

    int count = 0;
    char* tok = strtok(copy, TOKEN_SEP);
    while (tok && count < MAX_WORDS) {
        char clean[MAX_WORD_LEN];
        clean_alpha_token(tok, clean, sizeof(clean));
        if (clean[0] != '\0' && !word_in_pool(clean, count)) {
            strcpy(g_words[count], clean);
            count++;
        }
        tok = strtok(NULL, TOKEN_SEP);
    }
    int truncated = (tok != NULL);
    free(copy);
    if (truncated)
        printf("[!] Warning: sentence has more than %d unique words; extras ignored.\n", MAX_WORDS);
    return count;
}

static void add_natural_padding(int current) {
    int idx = 0;
    for (int i = current; i < MAX_WORDS; i++) {
        char candidate[MAX_WORD_LEN];
        int attempts = 0;
        for (;;) {
            strcpy(candidate, natural_words[idx % num_natural_words]);
            idx++;
            if (!word_in_pool(candidate, i)) break;
            if (++attempts > num_natural_words + 64) {
                snprintf(candidate, sizeof(candidate), "pad%03d", i);
                if (!word_in_pool(candidate, i)) break;
            }
        }
        strcpy(g_words[i], candidate);
    }
}

static void generate_shuffled_opcodes_rc4(const char* password) {
    for (int i = 0; i < 256; i++) g_shuffled_opcodes[i] = (unsigned char)i;
    RC4_State rc4;
    rc4_init(&rc4, (const unsigned char*)password, strlen(password));
    for (int i = 255; i > 0; i--) {
        unsigned char ks = rc4_byte(&rc4);
        int j = ks % (i + 1);
        unsigned char t = g_shuffled_opcodes[i];
        g_shuffled_opcodes[i] = g_shuffled_opcodes[j];
        g_shuffled_opcodes[j] = t;
    }
}

#ifdef _WIN32
#define AES_BLOCK_SIZE 16

static DWORD g_last_aes_error = 0;

static int aes_ctr_keystream(const char* password, unsigned char* output, int bytes_needed) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    int ok = 0;
    g_last_aes_error = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        g_last_aes_error = GetLastError();
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            g_last_aes_error = GetLastError();
            return 0;
        }
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        g_last_aes_error = GetLastError();
        goto cleanup;
    }
    if (!CryptHashData(hHash, (const BYTE*)password, (DWORD)strlen(password), 0)) {
        g_last_aes_error = GetLastError();
        goto cleanup;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        g_last_aes_error = GetLastError();
        goto cleanup;
    }

    {
        DWORD mode = CRYPT_MODE_CTR;
        BYTE counter[16] = { 0 };

        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
            g_last_aes_error = GetLastError();
            goto cleanup;
        }
        if (!CryptSetKeyParam(hKey, KP_IV, counter, 0)) {
            g_last_aes_error = GetLastError();
            goto cleanup;
        }

        DWORD data_len = (DWORD)bytes_needed;
        DWORD buf_size = data_len + AES_BLOCK_SIZE;
        BYTE* buffer = (BYTE*)calloc(1, buf_size);
        if (!buffer) {
            g_last_aes_error = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }

        if (CryptEncrypt(hKey, 0, TRUE, 0, buffer, &data_len, buf_size)) {
            memcpy(output, buffer, (size_t)bytes_needed);
            ok = 1;
        }
        else {
            g_last_aes_error = GetLastError();
        }
        free(buffer);
    }

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ok;
}

static int generate_shuffled_opcodes_aes(const char* password) {
    unsigned char keystream[256];
    if (!aes_ctr_keystream(password, keystream, 256))
        return 0;
    for (int i = 0; i < 256; i++) g_shuffled_opcodes[i] = (unsigned char)i;
    for (int i = 255; i > 0; i--) {
        int j = keystream[255 - i] % (i + 1);
        unsigned char t = g_shuffled_opcodes[i];
        g_shuffled_opcodes[i] = g_shuffled_opcodes[j];
        g_shuffled_opcodes[j] = t;
    }
    return 1;
}
#else
static int generate_shuffled_opcodes_aes(const char* password) {
    (void)password;
    return 0;
}
#endif

static int generate_shuffled_opcodes(const char* password, CipherMode cipher) {
    if (cipher == CIPHER_AES)
        return generate_shuffled_opcodes_aes(password);
    generate_shuffled_opcodes_rc4(password);
    return 1;
}

const char* cipher_name(CipherMode c) {
    return (c == CIPHER_AES) ? "AES-256-CTR (SHA-256 key)" : "RC4";
}

static void create_byte_to_word_map(void) {
    for (int i = 0; i < 256; i++) g_byte_to_word[i] = NULL;
    for (int pos = 0; pos < 256; pos++) {
        unsigned char b = g_shuffled_opcodes[pos];
        g_byte_to_word[b] = g_words[pos];
    }
}

static void build_reverse_lookup(void) {
    g_lookup_count = 0;
    for (int pos = 0; pos < 256; pos++) {
        strcpy(g_lookup_words[g_lookup_count], g_words[pos]);
        g_lookup_bytes[g_lookup_count] = g_shuffled_opcodes[pos];
        g_lookup_count++;
    }
}

int lookup_codeword(const char* word, unsigned char* out_byte) {
    if (!word || !word[0]) return 0;
    for (int i = 0; i < g_lookup_count; i++) {
        if (strcmp(word, g_lookup_words[i]) == 0) {
            *out_byte = g_lookup_bytes[i];
            return 1;
        }
    }
    return 0;
}

static void build_safe_noise_lists(void) {
    g_num_safe_connectors = 0;
    for (int i = 0; i < num_connector_candidates && g_num_safe_connectors < MAX_NOISE_WORDS; i++) {
        unsigned char dummy;
        if (!lookup_codeword(connector_candidates[i], &dummy))
            g_safe_connectors[g_num_safe_connectors++] = connector_candidates[i];
    }
}

int init_word_mapping(const char* sentence, const char* password, CipherMode cipher) {
    int count = extract_unique_words(sentence);
    if (count <= 0) return 0;
    if (count < MAX_WORDS) add_natural_padding(count);
    if (strlen(password) < 4) return 0;
    g_cipher_mode = cipher;
    if (!generate_shuffled_opcodes(password, cipher)) {
        if (cipher == CIPHER_AES) {
#ifdef _WIN32
            printf("ERROR: AES-256-CTR keystream failed (Win32 error %lu).\n",
                (unsigned long)g_last_aes_error);
#else
            printf("ERROR: AES-256-CTR is Windows-only.\n");
#endif
        }
        return 0;
    }
    create_byte_to_word_map();
    build_reverse_lookup();
    build_safe_noise_lists();
    return 1;
}

void verify_full_byte_coverage(void) {
    int missing = 0;
    for (int b = 0; b < 256; b++) {
        if (!g_byte_to_word[b]) missing++;
    }
    if (missing > 0)
        printf("[!] Warning: %d byte values have no codeword mapping.\n", missing);
}

const char* pick_safe_connector(void) {
    if (g_num_safe_connectors <= 0) return NULL;
    return g_safe_connectors[rand() % g_num_safe_connectors];
}
