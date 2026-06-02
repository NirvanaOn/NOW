#include "encrypt.h"
#include "decrypt.h"
#include "word_mapping.h"

typedef struct {
    int min_sentence;
    int max_sentence;
    int min_clause;
    int max_clause;
    int opener_pct;
    int comma_bridge_pct;
    int mid_bridge_pct;
    int paragraph_every;
} ProseParams;

static int append_piece(char** buf, size_t* cap, size_t* len, const char* piece) {
    size_t plen = strlen(piece);
    size_t need = *len + plen + 2;
    if (need >= *cap) {
        *cap = need + 8192;
        char* nb = (char*)realloc(*buf, *cap);
        if (!nb) return 0;
        *buf = nb;
    }
    if (*len > 0) {
        (*buf)[(*len)++] = ' ';
        (*buf)[(*len)] = '\0';
    }
    memcpy(*buf + *len, piece, plen + 1);
    *len += plen;
    return 1;
}

static int append_raw(char** buf, size_t* cap, size_t* len, const char* raw) {
    size_t rlen = strlen(raw);
    size_t need = *len + rlen + 1;
    if (need >= *cap) {
        *cap = need + 4096;
        char* nb = (char*)realloc(*buf, *cap);
        if (!nb) return 0;
        *buf = nb;
    }
    memcpy(*buf + *len, raw, rlen + 1);
    *len += rlen;
    return 1;
}

static char last_char(const char* buf, size_t len) {
    return (len > 0) ? buf[len - 1] : '\0';
}

static int append_punct(char** buf, size_t* cap, size_t* len, char p) {
    if (*len == 0) return 1;
    char prev = last_char(*buf, *len);

    if (p == PUNCT_COMMA) {
        if (prev == PUNCT_COMMA || prev == PUNCT_PERIOD || prev == PUNCT_BANG || prev == PUNCT_QUEST)
            return 1;
    }
    else if (p == PUNCT_PERIOD || p == PUNCT_BANG || p == PUNCT_QUEST) {
        if (prev == PUNCT_COMMA) {
            (*buf)[*len - 1] = p;
            return 1;
        }
        if (prev == PUNCT_PERIOD || prev == PUNCT_BANG || prev == PUNCT_QUEST)
            return 1;
    }

    char s[2] = { p, '\0' };
    return append_raw(buf, cap, len, s);
}

static int append_word_form(char** buf, size_t* cap, size_t* len, const char* word, int capitalize) {
    char tmp[MAX_WORD_LEN];
    if (!word || !word[0]) return 1;
    if (capitalize) {
        tmp[0] = (char)toupper((unsigned char)word[0]);
        strcpy(tmp + 1, word + 1);
        return append_piece(buf, cap, len, tmp);
    }
    return append_piece(buf, cap, len, word);
}

static int append_connector(char** buf, size_t* cap, size_t* len, int capitalize) {
    const char* c = pick_safe_connector();
    if (!c) return 1;
    return append_word_form(buf, cap, len, c, capitalize);
}

#define PROSE_FAIL() do { free(out); return NULL; } while (0)

static void prose_params_for_level(NoiseLevel level, ProseParams* p) {
    memset(p, 0, sizeof(*p));
    switch (level) {
    case NOISE_LOW:
        p->min_sentence = 10; p->max_sentence = 18;
        p->min_clause = 4;    p->max_clause = 7;
        p->opener_pct = 25;   p->comma_bridge_pct = 35;
        p->mid_bridge_pct = 12;
        p->paragraph_every = 6;
        break;
    case NOISE_HIGH:
        p->min_sentence = 6;  p->max_sentence = 12;
        p->min_clause = 2;    p->max_clause = 5;
        p->opener_pct = 55;   p->comma_bridge_pct = 65;
        p->mid_bridge_pct = 30;
        p->paragraph_every = 3;
        break;
    default:
        p->min_sentence = 8;  p->max_sentence = 15;
        p->min_clause = 3;    p->max_clause = 6;
        p->opener_pct = 40;   p->comma_bridge_pct = 50;
        p->mid_bridge_pct = 20;
        p->paragraph_every = 4;
        break;
    }
}

static int rnd_range(int lo, int hi) {
    if (hi <= lo) return lo;
    return lo + (rand() % (hi - lo + 1));
}

static int end_sentence(char** buf, size_t* cap, size_t* len) {
    int r = rand() % 100;
    if (r < 8) return append_punct(buf, cap, len, PUNCT_QUEST);
    if (r < 16) return append_punct(buf, cap, len, PUNCT_BANG);
    return append_punct(buf, cap, len, PUNCT_PERIOD);
}

static char* encrypt_shellcode_plain(const unsigned char* sc, size_t len, size_t* out_len) {
    size_t cap = len * 32 + 4096;
    size_t pos = 0;
    char* out = (char*)calloc(1, cap);
    if (!out) return NULL;

    for (size_t i = 0; i < len; i++) {
        const char* w = g_byte_to_word[sc[i]];
        if (!w) { free(out); return NULL; }
        if (!append_piece(&out, &cap, &pos, w)) { free(out); return NULL; }
    }
    *out_len = pos;
    return out;
}

static char* encrypt_shellcode_natural(const unsigned char* sc, size_t len, NoiseLevel level, size_t* out_len) {
    ProseParams pr;
    prose_params_for_level(level, &pr);

    size_t cap = len * 64 + 16384;
    size_t pos = 0;
    char* out = (char*)calloc(1, cap);
    if (!out) return NULL;

    int words_in_sentence = 0;
    int words_since_comma = 0;
    int sentence_target = rnd_range(pr.min_sentence, pr.max_sentence);
    int sentences_in_para = 0;
    int capitalize = 1;

    for (size_t i = 0; i < len; i++) {
        const char* w = g_byte_to_word[sc[i]];
        if (!w) { free(out); return NULL; }

        if (words_in_sentence == 0 && sentences_in_para >= pr.paragraph_every) {
            if (!append_raw(&out, &cap, &pos, "\n\n")) PROSE_FAIL();
            sentences_in_para = 0;
            capitalize = 1;
        }

        if (words_in_sentence == 0 && (rand() % 100) < pr.opener_pct) {
            if (g_num_safe_connectors > 0) {
                if (!append_connector(&out, &cap, &pos, 1)) PROSE_FAIL();
                if (!append_punct(&out, &cap, &pos, PUNCT_COMMA)) PROSE_FAIL();
                capitalize = 0;
            }
        }

        if (i > 0 && sc[i] == sc[i - 1] && g_num_safe_connectors > 0) {
            if (!append_punct(&out, &cap, &pos, PUNCT_COMMA)) PROSE_FAIL();
            if (!append_connector(&out, &cap, &pos, 0)) PROSE_FAIL();
            words_since_comma = 0;
        }

        if (!append_word_form(&out, &cap, &pos, w, capitalize)) PROSE_FAIL();
        capitalize = 0;
        words_in_sentence++;
        words_since_comma++;

        int is_last = (i + 1 >= len);

        if (is_last) {
            if (!end_sentence(&out, &cap, &pos)) PROSE_FAIL();
            break;
        }

        int should_end_sentence = (words_in_sentence >= sentence_target);
        int clause_limit = rnd_range(pr.min_clause, pr.max_clause);
        int should_comma = (!should_end_sentence && words_since_comma >= clause_limit);

        if (should_end_sentence) {
            if (!end_sentence(&out, &cap, &pos)) PROSE_FAIL();
            words_in_sentence = 0;
            words_since_comma = 0;
            sentence_target = rnd_range(pr.min_sentence, pr.max_sentence);
            sentences_in_para++;
            capitalize = 1;
        }
        else if (should_comma) {
            if (!append_punct(&out, &cap, &pos, PUNCT_COMMA)) PROSE_FAIL();
            words_since_comma = 0;
            if (g_num_safe_connectors > 0 && (rand() % 100) < pr.comma_bridge_pct) {
                if (!append_connector(&out, &cap, &pos, 0)) PROSE_FAIL();
            }
        }
        else if (g_num_safe_connectors > 0 && words_in_sentence > 1 && (rand() % 100) < pr.mid_bridge_pct) {
            if (!append_connector(&out, &cap, &pos, 0)) PROSE_FAIL();
        }
    }

    *out_len = pos;
    return out;
}

char* encrypt_shellcode(const unsigned char* sc, size_t len, NoiseLevel noise, size_t* out_len) {
    if (noise == NOISE_OFF)
        return encrypt_shellcode_plain(sc, len, out_len);
    return encrypt_shellcode_natural(sc, len, noise, out_len);
}

int roundtrip_self_test(const unsigned char* sc, size_t len, NoiseLevel noise) {
    size_t enc_len = 0;
    char* enc = encrypt_shellcode(sc, len, noise, &enc_len);
    if (!enc) return 0;

    unsigned char* dec = NULL;
    DecryptStats st;
    size_t dlen = decrypt_shellcode(enc, &dec, 0, &st);
    int ok = (dlen == len) && (memcmp(sc, dec, len) == 0);

    if (!ok) {
        printf("[!] Round-trip FAILED: in=%zu out=%zu codewords=%d noise_skipped=%d\n",
            len, dlen, st.codewords, st.noise_skipped);
    }

    free(enc);
    free(dec);
    return ok;
}
