# NØW  — Word-Based Shellcode Encoder

> Encode shellcode as natural-looking English prose. Decode it back with the right sentence + password.

<img width="1376" height="768" alt="NOW" src="https://github.com/user-attachments/assets/fdde7127-7411-4182-89cb-1441f345f22f" />

---

## What is NØW?

**NØW** (Natural Output Words) is a C tool that converts raw shellcode bytes into human-readable English text — either a plain list of codewords or fluent natural-looking prose with sentences and paragraphs. The output looks like ordinary writing, not hex dumps or base64 blobs.

Every byte value (0x00–0xFF) maps to a unique word, derived from a **secret sentence** you provide. A stream cipher (RC4 or AES-256-CTR) shuffles the byte-to-word assignments based on a **password**. Without both the sentence and password, the encoded text is just noise.

---

## How It Works

```
Shellcode bytes
      │
      ▼
Stream cipher (RC4 or AES-256-CTR) shuffles byte→word table
      │
      ▼
Each byte → one codeword from your secret sentence (padded to 256 unique words)
      │
      ▼
Optional: wrap in natural prose with connectors, punctuation, paragraph breaks
      │
      ▼
Output text file  (looks like an essay or paragraph)
```

Decryption reverses the process — it reads the text, strips punctuation and connector words, and maps each codeword back to its byte value.

---

## Features

- **256-word codebook** built from any sentence you provide, padded automatically with common English words
- **Two stream ciphers** for byte-to-word shuffling:
  - `RC4` — cross-platform, compatible with RC4ENC/RC4DEC
  - `AES-256-CTR` — Windows only (via CryptoAPI), compatible with AESENC/AESDEC
- **Four output styles:**
  
  | Level            | Description                              |
  |-------           |-------------                             |
  | 0 — Plain        | Raw word list, no punctuation            |
  | 1 — Light prose  | Longer sentences, minimal filler         |
  | 2 — Medium prose | Balanced paragraphs (default)            |
  | 3 — Heavy prose  | Frequent connectors and paragraph breaks |
  
- **Round-trip self-test** — automatically verifies encode→decode produces the exact same bytes before saving
- **Multiple input formats** — paste hex bytes directly or load a `.bin` file
- **Multiple output formats on decrypt** — saves `.bin`, `.c` (C array), and `.hex`
- **Optional shellcode execution** (Windows only) — runs decoded shellcode in memory via `VirtualAlloc` + `CreateThread`

---

## Project Structure

```
├── main.c            # Entry point, main menu loop
├── menu.c / menu.h   # Interactive CLI actions (encrypt, decrypt, help)
├── encrypt.c / .h    # Shellcode → word encoding (plain + natural prose)
├── decrypt.c / .h    # Word text → shellcode decoding
├── word_mapping.c/.h # Builds the 256-word codebook and byte↔word lookup tables
├── rc4.c / .h        # RC4 stream cipher implementation
├── io.c / .h         # File I/O, hex parsing, multi-line input
├── platform.c / .h   # Platform-specific shellcode execution (Windows)
├── util.c / .h       # String helpers (trim, clean tokens, etc.)
└── common.h          # Shared constants, macros, and type definitions
```

---

## Usage

Run the binary and follow the interactive menu:

```
  NØW v2.2 - Word-Based Shellcode Tool
  RC4 or AES stream | Natural prose output

Main menu:
  1. Encrypt shellcode -> words
  2. Decrypt words -> shellcode
  3. Help
  4. Exit
```

### Encrypt
1. Choose **option 1**
2. Enter your **secret sentence** (any phrase; more unique words = better codebook)
3. Enter a **password** (min 4 characters)
4. Choose stream cipher (`RC4` or `AES-256-CTR`)
5. Choose output style (0 = plain, 1–3 = natural prose)
6. Paste shellcode as **hex bytes** or load a `.bin` file
7. Output is saved to a `.txt` file

---

### Decrypt
1. Choose **option 2**
2. Enter the **same secret sentence and password** used during encryption
3. Choose the **same stream cipher**
4. Paste the encoded text or load the file
5. Output is saved as `.bin`, `.c`, and `.hex`

---

## Security Notes

- The security of the encoding depends entirely on keeping the **sentence and password secret**
- The word codebook is deterministic — the same sentence + password + cipher always produces the same mapping
- This tool is intended for **security research, CTF challenges, and red team payload obfuscation**
- Shellcode execution (`platform.c`) is Windows-only and requires explicit user confirmation at runtime

---
