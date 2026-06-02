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

## Example

<img width="1897" height="974" alt="1" src="https://github.com/user-attachments/assets/fa08aecf-35c6-41eb-b305-f5157df1468d" />


In the image above, we encrypted a shellcode using the NØW Word-Based Shellcode Tool. The original shellcode was first encrypted using the selected stream cipher (RC4 in this example) with the password "nirvana". After encryption, each encrypted byte was mapped to words from a predefined word pool, producing a block of natural-looking text instead of obvious shellcode bytes.

The generated output appears as normal prose containing words such as hope, bottle, spiral, fog, ink, and snow. However, this text is not meant to be read as a meaningful paragraph. Each word represents an encrypted byte value, and the sequence of words preserves the encrypted shellcode data.

During decryption, the tool performs the reverse process:

1.Convert the words back into their corresponding byte values.
2.Reconstruct the encrypted shellcode byte stream.
3.Use the same password and stream cipher settings (RC4) to decrypt the data.
4.Recover the original shellcode exactly as it was before encryption.

This technique transforms shellcode into human-readable text, making the payload appear less suspicious than a raw hexadecimal byte array while still allowing the original shellcode to be reconstructed when the correct password and cipher settings are supplied.

**Note**: Only English words should be used in the secret sentence. Non-English characters (Chinese, Japanese, Arabic, emojis, etc.) may cause encoding or parsing issues and can break the encryption/decryption process. Use standard English ASCII text for reliable results.

### Encrypted Text

```
Probably, laughed hope polishing, how most perhaps sleep would bottle, additionally, somewhere bottle, immediately bottle me spiral me time fog. Immediately, spiral animal certainly hope all by, previously do elsewhere hope perhaps ink fog, also hope ink, consequently fog? Door hope ink, meanwhile fog equally snow hope ink, recently room time hope get then immediately house, importantly house. Written all window hope all would, eventually vanished fire notably one he, elsewhere than?

Accordingly, roof snow me waves window, somewhere into me obviously now waves great, particularly ago fog. Nonetheless, me spiral hope ink, regardless fog snow consequently ink shore, fire moreover hope now birds, indirectly ink. Probably, peace floor bottle, everywhere bottle, everywhere bottle hope never would earth, white hope. Now birds time, ink hope door black, ink faded consequently snow.

About now birds moon animal, hope us window however me, currently ink similarly leaving floor. Regardless, hope now map written all window, hope all would vanished me waves? Probably, window into me furthermore now waves calm, there bucket basically horse ceiling star ceiling, dying. Furthermore, which evening pig because, bucket even word black ink!

Additionally, faded dying about now, however birds specifically used me, ink revolver hope, black ink originally faded, equally see. About now consequently birds certainly me ink two, floor particularly hope obviously now birds me. Word me word, my packed bag, me word me otherwise packed me, bag hope. Polishing father snow, me fog us, there word me packed, immediately bag hope everywhere ink.

Particularly, happy flower your, us, equally us, likewise us partly years about meanwhile fresh make, indirectly cat therefore just. Namely, not we just bottle, chiefly bottle me animal, about subsequently stone moreover to hope fish? Basically, father dawn nevertheless now, bottle, although bottle about stone prank, about but than, regardless bottle? Now home would lighthouse, immediately now go namely me until, similarly about indirectly stone.

Additionally, how ceiling stone horse, additionally me they ceiling make, its. Equally, fear us yellow chiefly ceiling stone a, old eventually now notably, whereas now eventually bottle, mainly bottle packed me. They mouse originally peace for, bottle us yellow, time, furthermore time written nowhere all window, written likewise all! Would hope us would hope stone, her hope.

Us would hope stone, alternatively waves me probably they moreover a, consequently get want there us, particularly yellow hope. Stone every currently something, notably or me word ceiling stone, great however hope stone, human me they indirectly angry. Prayer earth mostly one, nevertheless us yellow accordingly hope fish, staircase equally faded than bottle, obviously bottle about thinking leather? Buried bird bottle, chiefly bottle mainly, accordingly bottle, partly bottle, anywhere bottle moreover me perhaps time, me.

Time hope certainly stone, somewhere great your whereas, obviously your, originally your written all would. Something into packed me, time great partly laughed, regardless used every black, nonetheless dying until moreover now, somewhere now hope. Another black dying, similarly door previously stopped additionally bottle old, indeed hope stone. To animal time me time, particularly me time me.

Time about originally us, particularly would me time about, everywhere us dream meanwhile written initially stone, eventually waves ceiling meanwhile stone. Waves me they, chiefly sea whereas rocky washed leaf us, somewhere yellow hope. Mainly, all by hope us, containing ink dog, otherwise me they which. Rolled duck also, chiefly us yellow home most constant, war animal me, they found.

Long who what us yellow, hope polishing nowhere staircase? Look fire wall, indirectly he garden peace, differently waters there additionally bucket coming. Nevertheless, home ice notably have whereas room, sky something bottle packed, me stone cloud us. Importantly, yellow.

```

<img width="1904" height="969" alt="2" src="https://github.com/user-attachments/assets/e4da3933-ec28-4a78-b5d7-0081d790f413" />


#### Decrypting Words Back to Shellcode

The encrypted text is provided to the tool along with the correct password (nirvana) and stream cipher (RC4). The tool removes punctuation and formatting, converts each word back to its corresponding byte value, reconstructs the encrypted byte stream, and then decrypts it to recover the original shellcode.

Process:
Shellcode → Encrypted Bytes → Words → Words → Encrypted Bytes → Original Shellcode

**Note**: The password and cipher must match the values used during encryption. Any mismatch will result in incorrect or failed decryption.

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

## Build

1. Open the project in **Visual Studio 2022**.
2. Add all `.c` and `.h` files to the project.
3. Select **x64** and **Release**.
4. Build the solution (`Ctrl + Shift + B`).

**Requirements:**
- Visual Studio 2022
- Windows SDK

> Recommended: Build on Windows using Visual Studio.

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
