#ifndef WORDSHELL_MENU_H
#define WORDSHELL_MENU_H

#include "common.h"

void print_banner(void);
void print_help(void);
void action_encrypt(void);
void action_decrypt(void);
CipherMode ask_cipher_mode(void);
NoiseLevel ask_noise_level(void);

#endif
