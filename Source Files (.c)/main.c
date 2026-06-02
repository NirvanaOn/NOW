#include "menu.h"
#include "util.h"

int main(void) {
    print_banner();
    for (;;) {
        printf("Main menu:\n");
        printf("  1. Encrypt shellcode -> words\n");
        printf("  2. Decrypt words -> shellcode\n");
        printf("  3. Help\n");
        printf("  4. Exit\n");
        printf("Select [1-4]: ");

        char choice[16];
        if (!fgets(choice, sizeof(choice), stdin)) break;
        trim_newline(choice);

        if (choice[0] == '1') action_encrypt();
        else if (choice[0] == '2') action_decrypt();
        else if (choice[0] == '3') print_help();
        else if (choice[0] == '4') break;
        else printf("Invalid.\n");
    }
    printf("\nGoodbye.\n");
    return 0;
}
