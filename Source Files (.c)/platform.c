#include "platform.h"

#ifdef _WIN32
#include <windows.h>

void maybe_execute_shellcode(unsigned char* sc, size_t len) {
    printf("\nExecute shellcode in memory? (y/N): ");
    char ans[16];
    if (!fgets(ans, sizeof(ans), stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
        printf("Skipped.\n");
        return;
    }
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { printf("VirtualAlloc failed.\n"); return; }
    memcpy(mem, sc, len);
    printf("[*] Press Enter to run...\n");
    {
        char dummy[16];
        fgets(dummy, sizeof(dummy), stdin);
    }
    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    VirtualFree(mem, 0, MEM_RELEASE);
}
#else
void maybe_execute_shellcode(unsigned char* sc, size_t len) {
    (void)sc;
    (void)len;
}
#endif
