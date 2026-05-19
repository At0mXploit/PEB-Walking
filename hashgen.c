/*
 * hashgen.c
 * Run this once to get the djb2 hashes for any API names you need.
 * Compile: gcc hashgen.c -o hashgen
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint32_t djb2(const char *s)
{
    uint32_t h = 5381;
    int c;
    while ((c = (unsigned char)*s++) != 0) {
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}

int main(void)
{
    const char *apis[] = {
        "OpenProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "WaitForSingleObject",
        "CloseHandle",
        "VirtualFreeEx",
        "VirtualProtectEx",
        "VirtualAlloc",
        "CreateThread",
        "HeapAlloc",
    };

    int n = sizeof(apis) / sizeof(apis[0]);
    printf("%-30s  hash\n", "API");
    printf("%-30s  ----\n", "---");
    for (int i = 0; i < n; i++)
        printf("%-30s  0x%08X\n", apis[i], djb2(apis[i]));
    return 0;
}
