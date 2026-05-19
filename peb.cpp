#include <windows.h>
#include <stdio.h>
#include <intrin.h>   // __readgsqword
#include <wchar.h>

// Manual struct definitions (windows.h's are incomplete) 

typedef struct _UNICODE_STRING_M {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_M;

typedef struct _PEB_LDR_DATA_M {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_M, *PPEB_LDR_DATA_M;

typedef struct _PEB_M {
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PPEB_LDR_DATA_M   Ldr;
    // rest doesn't matter
} PEB_M, *PPEB_M;

// LDR_DATA_TABLE_ENTRY, only the fields we need, with correct offsets on x64
typedef struct _LDR_DATA_TABLE_ENTRY_M {
    LIST_ENTRY       InLoadOrderLinks;           // +0x00
    LIST_ENTRY       InMemoryOrderLinks;         // +0x10
    LIST_ENTRY       InInitializationOrderLinks; // +0x20
    PVOID            DllBase;                    // +0x30
    PVOID            EntryPoint;                 // +0x38
    ULONG            SizeOfImage;                // +0x40 (4 bytes + 4 pad)
    UNICODE_STRING_M FullDllName;                // +0x48
    UNICODE_STRING_M BaseDllName;                // +0x58
} LDR_DATA_TABLE_ENTRY_M, *PLDR_DATA_TABLE_ENTRY_M;

// Case-insensitive wide string compare 
// Avoids importing wcsicmp / lstrcmpiW.

static int wstr_iequals(const wchar_t* a, USHORT a_bytes, const wchar_t* b) {
    USHORT a_len = a_bytes / sizeof(wchar_t);
    for (USHORT i = 0; i < a_len; i++) {
        wchar_t ca = a[i];
        wchar_t cb = b[i];
        if (cb == L'\0') return 0;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return b[a_len] == L'\0';
}

// PEB Walking

static PVOID GetModuleBasePEB(const wchar_t* target_name) {
    // Step 1: read TEB from gs:[0x30] (x64)
    #ifdef _WIN64
        PVOID teb = (PVOID)__readgsqword(0x30);
        // Step 2: PEB at TEB + 0x60
        PPEB_M peb = *(PPEB_M*)((BYTE*)teb + 0x60);
    #else
        PVOID teb = (PVOID)__readfsdword(0x18);
        // Step 2: PEB at TEB + 0x30
        PPEB_M peb = *(PPEB_M*)((BYTE*)teb + 0x30);
    #endif

    // Step 3: get Ldr
    PPEB_LDR_DATA_M ldr = peb->Ldr;

    // Step 4: starting Flink, head of InMemoryOrderModuleList
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    // Step 5–10: walk the list
    while (curr != head) {
        // Back up 0x10 bytes (InMemoryOrderLinks offset) to reach struct top
        PLDR_DATA_TABLE_ENTRY_M entry =
            (PLDR_DATA_TABLE_ENTRY_M)((BYTE*)curr - 0x10);

        // Step 6–7: read BaseDllName
        if (entry->BaseDllName.Buffer != NULL && entry->BaseDllName.Length > 0) {
            // Step 8: compare
            if (wstr_iequals(entry->BaseDllName.Buffer,
                             entry->BaseDllName.Length,
                             target_name)) {
                // Step 9: match → return DllBase
                return entry->DllBase;
            }
        }

        // Step 10: follow Flink
        curr = curr->Flink;
    }
    return NULL;
}

int main(void) {
    PVOID kernel32   = GetModuleBasePEB(L"kernel32.dll");
    PVOID ntdll      = GetModuleBasePEB(L"ntdll.dll");
    PVOID kernelbase = GetModuleBasePEB(L"KernelBase.dll");
    PVOID user32     = GetModuleBasePEB(L"user32.dll");
    PVOID advapi32   = GetModuleBasePEB(L"advapi32.dll");

    printf("kernel32.dll    base: %p\n", kernel32);
    printf("ntdll.dll       base: %p\n", ntdll);
    printf("KernelBase.dll  base: %p\n", kernelbase);
    printf("user32.dll      base: %p\n", user32);
    printf("advapi32.dll    base: %p\n", advapi32);

    HMODULE k32_real      = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll_real    = GetModuleHandleA("ntdll.dll");
    HMODULE kbase_real    = GetModuleHandleA("KernelBase.dll");
    HMODULE user32_real   = GetModuleHandleA("user32.dll");
    HMODULE advapi32_real = GetModuleHandleA("advapi32.dll");

    printf("GetModuleHandleA kernel32:    %p  %s\n",
           (void*)k32_real,
           (k32_real == kernel32) ? "MATCH" : "MISMATCH");
    printf("GetModuleHandleA ntdll:       %p  %s\n",
           (void*)ntdll_real,
           (ntdll_real == ntdll) ? "MATCH" : "MISMATCH");
    printf("GetModuleHandleA KernelBase:  %p  %s\n",
           (void*)kbase_real,
           (kbase_real == kernelbase) ? "MATCH" : "MISMATCH");
    printf("GetModuleHandleA user32:      %p  %s\n",
           (void*)user32_real,
           (user32_real == user32) ? "MATCH" : "MISMATCH");
    printf("GetModuleHandleA advapi32:    %p  %s\n",
           (void*)advapi32_real,
           (advapi32_real == advapi32) ? "MATCH" : "MISMATCH");

    return 0;
}
