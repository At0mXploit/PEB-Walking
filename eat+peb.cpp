#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <wchar.h>

// PEB walking structures
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
} PEB_M, *PPEB_M;

typedef struct _LDR_DATA_TABLE_ENTRY_M {
    LIST_ENTRY       InLoadOrderLinks;           // +0x00
    LIST_ENTRY       InMemoryOrderLinks;         // +0x10
    LIST_ENTRY       InInitializationOrderLinks; // +0x20
    PVOID            DllBase;                    // +0x30
    PVOID            EntryPoint;                 // +0x38
    ULONG            SizeOfImage;                // +0x40
    UNICODE_STRING_M FullDllName;                // +0x48
    UNICODE_STRING_M BaseDllName;                // +0x58
} LDR_DATA_TABLE_ENTRY_M, *PLDR_DATA_TABLE_ENTRY_M;

// Case-insensitive wide string compare (no CRT import needed)// 

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

// ASCII to wide conversion for forwarder DLL names
// "NTDLL.dll" -> L"NTDLL.dll"

static void ascii_to_wide(const char* src, wchar_t* dst, size_t dst_max) {
    size_t i = 0;
    while (src[i] != '\0' && i < dst_max - 1) {
        dst[i] = (wchar_t)src[i];
        i++;
    }
    dst[i] = L'\0';
}

// PEB walking: resolve a DLL base address without GetModuleHandleA

static PVOID GetModuleBasePEB(const wchar_t* target_name) {
    #ifdef _WIN64
        PVOID teb = (PVOID)__readgsqword(0x30);
        PPEB_M peb = *(PPEB_M*)((BYTE*)teb + 0x60);
    #else
        PVOID teb = (PVOID)__readfsdword(0x18);
        PPEB_M peb = *(PPEB_M*)((BYTE*)teb + 0x30);
    #endif

    PPEB_LDR_DATA_M ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY_M entry =
            (PLDR_DATA_TABLE_ENTRY_M)((BYTE*)curr - 0x10);

        if (entry->BaseDllName.Buffer != NULL && entry->BaseDllName.Length > 0) {
            if (wstr_iequals(entry->BaseDllName.Buffer,
                             entry->BaseDllName.Length,
                             target_name)) {
                return entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// LoadFunction: resolve any export from a DLL base
// Forwarder recursion now uses PEB walking instead of GetModuleHandleA

PVOID LoadFunction(PBYTE Module, LPSTR FunctionName)
{
    PIMAGE_NT_HEADERS       NtHeader         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = NULL;
    PDWORD                  AddrOfFunctions  = NULL;
    PDWORD                  AddrOfNames      = NULL;
    PWORD                   AddrOfOrdinals   = NULL;
    PVOID                   FunctionAddr     = NULL;
    LPSTR                   FoundName        = NULL;
    CHAR  LowerFoundName   [MAX_PATH]        = {0};
    CHAR  LowerFunctionName[MAX_PATH]        = {0};

    RtlSecureZeroMemory(LowerFunctionName, MAX_PATH);
    memcpy(LowerFunctionName, FunctionName, strlen(FunctionName));
    CharLowerBuffA(LowerFunctionName, strlen(FunctionName));

    NtHeader     = (PIMAGE_NT_HEADERS)(Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew);
    ExpDirectory = (PIMAGE_EXPORT_DIRECTORY)(Module + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD ExpDirRVA  = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD ExpDirSize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    AddrOfNames     = (PDWORD)(Module + ExpDirectory->AddressOfNames);
    AddrOfFunctions = (PDWORD)(Module + ExpDirectory->AddressOfFunctions);
    AddrOfOrdinals  = (PWORD) (Module + ExpDirectory->AddressOfNameOrdinals);

    for (DWORD I = 0; I < ExpDirectory->NumberOfNames; I++)
    {
        RtlSecureZeroMemory(LowerFoundName, MAX_PATH);
        FoundName = (PCHAR)Module + AddrOfNames[I];

        memcpy(LowerFoundName, FoundName, strlen(FoundName));
        CharLowerBuffA(LowerFoundName, strlen(FoundName));

        if (!strcmp(LowerFoundName, LowerFunctionName))
        {
            DWORD FuncRva = AddrOfFunctions[AddrOfOrdinals[I]];

            // Forwarder check
            if (FuncRva >= ExpDirRVA && FuncRva < ExpDirRVA + ExpDirSize)
            {
                LPSTR Forwarder = (LPSTR)(Module + FuncRva);

                CHAR DllName [MAX_PATH] = {0};
                CHAR FuncName[MAX_PATH] = {0};

                LPSTR Dot = strchr(Forwarder, '.');
                if (!Dot) return NULL;

                size_t DllLen = Dot - Forwarder;
                memcpy(DllName, Forwarder, DllLen);
                strcpy(DllName + DllLen, ".dll");
                strcpy(FuncName, Dot + 1);

                // PEB walk replaces GetModuleHandleA here 
                wchar_t DllNameW[MAX_PATH] = {0};
                ascii_to_wide(DllName, DllNameW, MAX_PATH);

                PVOID NextModule = GetModuleBasePEB(DllNameW);
                if (!NextModule) return NULL;

                return LoadFunction((PBYTE)NextModule, FuncName);
            }

            FunctionAddr = (PVOID)(Module + FuncRva);
            return FunctionAddr;
        }
    }

    return NULL;
}

int main(void)
{
    // PEB walk for kernel32 base no API call
    PVOID k32 = GetModuleBasePEB(L"kernel32.dll");
    if (!k32) {
        printf("[-] Failed to find kernel32 via PEB walk\n");
        return 1;
    }

    printf("[+] kernel32.dll base (PEB walk): %p\n\n", k32);

    const char* targets[] = {
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateThread",
        "HeapAlloc"     // forwarder -> ntdll!RtlAllocateHeap
    };

    for (int i = 0; i < 4; i++) {
        // Verification only, GetModuleHandleA/GetProcAddress kept for comparison
        HMODULE k32_real = GetModuleHandleA("kernel32.dll");
        PVOID realVA     = (PVOID)GetProcAddress(k32_real, targets[i]);
        PVOID customVA   = LoadFunction((PBYTE)k32, (LPSTR)targets[i]);

        printf("Function: %s\n", targets[i]);
        printf("  GetProcAddress: %p\n", realVA);
        printf("  LoadFunction:   %p\n", customVA);
        printf("  Match: %s\n\n", (realVA == customVA) ? "YES" : "NO");
    }

    return 0;
}
