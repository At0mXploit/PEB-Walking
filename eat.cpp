#include <windows.h>
#include <stdio.h>
#include <string.h>

PVOID LoadFunction( PBYTE Module, LPSTR FunctionName )
{
    PIMAGE_NT_HEADERS       NtHeader         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = NULL;
    PDWORD                  AddrOfFunctions  = NULL;
    PDWORD                  AddrOfNames      = NULL;
    PWORD                   AddrOfOrdinals   = NULL;
    PVOID                   FunctionAddr     = NULL;
    LPSTR                   FoundName        = NULL;
    CHAR  LowerFoundName   [ MAX_PATH ]      = { 0 };
    CHAR  LowerFunctionName[ MAX_PATH ]      = { 0 };

    // Lowercase the target function name for case-insensitive comparison
    RtlSecureZeroMemory( LowerFunctionName, MAX_PATH );
    memcpy( LowerFunctionName, FunctionName, strlen( FunctionName ) );
    CharLowerBuffA( LowerFunctionName, strlen( FunctionName ) );

    // Walk to NT headers, then to the export directory
    NtHeader     = (PIMAGE_NT_HEADERS)( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDirectory = (PIMAGE_EXPORT_DIRECTORY)( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    // Resolve the three EAT arrays from their RVAs
    AddrOfNames     = (PDWORD)( Module + ExpDirectory->AddressOfNames );
    AddrOfFunctions = (PDWORD)( Module + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals  = (PWORD) ( Module + ExpDirectory->AddressOfNameOrdinals );

    // Walk every named export
    for ( DWORD I = 0; I < ExpDirectory->NumberOfNames; I++ )
    {
        RtlSecureZeroMemory( LowerFoundName, MAX_PATH );

        // AddrOfNames[I] is an RVA to the name string — add module base
        FoundName = ( PCHAR ) Module + AddrOfNames[ I ];

        memcpy( LowerFoundName, FoundName, strlen( FoundName ) );
        CharLowerBuffA( LowerFoundName, strlen( FoundName ) );

        if ( !strcmp( LowerFoundName, LowerFunctionName ) )
        {
            // AddrOfOrdinals[I] gives the ordinal index into AddrOfFunctions
            FunctionAddr = (PVOID)( Module + AddrOfFunctions[ AddrOfOrdinals[ I ] ] );
            return FunctionAddr;
        }
    }

    return NULL;

}

int main(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        printf("[-] Failed to get kernel32 base\n");
        return 1;
    }

    printf("[+] kernel32.dll base: %p\n\n", k32);

    // Test a few functions
    const char* targets[] = { "VirtualAlloc", "WriteProcessMemory", "CreateThread" };

    for (int i = 0; i < 3; i++) {
        PVOID realVA   = (PVOID)GetProcAddress(k32, targets[i]);
        PVOID customVA = LoadFunction((PBYTE)k32, (LPSTR)targets[i]);

        printf("Function: %s\n", targets[i]);
        printf("  GetProcAddress: %p\n", realVA);
        printf("  LoadFunction:   %p\n", customVA);
        printf("  Match: %s\n\n", (realVA == customVA) ? "YES" : "NO");
    }

    return 0;
}
