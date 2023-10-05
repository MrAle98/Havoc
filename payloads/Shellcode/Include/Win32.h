#include <ntdef.h>
#include <Macro.h>

#pragma pack(8)
typedef struct _FULLLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary:1;
            ULONG MarkedForRemoval:1;
            ULONG ImageDll:1;
            ULONG LoadNotificationsSent:1;
            ULONG TelemetryEntryProcessed:1;
            ULONG ProcessStaticImport:1;
            ULONG InLegacyLists:1;
            ULONG InIndexes:1;
            ULONG ShimDll:1;
            ULONG InExceptionTable:1;
            ULONG ReservedFlags1:2;
            ULONG LoadInProgress:1;
            ULONG LoadConfigProcessed:1;
            ULONG EntryProcessed:1;
            ULONG ProtectDelayLoad:1;
            ULONG ReservedFlags3:2;
            ULONG DontCallForThreads:1;
            ULONG ProcessAttachCalled:1;
            ULONG ProcessAttachFailed:1;
            ULONG CorDeferredValidate:1;
            ULONG CorImage:1;
            ULONG DontRelocate:1;
            ULONG CorILOnly:1;
            ULONG ChpeImage:1;
            ULONG ChpeEmulatorImage:1;
            ULONG ReservedFlags5:1;
            ULONG Redirected:1;
            ULONG ReservedFlags6:2;
            ULONG CompatDatabaseProcessed:1;
        };
    };
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
} FULLLDR_DATA_TABLE_ENTRY, *PFULLLDR_DATA_TABLE_ENTRY;

UINT_PTR LdrModulePeb( UINT_PTR hModuleHash );
PVOID LdrFunctionAddr( UINT_PTR hModule, UINT_PTR ProcHash );
PFULLLDR_DATA_TABLE_ENTRY LdrModulePebDTE( UINT_PTR hModuleHash );
