#include <windows.h>
#define NO_INLINE       __attribute__ ((noinline))


#define SHARED_USER_DATA_VA 0x7FFE0000
#define USER_SHARED_DATA ((PBYTE * const)SHARED_USER_DATA_VA)

VOID MemCopy(LPBYTE Src, LPBYTE Dst, SIZE_T size);
UINT_PTR HashString( LPVOID String, UINT_PTR Length );
BYTE    HideChar( BYTE C );
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
SIZE_T StringLengthA(LPCSTR String);
SIZE_T StringLengthW(LPCWSTR String);
BOOL IsText(PIMAGE_SECTION_HEADER);
VOID XOREncrypt(PBYTE Plain,DWORD Size,PBYTE Key,DWORD KeySize);
VOID SharedSleep(ULONG64 delay);