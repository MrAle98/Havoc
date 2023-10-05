#include <windows.h>
#define NO_INLINE       __attribute__ ((noinline))

UINT_PTR HashString( LPVOID String, UINT_PTR Length );
BYTE    HideChar( BYTE C );
SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
SIZE_T StringLengthA(LPCSTR String);
SIZE_T StringLengthW(LPCWSTR String);
BOOL IsText(PIMAGE_SECTION_HEADER);
VOID XOREncrypt(PBYTE Plain,DWORD Size,PBYTE Key,DWORD KeySize);