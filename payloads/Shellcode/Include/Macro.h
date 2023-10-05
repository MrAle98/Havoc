
#include <windows.h>

#ifdef _WIN64
    #define PPEB_PTR __readgsqword( 0x60 )
#else
    #define PPEB_PTR __readfsdword( 0x30 )
#endif
#define LDRP_DONT_CALL_FOR_THREADS   0x00040000

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define TEXTSTRINGSIZE 6
#define NT_SUCCESS(Status)              ( ( ( NTSTATUS ) ( Status ) ) >= 0 )
#define SEC( s, x )         __attribute__( ( section( "." #s "$" #x "" ) ) )
#define U_PTR( x )          ( ( UINT_PTR ) x )
#define C_PTR( x )          ( ( LPVOID ) x )
#define NtCurrentProcess()  ( HANDLE ) ( ( HANDLE ) - 1 )

#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )