#include <Utils.h>
#include <Macro.h>

SEC(text, B) ULONG64 SharedTimestamp(
) {
    //SIZE_T        UnixStart     = 0x019DB1DED53E8000; /* Start of Unix epoch in ticks. */
    //SIZE_T        TicksPerMilli = 1000;
    LARGE_INTEGER Time          = { 0 };
//
//    Time.LowPart  = USER_SHARED_DATA->SystemTime.LowPart;
//    Time.HighPart = USER_SHARED_DATA->SystemTime.High2Time;
    Time.LowPart = *(PDWORD)((PBYTE)USER_SHARED_DATA + 0x14);
    Time.HighPart = *(PDWORD)((PBYTE)USER_SHARED_DATA + 0x14 + 0x8);
    // NOTE: avoid 64-bit division which doesn't work in x86
    //return ( ULONGLONG ) ( ( Time.QuadPart - UnixStart ) / TicksPerMilli );

    return Time.QuadPart;
}
/*!
 * Sleep using KUSER_SHARED_DATA.SystemTime
 * @param Delay
 */
SEC( text, B ) VOID SharedSleep(
        ULONG64 Delay
) {
    SIZE_T  Rand          = { 0 };
    ULONG64 End           = { 0 };
    ULONG   TicksPerMilli = 1000;
    ULONG64 Current = 0;
    Delay *= TicksPerMilli;

    End  = SharedTimestamp() + Delay;
    /* increment random number til we reach the end */

    while ( SharedTimestamp() < End ) {
        Rand += 1;
    }

    if ( ( SharedTimestamp() - End ) > 2000 ) {
        return;
    }
}