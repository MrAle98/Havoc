#include <Utils.h>
#include <Macro.h>

SEC(text,B) VOID MemCopy(LPBYTE Src, LPBYTE Dst, SIZE_T size){
    for(int i=0;i<size;i++){
        Src[i] = Dst[i];
    }
}
SEC( text, B ) UINT_PTR HashString( LPVOID String, UINT_PTR Length )
{
    ULONG	Hash = 5381;
    PUCHAR	Ptr  = String;
    if(String <= 0){
        return 0;
    }
    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SEC( text, B ) BYTE NO_INLINE HideChar( BYTE C )
{
    return C;
}
SEC( text, B ) SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SEC( text, B ) SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SEC( text, B )SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SEC( text, B ) BOOL IsText(PIMAGE_SECTION_HEADER SecHeader){
    //todo add hideChar thing
    PCHAR name = SecHeader->Name;
    CHAR text[TEXTSTRINGSIZE] = {'.','t','e','x','t','\0'};
    BOOL res = TRUE;
    for(int i=0;i< TEXTSTRINGSIZE;i++){
        if(text[i] != name[i]){
            res = FALSE;
            break;
        }
    }
    return res;
}

SEC( text, B ) VOID XOREncrypt(PBYTE Plain,DWORD Size,PBYTE Key,DWORD KeySize){
    for(int i=0;i<Size;i++){
        Plain[i] = Plain[i] ^ Key[i%KeySize];
    }
}