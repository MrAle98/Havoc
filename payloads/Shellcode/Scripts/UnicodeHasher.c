#include <stdio.h>
#include <ctype.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


size_t CharStringToWCharString( char* Destination, char* Source, size_t MaximumAllowed )
{
    int Length = (int)MaximumAllowed;

    while (--Length >= 0)
    {
    	printf("*Destination = %c, *Source= %c\n",*Destination,*Source);
        *Destination = *Source;
        Destination += 2;
        Source++; 
    }

    return MaximumAllowed - Length;
}

ulong HashString( u_char* String, size_t Length )
{
    ulong	Hash = 5381;
    u_char*	Ptr  = String;
    if(String <= 0){
        return 0;
    }
    do
    {
        u_char character = *Ptr;
	printf("uchar = %c\n",character);
        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ulong) ( Ptr - (u_char*)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( true );

    return Hash;
}
void ToUpperString(char * temp) {
  // Convert to upper case
  char *s = temp;
  while (*s) {
    *s = toupper((unsigned char) *s);
    s++;
  }
}

int main(int argc, char** argv) 
{
  if (argc < 2)
    return 0;
  
  char dest[256] = {0};
  
  ToUpperString(argv[1]);
  CharStringToWCharString(dest,argv[1],strlen(argv[1]));
  //printf("argv[1] = %s\n",argv[1]);
  //mbstowcs(dest, argv[1], strlen(argv[1]));
  //printf("dest = %ls\n",dest);
  //printf("sizeof dest = %d\n",wcslen(dest)*sizeof(wchar_t));
  //u_char* ptr = dest;
  //for(int i=0;i<wcslen(dest)*sizeof(wchar_t);i++){
  //	printf("ptr[%d] = %c\n",i,ptr[i]); 
  //}
  for(int i=0;i<strlen(argv[1])*2;i++){
  	printf("dest[%d] = %c\n",i,dest[i]);
  }
  printf("\n[+] Unicode Hashed %s ==> 0x%x\n\n", argv[1], HashString(dest,strlen(argv[1])*2));
  
  return 0;
}
