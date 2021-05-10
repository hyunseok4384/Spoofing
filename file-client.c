#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#define BUF_SIZE 30
void error_handling(char *message);
#test

int main(int argc, char *argv[]){
	int sd;
	FILE *fp;
	char buf[BUF_SIZE];
	int read_cnt;
	struct socketaddr_in serv_addr;
	
	if(argc!=3){
		printf("Usage : %s <IP> <PORT> \n",argv[0]);
		exit(1);
	}
	/* 서버가 전송하는 파일 데이터를 담기위해서 파일을 하나 생성하고 있다 */
	fp=fopen("receive.c","wb");
	sd=socket(PF_INET, SOCK_STREAM, 0);
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));
	
	connect(sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	
	/* EOF가 전송될때까지 데이터를 수신한 다음 위에서 생성한 파일에 담고 있다 */
	while((read_cnt=read(sd, buf, BUF_SIZE))!=0)
	{
		fwrite((void*)buf, 1, read_cnt, fp);
	}
	puts("Received file data");
	/* 서버로 인사 메시지를 전송하고 있다. 서버의 입력 스트림이 닫히지 않았다면, 이 메시지를 수신할 수 있다 */
	write(sd, "Thank you", 10);
	fclose(fp);
	close(sd);
	return 0;
}

void error_handling(char *message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}
