#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char hello[1024] = "Cheat Code";

int main(){
	setbuf(stdout,NULL);
	setbuf(stdin,NULL);
	char data[1024];
	while (1) {
	  fgets(data,sizeof(data),stdin);
	  printf(data);
	}
}
