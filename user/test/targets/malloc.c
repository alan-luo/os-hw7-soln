#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

void on_ctrl_c(int sig) {}

#define PRIV_STR "Hey this is private!"

int main(void)
{
	if (signal(SIGINT, on_ctrl_c) == SIG_ERR) {
		perror("signal");
		return 1;
	}

	char *area = malloc(sizeof(PRIV_STR));

	if (area == NULL) {
		perror("malloc");
		return 1;
	}
	strcpy(area, PRIV_STR);
	printf("0x%lx\n", (unsigned long)area);

	pause();

	printf("%s\n", area);
	free(area);
}
