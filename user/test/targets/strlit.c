#include <stdio.h>
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

	char *area = PRIV_STR;

	printf("0x%lx\n", (unsigned long)area);

	pause();

	printf("%s\n", area);
}
