#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

void on_ctrl_c(int sig) {}

#define PRIV_STR "Hey this is private!"

int main(void)
{
	if (signal(SIGINT, on_ctrl_c) == SIG_ERR) {
		perror("signal");
		return 1;
	}

	char *area = mmap(NULL, sizeof(PRIV_STR), PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	strcpy(area, PRIV_STR);

	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid)
		printf("Parent: 0x%lx\n", (unsigned long)area);
	else
		printf("Child: 0x%lx\n", (unsigned long)area);

	pause();

	if (pid)
		printf("Parent: %s\n", area);
	else
		printf("Child: %s\n", area);
}
