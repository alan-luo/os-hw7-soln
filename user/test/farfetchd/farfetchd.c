#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <asm-generic/unistd.h>
#include <linux/farfetch.h>

static inline void die(const char *s)
{
	perror(s);
	exit(1);
}

#define farfetch(cmd, dst, target_pid, target_addr, len) \
	syscall(__NR_farfetch, cmd, dst, target_pid, target_addr, len)

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <pid> <addr> <len>\n", argv[0]);
		exit(1);
	}

	pid_t target_pid = atoi(argv[1]);
	unsigned long target_addr = strtol(argv[2], NULL, 0);
	size_t len = atol(argv[3]);

	char *buf = malloc(len);

	if (buf == NULL)
		die("malloc");

	long fetched = farfetch(FAR_READ, buf, target_pid, target_addr, len);

	if (fetched < 0)
		die("farfetch FAR_READ");

	char tmppath[] = "/tmp/farfetchd.XXXXXX";
	int tmpfd = mkstemp(tmppath);

	if (tmpfd < 0)
		die("mkstemp");

	FILE *tmpf = fdopen(tmpfd, "r+b");

	if (tmpf == NULL) {
		unlink(tmppath);
		die("fdopen");
	}

	if (fetched && fwrite(buf, fetched, 1, tmpf) != 1) {
		unlink(tmppath);
		die("fwrite");
	}
	fflush(tmpf);

	pid_t pid = fork();

	if (pid < 0) {
		unlink(tmppath);
		die("fork");
	}
	if (pid == 0) {
		execlp("bvi", "bvi", tmppath, (char *)NULL);
		die("execlp");
	}

	int wstatus;

	pid = waitpid(pid, &wstatus, 0);
	unlink(tmppath);
	if (pid < 0)
		die("waitpid");
	if (WEXITSTATUS(wstatus) != 0)
		exit(WEXITSTATUS(wstatus));

	char *bufout = malloc(fetched);

	if (bufout == NULL)
		die("malloc");

	fseek(tmpf, 0, SEEK_SET);
	if (fetched && fread(bufout, fetched, 1, tmpf) != 1)
		die("fread");
	fclose(tmpf);

	if (memcmp(buf, bufout, fetched) != 0)
		if (farfetch(FAR_WRITE, bufout, target_pid, target_addr, fetched) < 0)
			die("farfetch FAR_WRITE");
	free(buf);
	free(bufout);
}
