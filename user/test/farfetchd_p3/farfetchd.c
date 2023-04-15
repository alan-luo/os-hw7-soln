#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>

static inline void die(const char *s)
{
	perror(s);
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <pid> <addr> <len>\n", argv[0]);
		exit(1);
	}

	pid_t target_pid = atoi(argv[1]);
	unsigned long target_addr = strtol(argv[2], NULL, 0);
	size_t len = atol(argv[3]);

	int ffd = open("/dev/farfetch", O_RDWR);
	if (ffd == -1)
		die("open /dev/farfetch");

	if (ioctl(ffd, 0, target_pid) == -1)
		die("ioctl");

	char *buf = malloc(len);

	if (buf == NULL)
		die("malloc");

	if (lseek(ffd, target_addr, SEEK_SET) == -1)
		die("lseek");
	long fetched = read(ffd, buf, len);

	if (fetched < 0)
		die("read");

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

	if (memcmp(buf, bufout, fetched) != 0) {
		if (lseek(ffd, target_addr, SEEK_SET) == -1)
			die("lseek");
		if (write(ffd, bufout, fetched) < 0)
			die("write");
	}
	free(buf);
	free(bufout);
	close(ffd);
}
