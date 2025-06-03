/* test gpid with setsid etc... */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int	main(void) {
	int pid = getpid();
	int ppid = getppid();
	int gpid = getpgrp();
	printf("pid               : %d, ppid: %d, gpid: %d\n", pid, ppid, gpid);

	pid_t forked = fork();
	if (forked < 0) {
		perror("fork failed");
		return 1;
	} else if (forked == 0) {

		setsid(); // Create a new session and set the process group ID

		printf("Child process : pid: %d, ppid: %d, gpid: %d\n", getpid(), getppid(), getpgrp());
	} else {
		printf("Parent process: pid: %d, ppid: %d, gpid: %d\n", getpid(), getppid(), getpgrp());
	}

}
