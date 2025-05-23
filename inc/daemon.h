#ifndef DAEMON_H
#define DAEMON_H
#include <signal.h>

//#include <signal.h>

int	daemonize(char **envp);

typedef int ret_t;

typedef struct param_s {
	int client_fd;
	char **envp;
} param_t;

typedef struct command_s {
	char *name;
	ret_t (*func)(param_t *);
} command_t;

//#define NSIG_WORDS (NSIG / (8 * sizeof(unsigned long int)))
//#define NSIG_WORDS (1024 / (8 * sizeof(unsigned long int)))

typedef struct {
	unsigned long int __val[_SIGSET_NWORDS];
} kernel_sigset_t;

typedef ret_t (*command_func_t)(param_t *);

#endif
