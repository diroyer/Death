#ifndef DAEMON_H
#define DAEMON_H

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


typedef ret_t (*command_func_t)(param_t *);


#endif
