#ifndef DAEMON_H
#define DAEMON_H

#include <stdint.h>
#include <stdbool.h>

#define NB_SERVER 1
#define NB_SIGNAL 1

int	daemonize(char **envp);

typedef struct event_s {
	int fd;
	int epoll_fd;
	void (*handle_event)(struct event_s *self, uint32_t events);
	void *context;
} event_t;

typedef struct client_s {

	bool shell_active;
	char pty_name[32];
	event_t client_ev;
	event_t master_ev;
} client_t;

typedef struct signal_s {
	event_t event;
} signal_t;

typedef struct server_s {
	event_t event;
	client_t *client;
	signal_t *signal;
} server_t;

typedef struct param_s {
	client_t *client;
	char **envp;
} param_t;

typedef struct command_s {
	char *name;
	int (*func)(param_t *);
} command_t;

#endif
