#include "config.h"

#include "bashtypes.h"

#include "error.h"
#include "shell.h"
#include "xmalloc.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

enum osaibot_command {
	CMD_INPUT = 1,
	CMD_SIGNAL = 2,
};

enum osaibot_response {
	RESP_PROMPT = 1,
	RESP_BEGIN = 2,
};

struct pending_command {
	struct pending_command *next;
	char *string;
	size_t offset;
	size_t length;
};

static pthread_mutex_t input_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t input_cv = PTHREAD_COND_INITIALIZER;

static struct pending_command *inputs_pending;
static bool inputs_done;

static int sock;

static void send_fd(int sock, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(cmsg)) = fd;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(sock, &msg, 0) < 0)
		fatal_error("sendmsg failed");
}

int osaibot_getc(void)
{
	struct pending_command *input;
	char c;

	pthread_mutex_lock(&input_lock);
	while (!(input = inputs_pending) && !inputs_done)
		pthread_cond_wait(&input_cv, &input_lock);

	if (!input) {
		pthread_mutex_unlock(&input_lock);
		return EOF;
	}

	c = input->string[input->offset++];
	if (input->offset == input->length) {
		inputs_pending = input->next;
		xfree(input->string);
		xfree(input);
	}
	pthread_mutex_unlock(&input_lock);

	return c;
}

int osaibot_ungetc(int c)
{
	pthread_mutex_lock(&input_lock);
	if (!inputs_pending)
		goto bad;

	if (!inputs_pending->offset)
		goto bad;

	inputs_pending->string[--inputs_pending->offset] = c;
	pthread_mutex_unlock(&input_lock);
	return c;

bad:
	pthread_mutex_unlock(&input_lock);
	return EOF;
}

void osaibot_prompt(char *prompt)
{
	size_t len = strlen(prompt);
	struct termios termios;
	char buf[len + 1];

	// Enforce TOSTOP. Background processes may not display to terminal.
	if (tcgetattr(STDIN_FILENO, &termios) < 0)
		fatal_error("tcgetattr failed");

	termios.c_lflag |= TOSTOP;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios) < 0)
		fatal_error("tcsetattr failed");

	memcpy(buf + 1, prompt, len);
	buf[0] = RESP_PROMPT;
	send(sock, buf, sizeof(buf), 0);
}

void osaibot_begin_execute(void)
{
	char buf[1] = { RESP_BEGIN };

	send(sock, buf, sizeof(buf), 0);
}

static void *osaibot_input_thread_fn(void *unused)
{
	while (true) {
		char *buf;
		int size;

		size = recv(sock, NULL, 0, MSG_PEEK | MSG_TRUNC);
		if (size < 0)
			fatal_error("recv failed");

		buf = xmalloc(size);
		if (recv(sock, buf, size, 0) != size)
			fatal_error("recv failed");

		if (!size) {
			pthread_mutex_lock(&input_lock);
			inputs_done = true;
			pthread_cond_signal(&input_cv);
			pthread_mutex_unlock(&input_lock);

			break;
		}

		switch (buf[0]) {
		case CMD_INPUT:
		{
			struct pending_command *input;
			struct pending_command **ptr;
			char *input_str;

			input_str = xmalloc(size);
			input_str[size - 1] = '\0';
			memcpy(input_str, buf + 1, size - 1);

			input = xmalloc(sizeof(*input));
			*input = (struct pending_command) {
				.string = input_str,
				.length = size,
			};

			pthread_mutex_lock(&input_lock);
			// Insert to back of linked list
			for (ptr = &inputs_pending; *ptr; ptr = &(*ptr)->next);
			*ptr = input;
			pthread_cond_signal(&input_cv);
			pthread_mutex_unlock(&input_lock);

			break;
		}
		case CMD_SIGNAL:
		{
			pid_t foreground_pgid;
			int signum;

			if (size < 1 + sizeof(int))
				break;
			signum = *(int *)(buf + 1);

			foreground_pgid = tcgetpgrp(0);
			if (foreground_pgid < 0)
				break;
			if (foreground_pgid == getpid())
				break;

			kill(-foreground_pgid, signum);
			break;
		}
		}

		xfree(buf);
	}

	return NULL;
}

int osaibot_init(void)
{
	char *sock_fd_env;
	char *exe_fd_env;
	pthread_t thread;
	int netnsfd;
	int pidfd;
	int exefd;
	int flags;

	no_line_editing = 1;

	sock_fd_env = getenv("SOCK_FD");
	if (!sock_fd_env)
		fatal_error("missing env var SOCK_FD");

	sock = atoi(sock_fd_env);
	unsetenv("SOCK_FD");

	flags = fcntl(sock, F_GETFD);
	if (flags < 0)
		fatal_error("fcntl failed");
	if (fcntl(sock, F_SETFD, flags | FD_CLOEXEC))
		fatal_error("fcntl failed");

	flags = fcntl(sock, F_GETFL);
	if (flags < 0)
		fatal_error("fcntl failed");
	if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK))
		fatal_error("fcntl failed");

	exe_fd_env = getenv("EXE_FD");
	if (!exe_fd_env)
		fatal_error("missing env var EXE_FD");

	exefd = atoi(exe_fd_env);
	unsetenv("EXE_FD");

	close(exefd);

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd < 0)
		fatal_error("pidfd_open failed");

	send_fd(sock, pidfd);
	close(pidfd);

	netnsfd = open("/proc/self/ns/net", O_RDONLY);
	if (netnsfd < 0)
		fatal_error("pidfd_open failed");
	send_fd(sock, netnsfd);
	close(netnsfd);

	if (pthread_create(&thread, NULL, osaibot_input_thread_fn, NULL))
		fatal_error("pthread_create failed");
}
