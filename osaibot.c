#include "config.h"

#include "bashtypes.h"

#include "error.h"
#include "shell.h"
#include "xmalloc.h"

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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

static pthread_mutex_t input_thread_initialized = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_thread_initialized = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t input_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t input_cv = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t output_ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t output_complete = PTHREAD_COND_INITIALIZER;

static struct pending_command *inputs_pending;
static bool inputs_done;

// There can only be at most one pending output. We can simplify this rather
// than having a list
static const void *pending_output;
static size_t pending_output_len;

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

static void *osaibot_output_thread_fn(void *unused)
{
	pthread_setname_np(pthread_self(), "bash-output");
	pthread_mutex_unlock(&output_thread_initialized);

	while (true) {
		pthread_mutex_lock(&output_lock);
		while (!pending_output)
			pthread_cond_wait(&output_ready, &output_lock);

		send(sock, pending_output, pending_output_len, 0);
		pending_output = NULL;
		pthread_cond_signal(&output_complete);

		pthread_mutex_unlock(&output_lock);
	}
}

static void *osaibot_output_rpc(const void *buf, size_t len)
{
	pthread_mutex_lock(&output_lock);

	pending_output = buf;
	pending_output_len = len;
	pthread_cond_signal(&output_ready);

	while (pending_output)
		pthread_cond_wait(&output_complete, &output_lock);

	pthread_mutex_unlock(&output_lock);
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
	osaibot_output_rpc(buf, sizeof(buf));
}

void osaibot_begin_execute(void)
{
	char buf[1] = { RESP_BEGIN };

	osaibot_output_rpc(buf, sizeof(buf));
}

static void *osaibot_input_thread_fn(void *unused)
{
	pthread_setname_np(pthread_self(), "bash-input");
	pthread_mutex_unlock(&input_thread_initialized);

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

static void osaibot_syscall_rewrite(int sig_num, siginfo_t *siginfo, void *_ucontext)
{
	ucontext_t *ucontext = _ucontext;
	void osaibot_syscall_tramp(void);

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

	if (siginfo->si_signo != SIGSYS ||
	    siginfo->si_code != SYS_SECCOMP ||
	    siginfo->si_arch != AUDIT_ARCH_X86_64)
		return;

	if (ucontext->uc_mcontext.gregs[REG_RAX] != siginfo->si_syscall)
		fatal_error("syscall asserion error");

	switch (siginfo->si_syscall) {
	case SYS_clone: {
		void *stack;

		// RDI = flags
		ucontext->uc_mcontext.gregs[REG_RDI] &= ~CLONE_FILES;

		stack = ucontext->uc_mcontext.gregs[REG_RSI];
		if (stack)
			*(((void **)stack) - 1) = (void *)ucontext->uc_mcontext.gregs[REG_RIP];

		break;
	}
	case SYS_rt_sigprocmask: {
		// RDI = how
		int how = ucontext->uc_mcontext.gregs[REG_RDI];
		if (how == SIG_BLOCK || how == SIG_SETMASK) {
			sigset_t *oldset = (void *)ucontext->uc_mcontext.gregs[REG_RSI];

			if (oldset && sigismember(oldset, SIGSYS)) {
				size_t sigsetsize = ucontext->uc_mcontext.gregs[REG_R10];
				// This is not very safe per-se, but there should be quite a lot of buffer
				sigset_t *newset = alloca(sigsetsize);

				memcpy(newset, oldset, sigsetsize);
				sigdelset(newset, SIGSYS);
				ucontext->uc_mcontext.gregs[REG_RSI] = (uintptr_t)newset;
			}
		}
		break;
	}
	default:
		fatal_error("syscall asserion error");
	}

	*(((void **)ucontext->uc_mcontext.gregs[REG_RSP]) - 1) =
		(void *)ucontext->uc_mcontext.gregs[REG_RIP];
	ucontext->uc_mcontext.gregs[REG_RIP] = (uintptr_t)&osaibot_syscall_tramp;
}

static void *osaibot_thread_wrapper(void *unused)
{
	void osaibot_end_syscall(void);
	union {
		void *ptr;
		struct {
			uint32_t first_half;
			uint32_t second_half;
		};
	} end_syscall_halves = { &osaibot_end_syscall };
	struct sock_filter filter[] = {
		// if this is post-hook, allow immediately
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, end_syscall_halves.first_half, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, end_syscall_halves.second_half, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

		// No execve, filter should not affect other processes.
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),

		// glibc masks all signals on thread creation to avoid races.
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

		// Force clone instead of clone3
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_FILES, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

	};
	struct sock_fprog prog = {
		.len = ARRAY_SIZE(filter),
		.filter = filter,
	};
	struct sigaction act = {
		.sa_sigaction = osaibot_syscall_rewrite,
		.sa_flags = SA_NODEFER | SA_SIGINFO,
	};
	pthread_t input_thread;
	pthread_t output_thread;
	int res;

	sigemptyset(&act.sa_mask);

	if (sigaction(SIGSYS, &act, NULL))
		fatal_error("sigaction failed");

	// We don't set SECCOMP_FILTER_FLAG_TSYNC, so this filter is thread-local.
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
		fatal_error("seccomp failed");

	if (pthread_create(&input_thread, NULL, osaibot_input_thread_fn, NULL))
		fatal_error("pthread_create failed");
	if (pthread_create(&output_thread, NULL, osaibot_output_thread_fn, NULL))
		fatal_error("pthread_create failed");

	return NULL;
}


static void osaibot_init_caps(void)
{
	cap_t cap_p;
	int res;

	res = cap_drop_bound(CAP_SYS_PTRACE);
	if (res < 0)
		fatal_error("cap_drop_bound(CAP_SYS_PTRACE) failed");

	cap_p = cap_get_proc();
	if (!cap_p)
		fatal_error("cap_get_proc failed");

	res = cap_clear_flag(cap_p, CAP_INHERITABLE);
	if (res < 0)
		fatal_error("cap_clear_flag failed");

	res = cap_set_proc(cap_p);
	if (res < 0)
		fatal_error("cap_set_proc failed");

	res = cap_free(cap_p);
	if (res < 0)
		fatal_error("cap_free failed");
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

	pthread_setname_np(pthread_self(), "bash");

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

	osaibot_init_caps();

	// Wait for the initialization of the threads, before we close the sock
	pthread_mutex_lock(&input_thread_initialized);
	pthread_mutex_lock(&output_thread_initialized);

	if (pthread_create(&thread, NULL, osaibot_thread_wrapper, NULL))
		fatal_error("pthread_create failed");

	pthread_mutex_lock(&input_thread_initialized);
	pthread_mutex_lock(&output_thread_initialized);

	close(sock);
}
