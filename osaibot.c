#include "config.h"

#include "bashtypes.h"

#include "error.h"
#include "xmalloc.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

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
	send(sock, prompt, strlen(prompt), 0);
}

static void *osaibot_input_thread_fn(void *unused)
{
	struct sockaddr_un sockaddr = {
		.sun_family = AF_UNIX,
		.sun_path = "/tmp/socket",
	};

	// TODO: SOCK_SEQPACKET
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock == -1)
		fatal_error("socket failed");

	if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
		fatal_error("connect failed");

	while (true) {
		struct pending_command **ptr;
		struct pending_command *input;
		char *buf;
		int size;
		
		size = recv(sock, NULL, 0, MSG_PEEK|MSG_TRUNC);
		if (size < 0)
			fatal_error("recv failed");

		buf = xmalloc(size + 1);
		if (recv(sock, buf, size, 0) != size)
			fatal_error("recv failed");

		if (!size) {
			pthread_mutex_lock(&input_lock);
			inputs_done = true;
			pthread_cond_signal(&input_cv);
			pthread_mutex_unlock(&input_lock);
			
			break;
		}
		
		buf[size] = '\0';
		input = xmalloc(sizeof(*input));
		*input = (struct pending_command) {
			.string = buf,
			.length = size,
		};
		
		pthread_mutex_lock(&input_lock);
		for (ptr = &inputs_pending; *ptr; ptr = &(*ptr)->next);
		
		*ptr = input;
		pthread_cond_signal(&input_cv);
		pthread_mutex_unlock(&input_lock);
	}

	return NULL;
}

int osaibot_init(void)
{
	pthread_t thread;

	if (pthread_create(&thread, NULL, osaibot_input_thread_fn, NULL))
		fatal_error("pthread_create failed");
}
