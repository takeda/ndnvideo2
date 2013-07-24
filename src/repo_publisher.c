#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ccn/charbuf.h>

#include "ccnx.h"

typedef struct {
	unsigned short port;
	int socket;
	int active;
	struct ccn *handle;
} repo_publisher_t;

void
repo_publisher_free(repo_publisher_t *rp)
{
	assert(rp);

	if (rp->active)
		close(rp->socket);

	ccn_destroy(&rp->handle);
	free(rp);
}

repo_publisher_t *
repo_publisher_new(unsigned short repo_port)
{
	char const *str_port;
	repo_publisher_t *rp;

	if (!repo_port) {
		str_port = getenv("CCNR_STATUS_PORT");
		if (str_port)
			repo_port = atoi(str_port);
	}

	rp = calloc(1, sizeof(repo_publisher_t));
	JUMP_IF_NULL(rp, error);

	rp->port = repo_port;

	rp->handle = ccn_create();
	JUMP_IF_NULL(rp->handle, free_rp);

	ccn_connect(rp->handle, NULL);

	return rp;

free_rp:
	repo_publisher_free(rp);
error:
	return NULL;
}

int
repo_publisher_connect(repo_publisher_t *rp)
{
	int r;
	struct sockaddr_in serv_addr;

	assert(rp);

	bzero(&serv_addr, sizeof(serv_addr));

	serv_addr.sin_port = htons(rp->port);
	serv_addr.sin_family = AF_INET;
	inet_pton(serv_addr.sin_family, "127.0.0.1", &serv_addr.sin_addr);

	rp->socket = socket(PF_INET, SOCK_STREAM, 0);
	r = connect(rp->socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (r == 0)
		rp->active = 1;

	return r;
}

ssize_t
repo_publisher_put(void *state, ccn_charbuf_t const *data)
{
	repo_publisher_t *rp = (repo_publisher_t *) state;
	ssize_t r;
	char *buf[32];

	assert(rp);
	assert(data);

	if (!rp->active && repo_publisher_connect(rp)) {
		fprintf(stderr, "Error connecting to the repo on port %u\n", rp->port);
		return -1;
	}

	r = recv(rp->socket, buf, sizeof(buf), MSG_DONTWAIT);
	if (r == 0) {
		rp->active = 0;
		fprintf(stderr, "Connection to the repo was closed.\n");
		return -1;
	}

	r = send(rp->socket, data->buf, data->length, 0);

	ccn_put(rp->handle, data->buf, data->length);

	return r;
}

