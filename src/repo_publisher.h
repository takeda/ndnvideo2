#ifndef REPO_PUBLISHER_H
#define REPO_PUBLISHER_H

#include <stdio.h>

#include "ccnx.h"

struct repo_publisher;
typedef struct repo_publisher repo_publisher_t;

repo_publisher_t * repo_publisher_new(unsigned short repo_port);
void repo_publisher_free(repo_publisher_t *rp);
int repo_publisher_connect(repo_publisher_t *rp);
ssize_t repo_publisher_put(void *state, ccn_charbuf_t const *data);

#endif /* REPO_PUBLISHER_H */
