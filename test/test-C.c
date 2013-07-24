#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "packet_generator.h"
#include "repo_publisher.h"

static struct {
	size_t length;
	char *response;
} responses[] = {
	{38, "\x00\x00\x01\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02this is a test!"},
	{25, "\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04te"},
	{25, "\x00\x03\x01st2\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"},
	{13, "\x00\x00\x00\x04testtest3"},
	{0, NULL}
};

static test_no;

static ssize_t
tester(void *state, ccn_charbuf_t const *data)
{
	int r;

	if (!responses[test_no].response) {
		printf("!!!Testcase number exhausted!!!!\n");
		abort();
		return -1;
	}

	r = memcmp(data->buf, responses[test_no].response, responses[test_no].length);
	test_no++;

	if (r)
		fwrite(data->buf, data->length, 1, stdout);
	assert(r == 0);

	return r;
}

int main() {
	packet_gen_t *pg;

	pg = packet_gen_new(NULL, 0);
	pg->repo_publisher.func = tester;
	packet_gen_set_base_name(pg, "/usr/local");
	packet_gen_push_data(pg, "this is a test!", 15, 1, 2, 1, 1);
	pg->chunk_size = 22;
	packet_gen_push_data(pg, "test2", 5, 3, 4, 1, 0);
	packet_gen_push_data(pg, "testtest3", 9, 4, 4, 0, 1);
	packet_gen_free(pg);

	return 0;
}
