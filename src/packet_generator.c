#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ccn/charbuf.h>
#include "ccnx.h"

#include "packet_generator.h"

static void
send_data(packet_gen_t *pg, size_t size)
{
	struct packet_header hdr;
	unsigned int offset;
	int r;
	ccn_charbuf_t *name;

	assert(pg);

	if (!size)
		size = pg->elements.buf->length;

	assert(size <= pg->elements.buf->length);

	hdr.offset = pg->elements.count == 0 ? 0 : htobe16(pg->elements.offset);
	hdr.count = pg->elements.count;

	ccn_charbuf_reset(pg->packet);
	r = ccn_charbuf_append(pg->packet, &hdr, sizeof(hdr));
	r |= ccn_charbuf_append(pg->packet, pg->elements.buf->buf, size);

#if 1
	name = name_append_numeric(pg->name_segments, CCN_MARKER_SEQNUM, pg->segment++);

	struct ccn_charbuf *cb = name_to_uri(name);
	fprintf(stderr, "Name = %s\n", cb->buf);
	ccn_charbuf_destroy(&cb);

	r = content_object_from_data(pg->cs_data, pg->packet->buf,
			pg->packet->length, name);
	ccn_charbuf_destroy(&name);

	r = pg->repo_publisher.func(pg->repo_publisher.state, pg->cs_data->content_object);
	if (r < 0) {
		fprintf(stderr, "Error while publishing: %d\n", r);
		abort();
	}
#else
	r = pg->repo_publisher.func(pg->repo_publisher.state, pg->packet);
	if (r < 0) {
		fprintf(stderr, "Error while publishing: %d\n", r);
		abort();
	}
#endif

	pg->elements.buf->length -= size;
	pg->elements.offset = pg->elements.buf->length;
	memmove(pg->elements.buf->buf, pg->elements.buf->buf + size, pg->elements.buf->length);
	pg->elements.count = 0;
}

packet_gen_t *
packet_gen_new(repo_publisher_t *repo_publisher, unsigned int max_size)
{
	packet_gen_t *pg;

	if (!max_size)
		max_size = 3900;

	pg = calloc(1, sizeof(packet_gen_t));
	*pg = (packet_gen_t) {
		.chunk_size = max_size - sizeof(struct packet_header),
		.key_store = get_default_key_store(),
		.repo_publisher.func = repo_publisher_put,
		.repo_publisher.state = repo_publisher,
		.elements.buf = ccn_charbuf_create(),
		.packet = ccn_charbuf_create()
	};

	pg->cs_data = content_state_new(CCN_CONTENT_DATA, -1, pg->key_store);
	JUMP_IF_NULL(pg->cs_data, error);

	pg->cs_index = content_state_new(CCN_CONTENT_DATA, 1, pg->key_store);
	JUMP_IF_NULL(pg->cs_index, error);

	return pg;

free_packet_gen:
	packet_gen_free(pg);
error:
	return NULL;
}

void
packet_gen_free(packet_gen_t *pg)
{
	name_destroy(pg->name_base);
	name_destroy(pg->name_segments);
	name_destroy(pg->name_index);
	content_state_free(pg->cs_index);
	content_state_free(pg->cs_data);
	ccn_keystore_destroy(&pg->key_store);
	ccn_charbuf_destroy(&pg->elements.buf);
	ccn_charbuf_destroy(&pg->packet);
	free(pg);
}

void
packet_gen_set_base_name(packet_gen_t *pg, char const *name)
{
	name_destroy(pg->name_base);
	name_destroy(pg->name_segments);
	name_destroy(pg->name_index);

	pg->name_base = name_from_uri(name);
	pg->name_segments = name_append_str(pg->name_base, "segments");
	pg->name_index = name_append_str(pg->name_base, "index");
}

void
packet_gen_push_data(packet_gen_t *pg, void const *data,
		size_t data_len, uint64_t timestamp, uint64_t duration,
		bool start_fresh, bool flush)
{
	struct element_header hdr;
	int r;
	unsigned int no_chunks, packet_size;

	if (start_fresh && pg->elements.buf->length)
		send_data(pg, 0);

	hdr.length = htobe32(data_len);
	hdr.timestamp = htobe64(timestamp);
	hdr.duration = htobe64(duration);
	r = ccn_charbuf_append(pg->elements.buf, &hdr, sizeof(hdr));
	r |= ccn_charbuf_append(pg->elements.buf, data, data_len);

	if (r) {
		perror("ccn_charbuf_append");
		abort();
	}

	pg->elements.count += 1;

	no_chunks = ceilf((float) pg->elements.buf->length / pg->chunk_size);
	while (no_chunks >= 2) {
		packet_size = pg->chunk_size < pg->elements.buf->length
			? pg->chunk_size : pg->elements.buf->length;
		no_chunks--;
		send_data(pg, packet_size);
	}
	assert(no_chunks == 1);

	if (pg->elements.buf->length == pg->chunk_size || flush)
		send_data(pg, 0);
}

void
packet_gen_key(packet_gen_t *pg)
{
	struct content_state *cs;
	struct ccn_charbuf *name;
	int r;

	cs = content_state_new(CCN_CONTENT_KEY, -1, pg->cs_data->key_store);
	if (!cs)
		return;

	name = name_append_str(pg->name_base, "key");
	JUMP_IF_NULL(name, free_cs);

	r = content_state_set_keylocator_from_name(pg->cs_data, name);
	JUMP_IF_NEG(r, free_name);

	r = content_state_set_keylocator_from_name(pg->cs_index, name);
	JUMP_IF_NEG(r, free_name);

	r = content_state_key_object(cs, name);
	JUMP_IF_NEG(r, free_name);

	r = pg->repo_publisher.func(pg->repo_publisher.state, cs->content_object);

free_name:
	name_destroy(name);
free_cs:
	content_state_free(cs);
}

void
packet_gen_stream_info(packet_gen_t *pg, char const *caps)
{
	struct ccn_charbuf *name;
	int r;

	assert(pg);
	assert(caps);

	name = name_append_str(pg->name_base, "stream_info");
	r = content_object_from_data(pg->cs_data, caps, strlen(caps), name);
	name_destroy(name);

	if (r < 0) {
		fprintf(stderr, "Unable to generate stream_info: %s\n", get_err());
		abort();
	}

	r = pg->repo_publisher.func(pg->repo_publisher.state, pg->cs_data->content_object);
	if (r < 0) {
		fprintf(stderr, "Error while publishing index");
		abort();
	}
}

void
packet_gen_push_index(packet_gen_t *pg, uint64_t index)
{
	struct ccn_charbuf *name;
	char segment_str[32];
	int segment_str_len;
	int r;

	assert(pg);

	segment_str_len = snprintf(segment_str, sizeof(segment_str), "%u",
			pg->segment);
	assert(segment_str_len > 0);

	name = name_append_numeric(pg->name_index, CCN_MARKER_SEQNUM, index);
	r = content_object_from_data(pg->cs_index, segment_str, segment_str_len,
			name);
	name_destroy(name);
	if (r < 0) {
		fprintf(stderr, "Unable to generate index: %s\n", get_err());
		abort();
	}

	r = pg->repo_publisher.func(pg->repo_publisher.state, pg->cs_index->content_object);
	if (r < 0) {
		fprintf(stderr, "Error while publishing index");
		abort();
	}
}
