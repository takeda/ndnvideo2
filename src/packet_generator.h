#ifndef PACKET_GENERATOR_H
#define PACKET_GENERATOR_H

#include <stdbool.h>
#include <stdint.h>

#include "ccnx.h"
#include "repo_publisher.h"

typedef struct packet_gen {
	uintmax_t segment;
	unsigned int chunk_size;

	ccn_keystore_t *key_store;
	ccn_charbuf_t *name_base;
	ccn_charbuf_t *name_segments;
	ccn_charbuf_t *name_index;

	struct {
		ssize_t (*func)(void *, ccn_charbuf_t const *);
		void *state;
	} repo_publisher;

	struct {
		struct ccn_charbuf *buf;
		unsigned int count;
		unsigned int offset;
	} elements;
	struct ccn_charbuf *packet;
	struct content_state *cs_data;
	struct content_state *cs_index;

	bool running;
} packet_gen_t;

struct __attribute__((packed)) element_header {
	uint32_t length;
	uint64_t timestamp;
	uint64_t duration;
};

struct __attribute__((packed)) packet_header {
	uint16_t offset;
	uint8_t count;
};

packet_gen_t *packet_gen_new(repo_publisher_t *repo_publisher, unsigned int max_size);
void packet_gen_free(packet_gen_t *pg);
void packet_gen_set_base_name(packet_gen_t *pg, char const *name);
void packet_gen_push_data(packet_gen_t *pg, void const *data, size_t data_len,
		uint64_t timestamp, uint64_t duration, bool start_fresh, bool flush);
void packet_gen_stream_info(packet_gen_t *pg, char const *caps);
void packet_gen_push_index(packet_gen_t *pg, uint64_t index);

#endif /* PACKET_GENERATOR_H */
