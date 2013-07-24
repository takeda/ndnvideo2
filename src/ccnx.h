#ifndef CCNX_H
#define CCNX_H

#include <stdarg.h>
#include <stdint.h>

#include <ccn/ccn.h>

typedef struct ccn_keystore ccn_keystore_t;
typedef struct ccn_charbuf ccn_charbuf_t;
typedef enum ccn_content_type ccn_content_type_t;

typedef struct content_state {
	struct ccn_keystore const *key_store;
	unsigned char const *key_id;
	ssize_t key_id_len;
	struct ccn_pkey const *public_key;
	struct ccn_pkey const *private_key;
	enum ccn_content_type type;
	int freshness;
	struct ccn_charbuf *key_locator;
	struct ccn_charbuf *signed_info;
	struct ccn_charbuf *content_object;
	int ready_key_locator;
	int ready_signed_info;
} content_state_t;

char const *get_err();
ccn_keystore_t *get_default_key_store();
ccn_charbuf_t *keylocator_from_key(ccn_keystore_t const *ks);
void name_destroy(ccn_charbuf_t *c);
ccn_charbuf_t *name_from_uri(char const *name);
ccn_charbuf_t *name_to_uri(ccn_charbuf_t const *name);
ccn_charbuf_t *name_clone(ccn_charbuf_t const *c);
ccn_charbuf_t *name_append_str(ccn_charbuf_t *c, char const *segment);
ccn_charbuf_t *name_append_numeric(ccn_charbuf_t *c, enum ccn_marker marker,
		uintmax_t value);
content_state_t *content_state_new(ccn_content_type_t type, int freshness,
		ccn_keystore_t const *ks);
void content_state_free(content_state_t *cs);
int content_state_set_keylocator_from_key(content_state_t *cs);
int content_state_set_keylocator_from_name(content_state_t *cs,
		ccn_charbuf_t const *name);
int content_state_key_object(content_state_t *cs, ccn_charbuf_t const *name);
int generate_signed_info(content_state_t *cs);
int content_object_from_data(content_state_t *cs, void const *data,
		size_t data_len, ccn_charbuf_t const *name);

#define SET_ERR(...) \
do { \
	set_err(__FILE__, __LINE__, __VA_ARGS__); \
} while (0)

#define JUMP_IF_NULL(variable, label) \
do { \
	if (!variable) \
		goto label; \
} while(0)

#define JUMP_IF_NULL_MSG(variable, label, ...) \
do { \
	if (!variable) { \
		set_err(__FILE__, __LINE__, __VA_ARGS__); \
		goto label; \
	} \
} while(0)

#define JUMP_IF_NULL_ERRNO(variable, label) \
do { \
	if (!variable) { \
		set_err(__FILE__, __LINE__, "Got error: %s", strerror(errno)); \
		goto label; \
	} \
} while(0)

#define JUMP_IF_NEG(variable, label) \
do { \
	if (variable < 0) \
		goto label; \
} while(0)

#define JUMP_IF_NEG_MSG(variable, label, ...) \
do { \
	if (variable < 0) { \
		set_err(__FILE__, __LINE__, __VA_ARGS__); \
		goto label; \
	} \
} while(0)

#define JUMP_IF_NEG_ERRNO(variable, label) \
do { \
	if (variable < 0) { \
		set_err(__FILE__, __LINE__, "Got error: %s", strerror(errno)); \
		goto label; \
	} \
} while(0)

#endif /* CCNX_H */
