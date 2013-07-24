#include <assert.h>
#include <stdlib.h>

#include <ccn/charbuf.h>
#include <ccn/keystore.h>
#include <ccn/uri.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "ccnx.h"

static struct ccn_charbuf *error_message;

static void
set_err(char const *file, int line, char const *fmt, ...)
{
	va_list ap;

	if (!error_message)
		error_message = ccn_charbuf_create();

	ccn_charbuf_reset(error_message);

	va_start(ap, fmt);
	ccn_charbuf_putf(error_message, fmt, ap);
	va_end(ap);
}

char const *
get_err()
{
	if (!error_message)
		return NULL;

	return error_message->buf;
}

#if 0
static struct ccn_pkey *
private_key_dup(const struct ccn_pkey *key) {
	EVP_PKEY *new_key;
	RSA *orig_key;
	unsigned int *err;
	int r;

	new_key = EVP_PKEY_new();
	JUMP_IF_NULL(new_key, error);

	orig_key = EVP_PKEY_get1_RSA((EVP_PKEY *) key);
	JUMP_IF_NULL(orig_key, free_evp_key);

	r = EVP_PKEY_set1_RSA(new_key, orig_key);
	RSA_free(orig_key);
	JUMP_IF_NEG(r, free_evp_key);

	return (struct ccn_pkey *) new_key;

free_evp_key:
	EVP_PKEY_free(private_key);
error:
	err = ERR_get_error();
	SET_ERR("Unable to generate keypair from the key: %s",
		ERR_reason_error_string(err));

	return NULL;
}
#endif

ccn_keystore_t *
get_default_key_store()
{
	struct ccn_charbuf *path;
	struct ccn_keystore *ks;
	char *p;
	int r;

	p = getenv("HOME");
	JUMP_IF_NULL(p, exit);

	path = ccn_charbuf_create();
	JUMP_IF_NULL(path, exit);

	r = ccn_charbuf_putf(path, "%s/.ccnx/.ccnx_keystore", p);
	JUMP_IF_NEG(r, charbuf_free);

	p = ccn_charbuf_as_string(path);
	JUMP_IF_NULL(p, charbuf_free);

	ks = ccn_keystore_create();
	JUMP_IF_NULL(ks, charbuf_free);

	r = ccn_keystore_init(ks, p, "Th1s1sn0t8g00dp8ssw0rd.");
	ccn_charbuf_destroy(&path);
	JUMP_IF_NEG(r, keystore_free);

	return ks;

keystore_free:
	ccn_keystore_destroy(&ks);
charbuf_free:
	ccn_charbuf_destroy(&path);
exit:
	return NULL;
}

int
get_key_der_public(ccn_charbuf_t *c, ccn_keystore_t const *ks)
{
	EVP_PKEY *pub_key;
	unsigned char *p;
	unsigned long err;
	size_t bytes;
	int r;

	pub_key = (EVP_PKEY *) ccn_keystore_public_key((struct ccn_keystore *) ks);

	r = i2d_PUBKEY(pub_key, NULL);
	JUMP_IF_NEG(r, openssl_exit);

	bytes = r;
	p = ccn_charbuf_reserve(c, bytes);
	JUMP_IF_NULL(p, exit);

	r = i2d_PUBKEY(pub_key, &p);
	if (r != bytes)
		goto openssl_exit;

	c->length += bytes;

	return bytes;

openssl_exit:
	err = ERR_get_error();
	SET_ERR("Unable to obtain public key: %s", ERR_reason_error_string(err));
exit:
	return -1;
}

ccn_charbuf_t *
keylocator_from_name(ccn_charbuf_t const *name)
{
	struct ccn_charbuf *keylocator;
	int r;

	keylocator = ccn_charbuf_create();
	JUMP_IF_NULL(keylocator, exit);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyName, CCN_DTAG);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_charbuf_append_charbuf(keylocator, name);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_charbuf_append_closer(keylocator);
	JUMP_IF_NEG(r, charbuf_free); /* </KeyName> */

	r = ccn_charbuf_append_closer(keylocator);
	JUMP_IF_NEG(r, charbuf_free); /* </KeyLocator> */

	return keylocator;

charbuf_free:
	ccn_charbuf_destroy(&keylocator);
exit:
	return NULL;
}

ccn_charbuf_t *
keylocator_from_key(ccn_keystore_t const *ks)
{
	struct ccn_charbuf *keylocator;
	struct ccn_pkey const *pkey;
	int r;

	pkey = ccn_keystore_public_key((struct ccn_keystore *) ks);
	JUMP_IF_NEG(pkey, fail);

	keylocator = ccn_charbuf_create();
	JUMP_IF_NULL(keylocator, fail);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_charbuf_append_tt(keylocator, CCN_DTAG_Key, CCN_DTAG);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_append_pubkey_blob(keylocator, pkey);
	JUMP_IF_NEG(r, charbuf_free);

	r = ccn_charbuf_append_closer(keylocator);
	JUMP_IF_NEG(r, charbuf_free); /* </Key> */

	r = ccn_charbuf_append_closer(keylocator);
	JUMP_IF_NEG(r, charbuf_free); /* </KeyLocator> */

	return keylocator;

charbuf_free:
	ccn_charbuf_destroy(&keylocator);
fail:
	return NULL;
}

void
name_destroy(ccn_charbuf_t *c)
{
	ccn_charbuf_destroy(&c);
}

ccn_charbuf_t *
name_from_uri(char const *name)
{
	struct ccn_charbuf *c;
	int r;

	c = ccn_charbuf_create();
	JUMP_IF_NULL(c, exit);

	r = ccn_name_from_uri(c, name);
	JUMP_IF_NEG_MSG(r, free_charbuf, "Invalid URL");

	return c;

free_charbuf:
	ccn_charbuf_destroy(&c);
exit:
	return NULL;
}

ccn_charbuf_t *
name_to_uri(ccn_charbuf_t const *name)
{
	struct ccn_charbuf *c;
	int r;

	c = ccn_charbuf_create();
	JUMP_IF_NULL(c, exit);

	r = ccn_uri_append(c, name->buf, name->length, 0);
	JUMP_IF_NEG(r, free_charbuf);

	return c;

free_charbuf:
	ccn_charbuf_destroy(&c);
exit:
	return NULL;
}

ccn_charbuf_t *
name_clone(ccn_charbuf_t const *c)
{
	struct ccn_charbuf *new_name;
	int r;

	new_name = ccn_charbuf_create();
	JUMP_IF_NULL(new_name, exit);

	r = ccn_charbuf_append_charbuf(new_name, c);
	JUMP_IF_NEG(r, free_charbuf);

	return new_name;

free_charbuf:
	ccn_charbuf_destroy(&new_name);
exit:
	return NULL;
}

ccn_charbuf_t *
name_append_str(ccn_charbuf_t *c, char const *segment)
{
	struct ccn_charbuf *new_name;
	int r;

	new_name = name_clone(c);
	JUMP_IF_NULL(new_name, exit);

	r = ccn_name_append_str(new_name, segment);
	JUMP_IF_NEG(r, free_charbuf);

	return new_name;

free_charbuf:
	ccn_charbuf_destroy(&new_name);
exit:
	return NULL;
}

ccn_charbuf_t *
name_append_numeric(ccn_charbuf_t *c, enum ccn_marker marker, uintmax_t value)
{
	struct ccn_charbuf *new_name;
	int r;

	new_name = name_clone(c);
	JUMP_IF_NULL(new_name, exit);

	r = ccn_name_append_numeric(new_name, marker, value);
	JUMP_IF_NEG(r, free_charbuf);

	ccn_charbuf_as_string(c);

	return new_name;

free_charbuf:
	ccn_charbuf_destroy(&new_name);
exit:
	return NULL;
}

content_state_t *
content_state_new(ccn_content_type_t type, int freshness, ccn_keystore_t const *ks)
{
	struct content_state *cs;

	assert(ks);

	cs = calloc(1, sizeof(struct content_state));
	JUMP_IF_NULL_ERRNO(cs, error);

	cs->key_locator = ccn_charbuf_create();
	JUMP_IF_NULL_ERRNO(cs->key_locator, error);

	cs->signed_info = ccn_charbuf_create();
	JUMP_IF_NULL_ERRNO(cs->signed_info, error);

	cs->content_object = ccn_charbuf_create();
	JUMP_IF_NULL_ERRNO(cs->content_object, error);

	cs->type = type;
	cs->freshness = freshness;
	cs->key_store = ks;

	cs->public_key = ccn_keystore_public_key((ccn_keystore_t *) ks);
	cs->private_key = ccn_keystore_private_key((ccn_keystore_t *) ks);
	cs->key_id = ccn_keystore_public_key_digest((ccn_keystore_t *) ks);
	cs->key_id_len = ccn_keystore_public_key_digest_length((ccn_keystore_t *) ks);
	if (!cs->public_key || !cs->private_key || !cs->key_id || cs->key_id_len < 0) {
		SET_ERR("No public or private key available in key store");
		goto error;
	}

	return cs;

error:
	content_state_free(cs);
	return NULL;
}

void
content_state_free(content_state_t *cs)
{
	if (!cs)
		return;

	ccn_charbuf_destroy(&cs->key_locator);
	ccn_charbuf_destroy(&cs->signed_info);
	ccn_charbuf_destroy(&cs->content_object);
	free(cs);
}

int
content_state_set_keylocator_from_key(content_state_t *cs)
{
	int r;

	cs->ready_signed_info = 0;
	ccn_charbuf_reset(cs->key_locator);

	r = ccn_charbuf_append_tt(cs->key_locator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG(r, error);

	r = ccn_charbuf_append_tt(cs->key_locator, CCN_DTAG_Key, CCN_DTAG);
	JUMP_IF_NEG(r, error);

	r = ccn_append_pubkey_blob(cs->key_locator, cs->public_key);
	JUMP_IF_NEG(r, error);

	r = ccn_charbuf_append_closer(cs->key_locator);
	JUMP_IF_NEG(r, error); /* </Key> */

	r = ccn_charbuf_append_closer(cs->key_locator);
	JUMP_IF_NEG(r, error); /* </KeyLocator> */

	cs->ready_key_locator = 1;

	return 0;

error:
	return -1;
}

int
content_state_set_keylocator_from_name(content_state_t *cs,
		ccn_charbuf_t const *name)
{
	int r;

	cs->ready_signed_info = 0;
	ccn_charbuf_reset(cs->key_locator);

	r = ccn_charbuf_append_tt(cs->key_locator, CCN_DTAG_KeyLocator, CCN_DTAG);
	JUMP_IF_NEG_ERRNO(r, error);

	r = ccn_charbuf_append_tt(cs->key_locator, CCN_DTAG_KeyName, CCN_DTAG);
	JUMP_IF_NEG_ERRNO(r, error);

	r = ccn_charbuf_append_charbuf(cs->key_locator, name);
	JUMP_IF_NEG_ERRNO(r, error);

	r = ccn_charbuf_append_closer(cs->key_locator);
	JUMP_IF_NEG_ERRNO(r, error); /* </Key> */

	r = ccn_charbuf_append_closer(cs->key_locator);
	JUMP_IF_NEG_ERRNO(r, error); /* </KeyLocator> */

	cs->ready_key_locator = 1;

	return 0;

error:
	return -1;
}

int
content_state_key_object(content_state_t *cs, ccn_charbuf_t const *name)
{
	struct ccn_charbuf *key_der;
	int r;

	assert(cs);
	assert(name);

	key_der = ccn_charbuf_create();
	JUMP_IF_NULL_ERRNO(key_der, error);

	r = get_key_der_public(key_der, cs->key_store);
	JUMP_IF_NEG(r, free_key_der);

	r = content_object_from_data(cs, key_der->buf, key_der->length, name);
	ccn_charbuf_destroy(&key_der);
	JUMP_IF_NEG(r, error);

	return 0;

free_key_der:
	ccn_charbuf_destroy(&key_der);
error:
	return -1;
}

int
generate_signed_info(content_state_t *cs)
{
	int r;

	if (!cs->ready_key_locator && content_state_set_keylocator_from_key(cs) < 0)
		return -1;

	ccn_charbuf_reset(cs->signed_info);
	r = ccn_signed_info_create(cs->signed_info, cs->key_id, cs->key_id_len, NULL,
			cs->type, cs->freshness, NULL, cs->key_locator);

	cs->ready_signed_info = 1;

	return r;
}

int
content_object_from_data(content_state_t *cs, void const *data,
		size_t data_len, ccn_charbuf_t const *name)
{
	int r;

	assert(cs);
	assert(data);
	assert(name);

	r = generate_signed_info(cs);
	JUMP_IF_NEG_MSG(r, error, "Error when generating signed_info");

	ccn_charbuf_reset(cs->content_object);
	r = ccn_encode_ContentObject(cs->content_object, name, cs->signed_info, data,
			data_len, NULL, cs->private_key);
	JUMP_IF_NEG_MSG(r, error, "Error encoding the content_object");

	return 0;

error:
	return -1;
}

