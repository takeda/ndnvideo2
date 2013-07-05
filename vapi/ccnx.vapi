[CCode(cprefix = "ccn_", cheader_filename = "ccn/ccn.h")]
namespace ccnx {

[CCode(cname = "struct ccn", free_function = "ccn_destroy")]
[Compact]
public class handle {
	[CCode(cname = "ccn_connect")]
	public int connect(string? name);

	[CCode(cname = "ccn_create")]
	public handle();
}

[CCode(cname = "struct ccn_charbuf", cheader_filename = "ccn/charbuf.h", free_function = "ccn_charbuf_destroy")]
[Compact]
public class CharBuf {
	internal size_t length;
	internal size_t limit;
	internal uint8 buf[];

	[CCode(cname = "ccn_charbuf_append_charbuf")]
	int append_charbuf(CharBuf cb);

	public CharBuf clone() {
		var cb = new CharBuf();
		cb.append_charbuf(this);

		return cb;
	}

	[CCode(cname = "ccn_name_init")]
	public int name_init();

	[CCode(cname = "ccn_name_append_str")]
	public int name_append_str(string component);

	[CCode(cname = "ccn_name_from_uri", cheader_filename = "ccn/uri.h")]
	public int name_from_uri(string uri);

	[CCode(cname = "ccn_uri_append", cheader_filename = "ccn/uri.h")]
	int uri_append([CCode(array_length = false)]uint8 buf[], size_t size, int flags);

	public string name_to_uri() {
		var cb = new CharBuf();
		cb.uri_append(this.buf, this.length, 0);
		return (string) cb.buf;
	}

	[CCode(cname = "ccn_charbuf_create")]
	public CharBuf();
}

namespace Name {
	public static CharBuf from_uri(string uri) {
		var n = new CharBuf();
		n.name_from_uri(uri);
		return n;
	}
}

[CCode(cname = "struct ccn_pkey", cheader_filename = "ccn/keystore.h")]
public struct PKey {
}

[CCode(cname = "ccn_keystore_t", cheader_filename = "vala_fix.h,ccn/keystore.h", free_function = "ccn_keystore_destroy", free_function_address_of = true)]
[Compact]
public class KeyStore {
	[CCode(cname = "ccn_keystore_init")]
	public int init(string name, string password);

	[CCode(cname = "ccn_keystore_public_key")]
	public PKey public_key();

	[CCode(cname = "ccn_keystore_private_key")]
	public PKey private_key();

	[CCode(cname = "ccn_keystore_create")]
	public KeyStore();
}

}
