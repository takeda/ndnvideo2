using GLib.Environment;

namespace ccnx {
	public PKey get_default_key() {
		var ks = new KeyStore();
		ks.init("%s/.ccnx/.ccnx_keystore".printf(get_variable("HOME")), "Th1s1sn0t8g00dp8ssw0rd.");

		return ks.private_key();
	}
}
