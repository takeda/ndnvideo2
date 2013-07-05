using ccnx;

class PacketGenerator : GLib.Object {
	private ulong _segment = 0;
	private string _name_base_uri;
	private ccnx.CharBuf _name_base;
	private ccnx.CharBuf _name_segments;
	private ccnx.CharBuf _name_index;

	public string location {
		get {
			if (_name_base_uri == null)
				_name_base_uri = _name_base.name_to_uri();

			return _name_base_uri;
		}
		set {
			_name_base = ccnx.Name.from_uri(value);
			_name_segments = _name_base.clone();
			_name_index = _name_base.clone();

			_name_segments.name_append_str("segments");
			_name_index.name_append_str("index");
		}
	}

	public PacketGenerator(string location) {
		this.location = location;
	}
}
