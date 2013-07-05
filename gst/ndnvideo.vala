using Gst;

public class NDNVideoSink : Gst.Base.Sink {
	private string _location;
	private uint _chunk_size = 3900;

	class construct {
		set_static_metadata(
			"NDN Video Sink",
			"Sink/Network",
			"Publishes data over NDN network",
			"Derek Kulinski <takeda@takeda.tk>");

		add_pad_template(new Gst.PadTemplate("sink", Gst.PadDirection.SINK, Gst.PadPresence.ALWAYS, new Gst.Caps.any()));
	}

	[Description(blurb = "A location of the video stream in NDN network")]
	public string location {
		get { return _location; }
		set { _location = value; }
	}

	[Description(blurb = "Maximum amount of data in NDN packet")]
	public uint chunk_size {
		get { return _chunk_size; }
		set { _chunk_size = value; }
	}
}

private bool plugin_init(Gst.Plugin plugin) {
	return Gst.Element.register(plugin, "ndnvideosink", Gst.Rank.NONE, typeof(NDNVideoSink));
}

public const Gst.PluginDesc gst_plugin_desc = {
	1, 0, // My Vala does not have Gst.VERSION_MAJOR, Gst.VERSION_MINOR,
	"ndnvideo",
	"Video Streaming over NDN",
	plugin_init,
	"0.0.1",
	"BSD",
	"gst-plugins-ndnvideo",
	"NDNVideo",
	"https://github.com/takeda/ndnvideo2"
};
