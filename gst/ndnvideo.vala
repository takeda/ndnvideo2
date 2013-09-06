using Gst;
using ndnvideo;

public abstract class NDNSink : Gst.Base.Sink {
	[Description(blurb = "Caps from the source")]
	public string caps { get; private set; }

	[Description(blurb = "Maximum amount of data in NDN packet")]
	public uint chunk_size { get; set; default = 3900; }

	[Description(blurb = "A location of the video stream in NDN network")]
	public string location { get; set; default = "/ndn/ucla.edu/apps/video"; }

	private RepoPublisher _repo_publisher;
	private PacketGenerator _packet_gen;

	public override bool set_caps(Caps caps) {
		stdout.printf("Caps: %s\n", caps.to_string());
		if (this.caps == null) {
			this.caps = caps.to_string();
			stdout.printf("Publishing stream_info\n");
			_packet_gen.key();
			_packet_gen.stream_info(_caps);
		}
		return true;
	}

	public override bool start() {
		_repo_publisher = new RepoPublisher(0);
		_packet_gen = new PacketGenerator(_repo_publisher, chunk_size);
		_packet_gen.set_base_name(location);
		stdout.printf("Publishing stream to: %s\n", location);
		return true;
	}

	protected abstract bool is_delta(Buffer buffer);

	public override FlowReturn render(Buffer buffer) {
		MapInfo info;
		var delta = is_delta(buffer);

		if (!delta) {
			stdout.printf("Publishing index\n");
			_packet_gen.push_index(buffer.pts);
		}

		if (!buffer.map(out info, MapFlags.READ)) {
			stderr.printf("buffer.map() failed!\n");
			return FlowReturn.ERROR;
		}

		_packet_gen.push_data(info.data, buffer.pts, buffer.duration, !delta, false);
		buffer.unmap(info);

		return FlowReturn.OK;
	}
}

public class NDNVideoSink : NDNSink {
	class construct {
		set_static_metadata(
			"NDN Video Sink", "Sink/Network",
			"Publishes data over NDN network",
			"Derek Kulinski <takeda@takeda.tk>");

		add_pad_template(new Gst.PadTemplate("sink", Gst.PadDirection.SINK, Gst.PadPresence.ALWAYS, new Gst.Caps.any()));
	}

	protected override bool is_delta(Buffer buffer) {
		return (buffer.flags & BufferFlags.DELTA_UNIT) == BufferFlags.DELTA_UNIT;
	}

}

public class NDNAudioSink : NDNSink {
	private const uint _index_frequency = 2000;
	private uint64 _last_index = 0;

	class construct {
		set_static_metadata(
			"NDN Audio Sink", "Sink/Network",
			"Publishes data over NDN network",
			"Derek Kulinski <takeda@takeda.tk>");

		add_pad_template(new Gst.PadTemplate("sink", Gst.PadDirection.SINK, Gst.PadPresence.ALWAYS, new Gst.Caps.any()));
	}

	protected override bool is_delta(Buffer buffer) {
		if ((buffer.pts - _last_index) < _index_frequency * 1000000)
			return true;

		_last_index = buffer.pts;
		return false;
	}
}

private bool plugin_init(Gst.Plugin plugin) {
	Gst.Element.register(plugin, "ndnaudiosink", Gst.Rank.NONE, typeof(NDNAudioSink));
	Gst.Element.register(plugin, "ndnvideosink", Gst.Rank.NONE, typeof(NDNVideoSink));

	return true;
}

public const Gst.PluginDesc gst_plugin_desc = {
	1, 0, // My Vala does not have Gst.VERSION_MAJOR, Gst.VERSION_MINOR,
	"ndnvideo",
	"Video Streaming over NDN",
	plugin_init,
	"0.0.1",
	"GPL",
	"gst-plugins-ndnvideo",
	"NDNVideo",
	"https://github.com/takeda/ndnvideo2"
};
