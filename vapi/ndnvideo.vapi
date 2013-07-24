namespace ndnvideo {

[CCode(cheader_filename = "packet_generator.h", cprefix = "packet_gen_", cname = "packet_gen_t")]
[Compact]
public class PacketGenerator {
	public uint segment;
	public uint chunk_size;
	public bool running;

	public PacketGenerator(RepoPublisher rp, uint max_size);
	public void set_base_name(string name);
	public void push_data(uint8 data[], uint64 timestamp, uint64 duration,
			bool start_fresh, bool flush);
	public void key();
	public void stream_info(string caps);
	public void push_index(uint64 index);
}

[CCode(cheader_filename = "repo_publisher.h", cprefix = "repo_publisher_", cname = "repo_publisher_t")]
[Compact]
public class RepoPublisher {
	public RepoPublisher(ushort repo_port);
	public int repo_publisher_connect();
//	public ssize_t repo_publisher_put(ccn_charbuf_t const *data);
}

}
