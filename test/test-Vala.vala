using ndnvideo;

void main() {
	var rp = new RepoPublisher(8080);
	var pg = new PacketGenerator(rp, 0);
	pg.set_base_name("/usr/local");
	print("segment = %u\n", pg.segment);
	print("chunk_size = %u\n", pg.chunk_size);
	print("running = %s\n", pg.running.to_string());
}
