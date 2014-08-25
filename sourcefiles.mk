# The "client" source files do not depend on "serval.h" or "rhizome.h", ie,
# they can be linked into executables other than servald.
SERVAL_CLIENT_SOURCES = \
	cli.c \
        conf.c \
        conf_om.c \
        conf_parse.c \
        conf_schema.c \
	console.c \
	dataformats.c \
	fdqueue.c \
        instance.c \
	limit.c \
	logMessage.c \
	log_util.c \
	mem.c \
	net.c \
	os.c \
	performance_timing.c \
	randombytes.c \
	rotbuf.c \
	sighandlers.c \
	socket.c \
	srandomdev.c \
	strbuf.c \
	strbuf_helpers.c \
	str.c \
	strlcpy.c \
	uuid.c \
	whence.c \
        xprintf.c

# These objects do not belong in the Serval DNA daemon but are available for
# client applications.
SERVAL_LIB_SOURCES = \
	log_stderr.c

# These source files are imported and do not depend on any local header files.
# They also take a long time to compile, so their dependencies should be as
# narrow as possible to avoid unnecessary recompilations when developers modify
# header files.
SQLITE3_SOURCES = \
	sqlite-amalgamation-3070900/sqlite3.c

# The source files for building the Serval DNA daemon.
SERVAL_DAEMON_SOURCES = \
	commandline.c \
        conf_cli.c \
	rhizome_cli.c \
	keyring_cli.c \
	network_cli.c \
	test_cli.c \
	crypto.c \
	directory_client.c \
	dna_helper.c \
	golay.c \
	httpd.c \
	http_server.c \
	keyring.c \
	log.c \
	lsif.c \
	main.c \
	radio_link.c \
	meshms.c \
	meshms_restful.c \
	msp_client.c \
	msp_proxy.c \
	monitor.c \
	monitor-client.c \
	monitor-cli.c \
	overlay_address.c \
	overlay_buffer.c \
	overlay_interface.c \
	overlay_link.c \
	overlay_packetradio.c \
	overlay_queue.c \
	overlay_mdp.c \
	overlay_mdp_services.c \
	mdp_filter.c \
	overlay_olsr.c \
	overlay_packetformats.c \
	overlay_payload.c \
	route_link.c \
	rhizome.c \
	rhizome_bundle.c \
	rhizome_crypto.c \
	rhizome_database.c \
	rhizome_direct.c \
	rhizome_direct_http.c \
	rhizome_fetch.c \
	rhizome_http.c \
	rhizome_restful.c \
	rhizome_packetformats.c \
	rhizome_store.c \
	rhizome_sync.c \
	serval_packetvisualise.c \
	server.c \
	sha2.c \
	vomp.c \
	vomp_console.c \
        fec-3.0.1/ccsds_tables.c \
	fec-3.0.1/decode_rs_8.c \
	fec-3.0.1/encode_rs_8.c \
	fec-3.0.1/init_rs_char.c \
	context1.c

MDP_CLIENT_SOURCES = \
	mdp_client.c \
        mdp_net.c

SIMULATOR_SOURCES = \
        simulator.c

MONITOR_CLIENT_SRCS = \
	monitor-client.c
