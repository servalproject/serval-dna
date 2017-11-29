# The "client" source files do not depend on "serval.h" or "rhizome.h", ie,
# they can be linked into executables other than servald.
SERVAL_CLIENT_SOURCES = \
	base64.c \
	cli.c \
	cli_stdio.c \
	commandline.c \
        conf.c \
        conf_om.c \
        conf_parse.c \
        conf_schema.c \
	console.c \
	context1.c \
	dataformats.c \
	echo_cli.c \
	fdqueue.c \
        instance.c \
	limit.c \
	log.c \
	log_inline.c \
	log_cli.c \
	log_context.c \
	log_util.c \
	mem.c \
	net.c \
	numeric_str.c \
	os.c \
	performance_timing.c \
	rotbuf.c \
	sighandlers.c \
	socket.c \
	strbuf.c \
	strbuf_helpers.c \
	str.c \
	strlcpy.c \
	test_cli.c \
	uri.c \
	serval_uuid.c \
	version_cli.c \
	whence.c \
        xprintf.c

# These source files are imported and do not depend on any local header files.
# They also take a long time to compile, so their dependencies should be as
# narrow as possible to avoid unnecessary recompilations when developers modify
# header files.
SQLITE3_SOURCES = $(SQLITE3_AMALGAMATION)/sqlite3.c

# The source files for building the Serval DNA daemon.
SERVAL_DAEMON_SOURCES = \
	main.c \
	servald_main.c \
        conf_cli.c \
	crypto.c \
	directory_client.c \
	dna_helper.c \
	golay.c \
	httpd.c \
	http_server.c \
	keyring.c \
	keyring_cli.c \
	keyring_restful.c \
	log_output_console.c \
	log_output_file.c \
	lsif.c \
	radio_link.c \
	meshms.c \
	meshmb.c \
	meshmb_cli.c \
	message_ply.c \
	meshms_cli.c \
	meshms_restful.c \
	meshmb_restful.c \
	msp_client.c \
	msp_proxy.c \
	monitor.c \
	monitor-client.c \
	monitor-cli.c \
	overlay_address.c \
	overlay_buffer.c \
	overlay_interface.c \
	overlay_link.c \
	overlay_probe.c \
	overlay_stun.c \
	overlay_stunreq.c \
	overlay_packetradio.c \
	overlay_queue.c \
	overlay_mdp.c \
	overlay_mdp_echo.c \
	overlay_mdp_trace.c \
	overlay_mdp_keymaprequest.c \
	overlay_mdp_dnalookup.c \
	mdp_filter.c \
	msp_server.c \
	nibble_tree.c \
	network_cli.c \
	overlay_olsr.c \
	overlay_packetformats.c \
	overlay_payload.c \
	route_link.c \
	rhizome.c \
	rhizome_bundle.c \
	rhizome_crypto.c \
	rhizome_database.c \
	overlay_mdp_rhizome.c \
	rhizome_direct.c \
	rhizome_direct_cli.c \
	rhizome_direct_http.c \
	rhizome_fetch.c \
	rhizome_http.c \
	rhizome_packetformats.c \
	rhizome_store.c \
	rhizome_sync.c \
	rhizome_sync_keys.c \
	rhizome_restful.c \
	rhizome_cli.c \
	sync_keys.c \
	serval_packetvisualise.c \
	server.c \
	server_httpd.c \
	vomp.c \
	vomp_console.c \
        fec-3.0.1/ccsds_tables.c \
	fec-3.0.1/decode_rs_8.c \
	fec-3.0.1/encode_rs_8.c \
	fec-3.0.1/init_rs_char.c

SERVAL_DAEMON_JNI_SOURCES = \
	jni_common.c \
	jni_commandline.c \
	jni_instance.c \
	jni_server.c

MDP_CLIENT_SOURCES = \
	mdp_client.c

SIMULATOR_SOURCES = \
        simulator.c

MONITOR_CLIENT_SRCS = \
	monitor-client.c

# These source files must excluded from the Android.mk build, otherwise
# the libserval.so link fails.
# TODO: get rid of the need for this separate list by unifying the daemon
# and client logging.
CLIENT_ONLY_SOURCES = \
	log_stderr.c

ANDROID_SOURCES = \
	android.c \
	log_output_android.c

ALL_SOURCES = \
	$(SERVAL_CLIENT_SOURCES) \
	$(MDP_CLIENT_SOURCES) \
	$(SQLITE3_SOURCES) \
	$(SERVAL_DAEMON_SOURCES) \
	$(SERVAL_DAEMON_JNI_SOURCES) \
	$(SIMULATOR_SOURCES) \
	$(MONITOR_CLIENT_SRCS) \
	$(CLIENT_ONLY_SOURCES) \
	$(ANDROID_SOURCES)
