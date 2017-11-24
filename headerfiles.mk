# These public library headers are designed for re-use, and do not depend on
# any PUBLIC_HDRS or PRIVATE_HDRS.
LIB_HDRS= \
	lang.h \
	feature.h \
	section.h \
	trigger.h \
	uri.h \
	base64.h \
	xprintf.h \
	whence.h \
	str.h \
	strbuf.h \
	serval_uuid.h \
	numeric_str.h \
	socket.h \
	net.h \
	mem.h \
	os.h \
	strbuf_helpers.h \
	log.h \
	log_output.h \
	debug.h \
	rotbuf.h \
	fifo.h \
	cli.h \
	fdqueue.h \
	http_server.h \
	nibble_tree.h

# These headers are specific to Serval DNA, and may depend on LIB_HDRS.  They
# are exposed by the iOS framework module, so they are accessible to Swift code
# in Xcode projects.
PUBLIC_HDRS= \
	constants.h \
	log.h \
	conf.h \
	conf_schema.h \
	idebug.h \
	instance.h \
	serval_types.h \
	rhizome_types.h \
	dataformats.h \
	sighandlers.h \
	commandline.h \
	crypto.h \
	server.h \
	servald_main.h \
	sync_keys.h \
	keyring.h \
	route_link.h \
	limit.h \
	overlay_buffer.h \
	overlay_address.h \
	overlay_packet.h \
	rhizome.h \
	meshms.h \
	meshmb.h \
	message_ply.h \
	mdp_client.h \
	msp_client.h \
	msp_server.h \
	radio_link.h \
	monitor-client.h \
	serval.h

# The public amalgamated SQLite3 header is independent of Serval headers, and
# may only be included directly from source (.c) files.
SQLITE3_AMALGAMATION = sqlite-amalgamation-3140200
SQLITE3_HDRS = $(SQLITE3_AMALGAMATION)/sqlite3.h

# These headers are specific to Serval DNA, and may depend on LIB_HDRS.  They
# may only be included directly from source (.c) files, or by other private
# headers.  They are not exposed by the iOS framework module, so are
# inaccessible to Swift code in Xcode projects.
PRIVATE_HDRS= \
	httpd.h \
	msp_common.h \
	overlay_interface.h \

# All header files, useful for writing dependency rules with total coverage.
ALL_HDRS = $(LIB_HDRS) $(PUBLIC_HDRS) $(PRIVATE_HDRS) $(SQLITE3_HDRS)
