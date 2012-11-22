STRUCT(log)
STRING(256,             file,       "", opt_absolute_path,, "Absolute path of log file")
ATOM(int,               show_pid,   1, opt_boolean,, "If true, all log lines contain PID of logging process")
ATOM(int,               show_time,  1, opt_boolean,, "If true, all log lines contain time stamp")
END_STRUCT

STRUCT(rhizomepeer)
STRING(25,              protocol,   "http", opt_protocol,, "Protocol name")
STRING(256,             host,       "", opt_str_nonempty, MANDATORY, "Host name or IP address")
ATOM(uint16_t,          port,       RHIZOME_HTTP_PORT, opt_port,, "Port number")
END_STRUCT

ARRAY(peerlist, struct config_rhizomepeer, 10, opt_rhizome_peer, "Rhizome peers")

STRUCT(rhizomedirect)
SUB(peerlist,           peer,)
END_STRUCT

STRUCT(rhizome)
STRING(256,             path,       "", opt_absolute_path,, "Absolute path of rhizome directory")
ATOM(int,               enabled,    1, opt_boolean,, "If true, Rhizome HTTP server is started")
SUB(rhizomedirect,      direct,)
END_STRUCT

STRUCT(directory)
ATOM(sid_t,             service,     SID_NONE, opt_sid,, "Subscriber ID of Serval Directory Service")
END_STRUCT

STRUCT(network_interface)
ATOM(struct pattern_list,match,     PATTERN_LIST_EMPTY, opt_pattern_list, MANDATORY, "Names that match network interface")
ATOM(short,             type,       OVERLAY_INTERFACE_WIFI, opt_interface_type,, "Type of network interface")
ATOM(uint16_t,          port,       RHIZOME_HTTP_PORT, opt_port,, "Port number for network interface")
ATOM(uint64_t,          speed,      1000000, opt_uint64_scaled,, "Speed in bits per second")
END_STRUCT

ARRAY(interface_list, struct config_network_interface, 10, opt_config_network_interface, "Network interfaces")

STRUCT(main)
SUBP(interface_list,    interfaces, opt_interface_list, MANDATORY)
SUB(log,                log,)
NODE(debugflags_t,      debug,      0, opt_debugflags, NO_TEXT, "Debug flags")
SUB(rhizome,            rhizome,)
SUB(directory,          directory,)
END_STRUCT
