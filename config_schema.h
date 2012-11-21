SECTION(log)
ITEM(   file,       const char *,   NULL,   opt_absolute_path, "Absolute path of log file")
ITEM(   show_pid,   int,            1,      opt_boolean, "If true, all log lines contain PID of logging process")
ITEM(   show_time,  int,            1,      opt_boolean, "If true, all log lines contain time stamp")
SECTION_END

SECTION(rhizomepeer)
ITEM(   protocol,   const char *,   NULL,   opt_protocol, "Protocol name")
ITEM(   host,       const char *,   NULL,   opt_host, "Host name or IP address")
ITEM(   port,       unsigned short, 4110,   opt_port, "Port number")
SECTION_END

SECTION(rhizomedirect)
LIST(   peer,       struct config_rhizomepeer, opt_rhizome_peer, "List of rhizome peers")
SECTION_END

SECTION(rhizome)
ITEM(   path,       const char *,   NULL,   opt_absolute_path, "Absolute path of rhizome directory")
ITEM(   enabled,    int,            1,      opt_boolean, "If true, Rhizome HTTP server is started")
SUB(    direct,     rhizomedirect)
SECTION_END

SECTION(main)
SUB(    log,        log)
ITEM(   debug,      debugflags_t,   0,      opt_debugflags, "Debug flags")
SUB(    rhizome,    rhizome)
SECTION_END
