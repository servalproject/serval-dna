CONFIG_SECTION( log)
CONFIG_ITEM(    file,       const char *,   NULL, opt_absolute_path, "Absolute path of log file")
CONFIG_ITEM(    show_pid,   int,            1,    opt_boolean, "If true, all log lines contain PID of logging process")
CONFIG_ITEM(    show_time,  int,            1,    opt_boolean, "If true, all log lines contain time stamp")
CONFIG_SECTION_END

CONFIG_SECTION( rhizome)
CONFIG_ITEM(    path,       const char *,   NULL, opt_absolute_path, "Absolute path of rhizome directory")
CONFIG_ITEM(    enabled,    int,            1,    opt_boolean, "If true, Rhizome HTTP server is started")
CONFIG_SECTION_END

CONFIG_SECTION( main)
CONFIG_STRUCT(  log,        log)
CONFIG_ITEM(    debug,      debugflags_t,   0,    opt_debugflags, "Debug flags")
CONFIG_STRUCT(  rhizome,    rhizome)
CONFIG_SECTION_END
