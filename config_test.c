#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "str.h"
#include "log.h"
#include "config.h"

int main(int argc, char **argv)
{
  int i;
  for (i = 1; i < argc; ++i) {
    int fd = open(argv[i], O_RDONLY);
    if (fd == -1) {
      perror("open");
      exit(1);
    }
    struct stat st;
    fstat(fd, &st);
    char *buf = malloc(st.st_size);
    if (!buf) {
      perror("malloc");
      exit(1);
    }
    if (read(fd, buf, st.st_size) != st.st_size) {
      perror("read");
      exit(1);
    }
    struct cf_om_node *root = cf_parse_to_om(argv[i], buf, st.st_size);
    close(fd);
    //cf_dump_node(root, 0);
    struct config_main config;
    memset(&config, 0, sizeof config);
    cf_dfl_config_main(&config);
    int result = cf_opt_config_main(&config, root);
    cf_free_node(root);
    free(buf);
    DEBUGF("result = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), result)));
    DEBUGF("config.log.file = %s", alloca_str_toprint(config.log.file));
    DEBUGF("config.log.show_pid = %d", config.log.show_pid);
    DEBUGF("config.log.show_time = %d", config.log.show_time);
    DEBUGF("config.server.chdir = %s", alloca_str_toprint(config.server.chdir));
    DEBUGF("config.debug = %llx", (unsigned long long) config.debug);
    DEBUGF("config.directory.service = %s", alloca_tohex(config.directory.service.binary, SID_SIZE));
    DEBUGF("config.rhizome.api.addfile.allow_host = %s", inet_ntoa(config.rhizome.api.addfile.allow_host));
    int j;
    for (j = 0; j < config.mdp.iftype.ac; ++j) {
      DEBUGF("config.mdp.iftype.%u", config.mdp.iftype.av[j].key);
      DEBUGF("   .tick_ms = %u", config.mdp.iftype.av[j].value.tick_ms);
    }
    for (j = 0; j < config.dna.helper.argv.ac; ++j) {
      DEBUGF("config.dna.helper.argv.%u=%s", config.dna.helper.argv.av[j].key, config.dna.helper.argv.av[j].value);
    }
    for (j = 0; j < config.rhizome.direct.peer.ac; ++j) {
      DEBUGF("config.rhizome.direct.peer.%s", config.rhizome.direct.peer.av[j].key);
      DEBUGF("   .protocol = %s", alloca_str_toprint(config.rhizome.direct.peer.av[j].value.protocol));
      DEBUGF("   .host = %s", alloca_str_toprint(config.rhizome.direct.peer.av[j].value.host));
      DEBUGF("   .port = %u", config.rhizome.direct.peer.av[j].value.port);
    }
    for (j = 0; j < config.interfaces.ac; ++j) {
      DEBUGF("config.interfaces.%s", config.interfaces.av[j].key);
      DEBUGF("   .exclude = %d", config.interfaces.av[j].value.exclude);
      DEBUGF("   .match = [");
      int k;
      for (k = 0; k < config.interfaces.av[j].value.match.patc; ++k)
	DEBUGF("             %s", alloca_str_toprint(config.interfaces.av[j].value.match.patv[k]));
      DEBUGF("            ]");
      DEBUGF("   .type = %d", config.interfaces.av[j].value.type);
      DEBUGF("   .port = %u", config.interfaces.av[j].value.port);
      DEBUGF("   .speed = %llu", (unsigned long long) config.interfaces.av[j].value.speed);
    }
    for (j = 0; j < config.hosts.ac; ++j) {
      char sidhex[SID_STRLEN + 1];
      tohex(sidhex, config.hosts.av[j].key.binary, SID_SIZE);
      DEBUGF("config.hosts.%s", sidhex);
      DEBUGF("   .interface = %s", alloca_str_toprint(config.hosts.av[j].value.interface));
      DEBUGF("   .address = %s", inet_ntoa(config.hosts.av[j].value.address));
      DEBUGF("   .port = %u", config.hosts.av[j].value.port);
    }
  }
  exit(0);
}

const struct __sourceloc __whence = __NOWHERE__;

static const char *_trimbuildpath(const char *path)
{
  /* Remove common path prefix */
  int lastsep = 0;
  int i;
  for (i = 0; __FILE__[i] && path[i]; ++i) {
    if (i && path[i - 1] == '/')
      lastsep = i;
    if (__FILE__[i] != path[i])
      break;
  }
  return &path[lastsep];
}

void logMessage(int level, struct __sourceloc whence, const char *fmt, ...)
{
  const char *levelstr = "UNKWN:";
  switch (level) {
    case LOG_LEVEL_FATAL: levelstr = "FATAL:"; break;
    case LOG_LEVEL_ERROR: levelstr = "ERROR:"; break;
    case LOG_LEVEL_INFO:  levelstr = "INFO:"; break;
    case LOG_LEVEL_WARN:  levelstr = "WARN:"; break;
    case LOG_LEVEL_DEBUG: levelstr = "DEBUG:"; break;
  }
  fprintf(stderr, "%s ", levelstr);
  if (whence.file) {
    fprintf(stderr, "%s", _trimbuildpath(whence.file));
    if (whence.line)
      fprintf(stderr, ":%u", whence.line);
    if (whence.function)
      fprintf(stderr, ":%s()", whence.function);
    fputc(' ', stderr);
  } else if (whence.function) {
    fprintf(stderr, "%s() ", whence.function);
  }
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

debugflags_t debugFlagMask(const char *flagname)
{
  if	  (!strcasecmp(flagname,"all"))			return ~0;
  else if (!strcasecmp(flagname,"interfaces"))		return 1 << 0;
  else if (!strcasecmp(flagname,"rx"))			return 1 << 1;
  else if (!strcasecmp(flagname,"tx"))			return 1 << 2;
  else if (!strcasecmp(flagname,"verbose"))		return 1 << 3;
  else if (!strcasecmp(flagname,"verbio"))		return 1 << 4;
  else if (!strcasecmp(flagname,"peers"))		return 1 << 5;
  else if (!strcasecmp(flagname,"dnaresponses"))	return 1 << 6;
  else if (!strcasecmp(flagname,"dnahelper"))		return 1 << 7;
  else if (!strcasecmp(flagname,"vomp"))		return 1 << 8;
  else if (!strcasecmp(flagname,"packetformats"))	return 1 << 9;
  else if (!strcasecmp(flagname,"packetconstruction"))	return 1 << 10;
  else if (!strcasecmp(flagname,"gateway"))		return 1 << 11;
  else if (!strcasecmp(flagname,"keyring"))		return 1 << 12;
  else if (!strcasecmp(flagname,"sockio"))		return 1 << 13;
  else if (!strcasecmp(flagname,"frames"))		return 1 << 14;
  else if (!strcasecmp(flagname,"abbreviations"))	return 1 << 15;
  else if (!strcasecmp(flagname,"routing"))		return 1 << 16;
  else if (!strcasecmp(flagname,"security"))		return 1 << 17;
  else if (!strcasecmp(flagname,"rhizome"))	        return 1 << 18;
  else if (!strcasecmp(flagname,"rhizometx"))		return 1 << 19;
  else if (!strcasecmp(flagname,"rhizomerx"))		return 1 << 20;
  else if (!strcasecmp(flagname,"rhizomeads"))		return 1 << 21;
  else if (!strcasecmp(flagname,"monitorroutes"))	return 1 << 22;
  else if (!strcasecmp(flagname,"queues"))		return 1 << 23;
  else if (!strcasecmp(flagname,"broadcasts"))		return 1 << 24;
  else if (!strcasecmp(flagname,"manifests"))		return 1 << 25;
  else if (!strcasecmp(flagname,"mdprequests"))		return 1 << 26;
  else if (!strcasecmp(flagname,"timing"))		return 1 << 27;
  return 0;
}
