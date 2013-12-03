/*
Serval DNA configuration stand-alone configuration check utility
Copyright 2013 Serval Project, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#include "str.h"
#include "log.h"
#include "conf.h"

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
    struct cf_om_node *root = NULL;
    int ret = cf_om_parse(argv[i], buf, st.st_size, &root);
    close(fd);
    DEBUGF("ret = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), ret)));
    //cf_dump_node(root, 0);
    struct config_main config;
    memset(&config, 0, sizeof config);
    cf_dfl_config_main(&config);
    int result = root ? cf_opt_config_main(&config, root) : CFEMPTY;
    cf_om_free_node(&root);
    free(buf);
    DEBUGF("result = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), result)));
    DEBUGF("config.log.file.path = %s", alloca_str_toprint(config.log.file.path));
    DEBUGF("config.log.file.show_pid = %d", config.log.file.show_pid);
    DEBUGF("config.log.file.show_time = %d", config.log.file.show_time);
    DEBUGF("config.server.chdir = %s", alloca_str_toprint(config.server.chdir));
    DEBUGF("config.debug.verbose = %d", config.debug.verbose);
    DEBUGF("config.directory.service = %s", alloca_tohex_sid_t(config.directory.service));
    DEBUGF("config.rhizome.api.addfile.allow_host = %s", inet_ntoa(config.rhizome.api.addfile.allow_host));
    unsigned j;
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
      DEBUGF("config.interfaces.%u", config.interfaces.av[j].key);
      DEBUGF("   .exclude = %d", config.interfaces.av[j].value.exclude);
      DEBUGF("   .match = [");
      int k;
      for (k = 0; k < config.interfaces.av[j].value.match.patc; ++k)
	DEBUGF("             %s", alloca_str_toprint(config.interfaces.av[j].value.match.patv[k]));
      DEBUGF("            ]");
      DEBUGF("   .type = %d", config.interfaces.av[j].value.type);
      DEBUGF("   .port = %u", config.interfaces.av[j].value.port);
      DEBUGF("   .drop_broadcasts = %llu", (unsigned long long) config.interfaces.av[j].value.drop_broadcasts);
      DEBUGF("   .drop_unicasts = %llu", (unsigned long long) config.interfaces.av[j].value.drop_unicasts);
      DEBUGF("   .drop_packets = %llu", (unsigned long long) config.interfaces.av[j].value.drop_packets);
    }
    for (j = 0; j < config.hosts.ac; ++j) {
      char sidhex[SID_STRLEN + 1];
      tohex(sidhex, SID_STRLEN, config.hosts.av[j].key.binary);
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
