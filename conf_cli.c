/*
Serval configuration command-line functions
Copyright (C) 2014 Serval Project Inc.

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

#include "cli.h"
#include "conf.h"
#include "commandline.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "instance.h"
#include "mdp_client.h"
#include "server.h"

DEFINE_FEATURE(cli_config);

DEFINE_CMD(app_config_schema, CLIFLAG_PERMISSIVE_CONFIG,
   "Display configuration schema.",
   "config", "schema");
static int app_config_schema(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  struct cf_om_node *root = NULL;
  if (cf_sch_config_main(&root) == -1) {
    cf_om_free_node(&root);
    return -1;
  }
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it))
    if (it.node->text || it.node->nodc == 0) {
      cli_put_string(context, it.node->fullkey,"=");
      cli_put_string(context, it.node->text, "\n");
    }
  cf_om_free_node(&root);
  return 0;
}

DEFINE_CMD(app_config_dump, CLIFLAG_PERMISSIVE_CONFIG,
   "Dump configuration settings.",
   "config","dump","[--full]");
static int app_config_dump(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  int full = 0 == cli_arg(parsed, "--full", NULL, NULL, NULL);
  if (create_serval_instance_dir() == -1)
    return -1;
  struct cf_om_node *root = NULL;
  int ret = cf_fmt_config_main(&root, &config);
  if (ret == CFERROR) {
    cf_om_free_node(&root);
    return -1;
  }
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it)) {
    if (it.node->text && (full || it.node->line_number)) {
      cli_put_string(context, it.node->fullkey, "=");
      cli_put_string(context, it.node->text, "\n");
    }
  }
  cf_om_free_node(&root);
  return ret == CFOK ? 0 : 1;
}

static int mdp_client_sync_config(time_ms_t timeout)
{
  /* Bind to MDP socket and await confirmation */
  struct mdp_header mdp_header = {
      .remote.port = MDP_SYNC_CONFIG,
    };
  int mdpsock = mdp_socket();
  if (mdpsock == -1)
    return WHY("cannot create MDP socket");
  set_nonblock(mdpsock);
  int r = mdp_send(mdpsock, &mdp_header, NULL, 0);
  if (r == -1)
    goto end;
  time_ms_t deadline = gettime_ms() + timeout; // TODO add --timeout option
  struct mdp_header rev_header;
  do {
    ssize_t len = mdp_poll_recv(mdpsock, deadline, &rev_header, NULL, 0);
    if (len == -1){
      r = -1;
      goto end;
    }
    if (len == -2) {
      WHYF("timeout while synchronising daemon configuration");
      r = -1;
      goto end;
    }
  } while (!(rev_header.flags & MDP_FLAG_CLOSE));
  r = 0;
  
end:
  mdp_close(mdpsock);
  return r;
}

DEFINE_CMD(app_config_set, CLIFLAG_PERMISSIVE_CONFIG,
  "Set and del specified configuration variables.",
  "config","set","<variable>","<value>","...");
DEFINE_CMD(app_config_set, CLIFLAG_PERMISSIVE_CONFIG,
  "Del and set specified configuration variables.",
  "config","del","<variable>","...");
DEFINE_CMD(app_config_set, CLIFLAG_PERMISSIVE_CONFIG,
  "Synchronise with the daemon's configuration.",
  "config","sync","...");
static int app_config_set(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  if (create_serval_instance_dir() == -1)
    return -1;
  // <kludge>
  // This fixes a subtle bug in when upgrading the Batphone app: the servald.conf file does
  // not get upgraded.  The bug goes like this:
  //  1. new Batphone APK is installed, but prior servald.conf is not overwritten because it
  //     comes in serval.zip;
  //  2. new Batphone is started, which calls JNI "stop" command, which reads the old servald.conf
  //     into memory buffer;
  //  3. new Batphone unpacks serval.zip, overwriting servald.conf with new version;
  //  4. new Batphone calls JNI "config set rhizome.enable 1", which sets the "rhizome.enable"
  //     config option in the existing memory buffer and overwrites servald.conf;
  // Bingo, the old version of servald.conf is what remains.  This kludge intervenes in step 4, by
  // reading the new servald.conf into the memory buffer before applying the "rhizome.enable" set
  // value and overwriting.
  if (cf_om_reload() == -1)
    return -1;
  // </kludge>
  const char *var[parsed->argc - 1];
  const char *val[parsed->argc - 1];
  unsigned nvar = 0;
  unsigned i;
  for (i = 1; i < parsed->argc; ++i) {
    const char *arg = parsed->args[i];
    int iv = -1;
    if (strcmp(arg, "set") == 0) {
      if (i + 2 > parsed->argc)
	return WHYF("malformed command at args[%d]: 'set' not followed by two arguments", i);
      var[nvar] = parsed->args[iv = ++i];
      val[nvar] = parsed->args[++i];
    } else if (strcmp(arg, "del") == 0) {
      if (i + 1 > parsed->argc)
	return WHYF("malformed command at args[%d]: 'del' not followed by one argument", i);
      var[nvar] = parsed->args[iv = ++i];
      val[nvar] = NULL;
    } else if (strcmp(arg, "sync") == 0)
      var[nvar] = val[nvar] = NULL;
    else
      return WHYF("malformed command at args[%d]: unsupported action '%s'", i, arg);
    if (var[nvar] && !is_configvarname(var[nvar]))
      return WHYF("malformed command at args[%d]: '%s' is not a valid config option name", iv, var[nvar]);
    ++nvar;
  }
  int changed = 0;
  for (i = 0; i < nvar; ++i) {
    if (var[i]) {
      if (cf_om_set(&cf_om_root, var[i], val[i]) == -1)
	return -1;
      if (val[i])
	DEBUGF(config, "config set %s %s", var[i], alloca_str_toprint(val[i]));
      else
	DEBUGF(config, "config del %s", var[i]);
      changed = 1;
    } else {
      if (changed) {
	if (cf_om_save() == -1)
	  return -1;
	if (cf_reload() == -1) // logs an error if the new config is bad
	  return 2;
	changed = 0;
      }
      int pid = server_pid();
      if (pid) {
	DEBUG(config, "config sync");
	// TODO make timeout configurable with --timeout option.
	if (mdp_client_sync_config(10000) == -1)
	  return 3;
      } else
	DEBUGF(config, "config sync -- skipped, server not running");
    }
  }
  if (changed) {
    if (cf_om_save() == -1)
      return -1;
    if (cf_reload() == -1) // logs an error if the new config is bad
      return 2;
  }
  return 0;
}

DEFINE_CMD(app_config_get, CLIFLAG_PERMISSIVE_CONFIG,
  "Get specified configuration variable.",
  "config","get","[<variable>]");
static int app_config_get(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  const char *var;
  if (cli_arg(parsed, "variable", &var, is_configvarpattern, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (cf_om_reload() == -1)
    return -1;
  if (var && is_configvarname(var)) {
    const char *value = cf_om_get(cf_om_root, var);
    if (value) {
      cli_field_name(context, var, "=");
      cli_put_string(context, value, "\n");
    }
  } else {
    struct cf_om_iterator it;
    for (cf_om_iter_start(&it, cf_om_root); it.node; cf_om_iter_next(&it)) {
      if (var && cf_om_match(var, it.node) <= 0)
	continue;
      if (it.node->text) {
	cli_field_name(context, it.node->fullkey, "=");
	cli_put_string(context, it.node->text, "\n");
      }
    }
  }
  return 0;
}

DEFINE_CMD(app_config_paths, CLIFLAG_PERMISSIVE_CONFIG,
   "Dump file and directory paths.",
   "config", "paths");
static int app_config_paths(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  if (cf_om_reload() == -1)
    return -1;
  char path[1024];
  if (FORMF_SERVAL_ETC_PATH(path, NULL)) {
    cli_field_name(context, "SERVAL_ETC_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  if (FORMF_SERVAL_RUN_PATH(path, NULL)) {
    cli_field_name(context, "SERVAL_RUN_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  if (FORMF_SERVAL_CACHE_PATH(path, NULL)) {
    cli_field_name(context, "SERVAL_CACHE_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  strbuf sb = strbuf_local_buf(path);
  strbuf_system_log_path(sb);
  if (!strbuf_overrun(sb)) {
    cli_field_name(context, "SYSTEM_LOG_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  strbuf_reset(sb);
  strbuf_serval_log_path(sb);
  if (!strbuf_overrun(sb)) {
    cli_field_name(context, "SERVAL_LOG_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  if (FORMF_SERVAL_TMP_PATH(path, NULL)) {
    cli_field_name(context, "SERVAL_TMP_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  if (FORMF_SERVALD_PROC_PATH(path, NULL)) {
    cli_field_name(context, "SERVALD_PROC_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  if (FORMF_RHIZOME_STORE_PATH(path, NULL)) {
    cli_field_name(context, "RHIZOME_STORE_PATH", ":");
    cli_put_string(context, path, "\n");
  }
  return 0;
}
