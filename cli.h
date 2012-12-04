#ifndef __SERVALD_CLI_H
#define __SERVALD_CLI_H 

typedef struct command_line_option {
  int (*function)(int argc, const char *const *argv, const struct command_line_option *o, void *context);
  const char *words[32]; // 32 words should be plenty!
  unsigned long long flags;
#define CLIFLAG_NONOVERLAY          (1<<0) /* Uses a legacy IPv4 DNA call instead of overlay mnetwork */
#define CLIFLAG_STANDALONE          (1<<1) /* Cannot be issued to a running instance */
#define CLIFLAG_PERMISSIVE_CONFIG   (1<<2) /* No error on bad configuration file */
  const char *description; // describe this invocation
} command_line_option;


int cli_usage(const command_line_option *options);
int cli_parse(const int argc, const char *const *args, const struct command_line_option *options);
int cli_invoke(const struct command_line_option *option, const int argc, const char *const *args, void *context);
int cli_arg(int argc, const char *const *argv, const command_line_option *o, char *argname, const char **dst, int (*validator)(const char *arg), char *defaultvalue);

int cli_lookup_did(const char *text);
int cli_absolute_path(const char *arg);
int cli_optional_sid(const char *arg);
int cli_optional_bundle_key(const char *arg);
int cli_manifestid(const char *arg);
int cli_fileid(const char *arg);
int cli_optional_bundle_crypt_key(const char *arg);
int cli_uint(const char *arg);
int cli_optional_did(const char *text);



#endif
