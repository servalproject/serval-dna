#ifndef __SERVAL_DNA__COMMANDLINE_H
#define __SERVAL_DNA__COMMANDLINE_H

#define KEYRING_PIN_OPTION	  ,"[--keyring-pin=<pin>]"
#define KEYRING_ENTRY_PIN_OPTION  ,"[--entry-pin=<pin>]"
#define KEYRING_PIN_OPTIONS	  KEYRING_PIN_OPTION KEYRING_ENTRY_PIN_OPTION "..."

// macros are weird sometimes ....
#define _APPEND(X,Y) X ## Y
#define _APPEND2(X,Y) _APPEND(X,Y)

#define DEFINE_CMD(FUNC, FLAGS, HELP, WORD1, ...) \
  static int FUNC(const struct cli_parsed *parsed, struct cli_context *context); \
  struct cli_schema _APPEND2(FUNC, __LINE__) \
    __attribute__((used,aligned(sizeof(void *)),section("commands"))) = {\
  .function = FUNC, \
  .words = {WORD1, ##__VA_ARGS__, NULL}, \
  .flags = FLAGS, \
  .description = HELP\
  }

extern struct cli_schema __start_commands[];
extern struct cli_schema __stop_commands[];

#define CMD_COUNT (__stop_commands - __start_commands)
#endif