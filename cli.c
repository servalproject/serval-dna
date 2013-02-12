#include <stdio.h>
#include <strings.h>
#include "cli.h"
#include "log.h"
#include "serval.h"
#include "rhizome.h"

int cli_usage(const struct command_line_option *commands) {
  printf("Usage:\n");
  int i,j;
  for(i=0;commands[i].function;i++) {
    for(j=0;commands[i].words[j];j++)
      printf(" %s",commands[i].words[j]);
    printf("\n   %s\n",commands[i].description);
  }
  return 0;
}

static const char * parsed_add_label_arg(struct parsed_command *parsed, const char *label, unsigned labellen, unsigned argi)
{
  if (parsed->labelc >= NELS(parsed->labelv))
    return "too many labeled args";
  parsed->labelv[parsed->labelc].label = label;
  parsed->labelv[parsed->labelc].len = labellen;
  parsed->labelv[parsed->labelc].argi = argi;
  ++parsed->labelc;
  return NULL;
}

int cli_parse(const int argc, const char *const *args, const struct command_line_option *commands, struct parsed_command *parsed)
{
  int ambiguous = 0;
  int matched_cmd = -1;
  int cmd;
  for (cmd = 0; commands[cmd].function; ++cmd) {
    struct parsed_command cmdpa;
    memset(&cmdpa, 0, sizeof cmdpa);
    cmdpa.command = &commands[cmd];
    cmdpa.args = args;
    cmdpa.argc = argc;
    cmdpa.labelc = 0;
    cmdpa.varargi = -1;
    const char *problem = NULL;
    const char *word = NULL;
    int arg, opt;
    for (arg = 0, opt = 0; !problem && (word = commands[cmd].words[opt]); ++opt) {
      int wordlen = strlen(word);
      if (cmdpa.varargi != -1)
	problem = "more words not allowed after \"...\"";
      else if (wordlen > 4 && word[0] == '[' && word[1] == '<' && word[wordlen-2] == '>' && word[wordlen-1] == ']') {
	// "[<label>]" consumes one argument if available, records it with label "label".
	if (arg < argc)
	  problem = parsed_add_label_arg(&cmdpa, &word[2], wordlen - 4, arg++);
      } else if (wordlen > 2 && word[0] == '[' && word[wordlen-1] == ']') {
	// "[word]" consumes one argument if it exactly matches "word", records it with label
	// "word".
	const char *endp = NULL;
	if (arg < argc && strncase_startswith(word + 1, wordlen - 2, args[arg], &endp) && endp == word + wordlen - 1)
	  problem = parsed_add_label_arg(&cmdpa, &word[1], wordlen - 2, arg++);
      } else if (wordlen == 3 && word[0] == '.' && word[1] == '.' && word[2] == '.') {
	// "..." consumes all remaining arguments.
	cmdpa.varargi = arg;
	arg = argc;
      } else if (wordlen > 2 && word[0] == '<' && word[wordlen-1] == '>') {
	// "<label>" consumes exactly one argument, records it with label "label".
	if (arg < argc)
	  problem = parsed_add_label_arg(&cmdpa, &word[1], wordlen - 2, arg++);
	else
	  break;
      } else if (wordlen > 0) {
	const char *endp = NULL;
	// "word" consumes exactly one argument which must exactly match "word".
	if (arg < argc && strncase_startswith(word, wordlen, args[arg], &endp) && endp == word + wordlen)
	  ++arg;
	else
	  break;
      } else
	problem = "malformed";
    }
    if (problem)
      return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - %s", cmd, opt - 1, word, problem);
    if (!word && arg == argc) {
      /* A match!  We got through the command definition with no internal errors and all literal
       args matched and we have a proper number of args.  If we have multiple matches, then note
       that the call is ambiguous. */
      if (matched_cmd >= 0)
	++ambiguous;
      if (ambiguous == 1) {
	WHY("Ambiguous command line call:");
	WHY_argv("   ", argc, args);
	WHY("Matches the following known command line calls:");
	WHY_argv("   ", argc, commands[matched_cmd].words);
      }
      if (ambiguous)
	WHY_argv("   ", argc, commands[cmd].words);
      matched_cmd = cmd;
      *parsed = cmdpa;
    }
  }
  /* Don't process ambiguous calls */
  if (ambiguous)
    return -1;
  /* Complain if we found no matching calls */
  if (matched_cmd < 0) {
    if (argc) {
      WHY("Unknown command line call:");
      WHY_argv("   ", argc, args);
    }
    INFO("Use \"help\" command to see a list of valid commands");
    return -1;
  }
  return matched_cmd;
}

void _debug_parsed(struct __sourceloc __whence, const struct parsed_command *parsed)
{
  DEBUG_argv("command", parsed->argc, parsed->args);
  strbuf b = strbuf_alloca(1024);
  int i;
  for (i = 0; i < parsed->labelc; ++i) {
    const struct labelv *lab = &parsed->labelv[i];
    strbuf_sprintf(b, " %s=%d", alloca_toprint(-1, lab->label, lab->len), lab->argi);
  }
  if (parsed->varargi >= 0)
    strbuf_sprintf(b, " varargi=%d", parsed->varargi); 
  DEBUGF("parsed%s", strbuf_str(b));
}

int cli_invoke(const struct parsed_command *parsed, void *context)
{
  IN();
  int ret = parsed->command->function(parsed, context);
  RETURN(ret);
}

int cli_arg(const struct parsed_command *parsed, char *label, const char **dst, int (*validator)(const char *arg), char *defaultvalue)
{
  int labellen = strlen(label);
  if (dst)
    *dst = defaultvalue;
  int i;
  for (i = 0; i < parsed->labelc; ++i) {
    if (parsed->labelv[i].len == labellen && strncasecmp(label, parsed->labelv[i].label, labellen) == 0) {
      const char *value = parsed->args[parsed->labelv[i].argi];
      if (validator && !(*validator)(value))
	return WHYF("Invalid argument %d '%s': \"%s\"", i + 1, label, value);
      if (dst)
	*dst = value;
      return 0;
    }
  }
  /* No matching valid argument was found, so return default value.  It might seem that this should
   never happen, but it can because more than one version of a command line option may exist, one
   with a given argument and another without, and allowing a default value means we can have a
   single function handle both in a fairly simple manner. */
  return 1;
}

int cli_lookup_did(const char *text)
{
  return text[0] == '\0' || strcmp(text, "*") == 0 || str_is_did(text);
}

int cli_absolute_path(const char *arg)
{
  return arg[0] == '/' && arg[1] != '\0';
}

int cli_optional_sid(const char *arg)
{
  return !arg[0] || str_is_subscriber_id(arg);
}

int cli_optional_bundle_key(const char *arg)
{
  return !arg[0] || rhizome_str_is_bundle_key(arg);
}

int cli_manifestid(const char *arg)
{
  return rhizome_str_is_manifest_id(arg);
}

int cli_fileid(const char *arg)
{
  return rhizome_str_is_file_hash(arg);
}

int cli_optional_bundle_crypt_key(const char *arg)
{
  return !arg[0] || rhizome_str_is_bundle_crypt_key(arg);
}

int cli_uint(const char *arg)
{
  register const char *s = arg;
  while (isdigit(*s++))
    ;
  return s != arg && *s == '\0';
}

int cli_optional_did(const char *text)
{
  return text[0] == '\0' || str_is_did(text);
}
