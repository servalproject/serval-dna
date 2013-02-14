#include <stdio.h>
#include <strings.h>
#include "cli.h"
#include "log.h"
#include "serval.h"
#include "rhizome.h"

int cli_usage(const struct cli_schema *commands) {
  printf("Usage:\n");
  int i,j;
  for(i=0;commands[i].function;i++) {
    for(j=0;commands[i].words[j];j++)
      printf(" %s",commands[i].words[j]);
    printf("\n   %s\n",commands[i].description);
  }
  return 0;
}

int cli_parse(const int argc, const char *const *args, const struct cli_schema *commands, struct cli_parsed *parsed)
{
  int ambiguous = 0;
  int matched_cmd = -1;
  int cmd;
  for (cmd = 0; commands[cmd].function; ++cmd) {
    struct cli_parsed cmdpa;
    memset(&cmdpa, 0, sizeof cmdpa);
    cmdpa.command = &commands[cmd];
    cmdpa.args = args;
    cmdpa.argc = argc;
    cmdpa.labelc = 0;
    cmdpa.varargi = -1;
    const char *word = NULL;
    unsigned arg = 0;
    unsigned opt = 0;
    while ((word = commands[cmd].words[opt])) {
      //DEBUGF("cmd=%d opt=%d word='%s' args[arg=%d]='%s'", cmd, opt, word, arg, arg < argc ? args[arg] : "");
      unsigned wordlen = strlen(word);
      if (cmdpa.varargi != -1)
	return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - more words not allowed after \"...\"", cmd, opt, word);
      /* These are the argument matching rules:
       *
       * "..." consumes all remaining arguments
       *
       * "word" consumes one argument that exactly matches "word", does not label it
       *
       * "<label>" consumes exactly one argument "ANY", records it with label "label"
       *
       * "prefix=<any>" consumes one argument "prefix=ANY" or two arguments "prefix" "ANY",
       * and records the text matching ANY with label "prefix"
       *
       * "prefix <any>" consumes one argyment "prefix ANY" if available or two arguments "prefix"
       * "ANY", and records the text matching ANY with label "prefix"
       *
       * "prefix<any>" consumes one argument "prefixANY", and records the text matching ANY with
       * label "prefix"
       *
       * "[<label>]" consumes one argument "ANY" if available, records it with label "label"
       *
       * "[prefix=<any>]" consumes one argument "prefix=ANY" if available or two arguments
       * "prefix" "ANY" if available, records the text matching ANY with label "prefix"
       *
       * "[prefix <any>]" consumes one argument "prefix ANY" if available or two arguments
       * "prefix" "ANY" if available, records the text matching ANY with label "prefix"
       *
       * "[prefix<any>]" consumes one argument "prefixANY" if available, records the text matching
       * ANY with label "prefix"
       *
       * "[word]" consumes one argument if it exactly matches "word", records it with label
       * "word"
       */
      if (wordlen == 3 && word[0] == '.' && word[1] == '.' && word[2] == '.') {
	cmdpa.varargi = arg;
	arg = argc;
	++opt;
      } else {
	int optional = 0;
	int repeating = 0;
	if (wordlen > 5 && word[0] == '[' && word[wordlen-4] == ']' && word[wordlen-3] == '.' && word[wordlen-2] == '.' && word[wordlen-1] == '.') {
	  optional = repeating = 1;
	  word += 1;
	  wordlen -= 5;
	}
	else if (wordlen > 2 && word[0] == '[' && word[wordlen-1] == ']') {
	  optional = 1;
	  word += 1;
	  wordlen -= 2;
	}
	const char *prefix = NULL;
	unsigned prefixlen = 0;
	char prefixarglen = 0;
	const char *label = NULL;
	unsigned labellen = 0;
	const char *text = NULL;
	const char *caret = strchr(word, '<');
	unsigned oarg = arg;
	if (wordlen > 2 && caret && word[wordlen-1] == '>') {
	  if ((prefixarglen = prefixlen = caret - word)) {
	    prefix = word;
	    if (prefixlen > 1 && (prefix[prefixlen-1] == '=' || prefix[prefixlen-1] == ' '))
	      --prefixarglen;
	    label = prefix;
	    labellen = prefixarglen;
	    if (arg < argc) {
	      unsigned arglen = strlen(args[arg]);
	      if (arglen >= prefixlen && strncmp(args[arg], prefix, prefixlen) == 0) {
		text = args[arg++] + prefixlen;
	      } else if (arg + 1 < argc && arglen == prefixarglen && strncmp(args[arg], prefix, prefixarglen) == 0) {
		++arg;
		text = args[arg++];
	      }
	    }
	  } else {
	    label = &word[1];
	    labellen = wordlen - 2;
	    if (arg < argc)
	      text = args[arg++];
	  }
	} else if (arg < argc && strlen(args[arg]) == wordlen && strncmp(args[arg], word, wordlen) == 0) {
	  if (optional) {
	    text = args[arg];
	    label = word;
	    labellen = wordlen;
	  }
	  ++arg;
	}
	if (arg == oarg && !optional)
	  break;
	if (labellen && text) {
	  if (cmdpa.labelc >= NELS(cmdpa.labelv))
	    return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - label limit exceeded", cmd, opt, word);
	  cmdpa.labelv[cmdpa.labelc].label = label;
	  cmdpa.labelv[cmdpa.labelc].len = labellen;
	  cmdpa.labelv[cmdpa.labelc].text = text;
	  ++cmdpa.labelc;
	  if (!repeating)
	    ++opt;
	} else
	  ++opt;
      }
    }
    //DEBUGF("cmd=%d opt=%d args[arg=%d]='%s'", cmd, opt, arg, arg < argc ? args[arg] : "");
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

void _debug_cli_parsed(struct __sourceloc __whence, const struct cli_parsed *parsed)
{
  DEBUG_argv("command", parsed->argc, parsed->args);
  strbuf b = strbuf_alloca(1024);
  int i;
  for (i = 0; i < parsed->labelc; ++i) {
    const struct labelv *lab = &parsed->labelv[i];
    strbuf_sprintf(b, " %s=%s", alloca_toprint(-1, lab->label, lab->len), alloca_str_toprint(lab->text));
  }
  if (parsed->varargi >= 0)
    strbuf_sprintf(b, " varargi=%d", parsed->varargi); 
  DEBUGF("parsed%s", strbuf_str(b));
}

int cli_invoke(const struct cli_parsed *parsed, void *context)
{
  IN();
  int ret = parsed->command->function(parsed, context);
  RETURN(ret);
}

int _cli_arg(struct __sourceloc __whence, const struct cli_parsed *parsed, char *label, const char **dst, int (*validator)(const char *arg), char *defaultvalue)
{
  int labellen = strlen(label);
  if (dst)
    *dst = defaultvalue;
  int i;
  for (i = 0; i < parsed->labelc; ++i) {
    if (parsed->labelv[i].len == labellen && strncasecmp(label, parsed->labelv[i].label, labellen) == 0) {
      const char *value = parsed->labelv[i].text;
      if (validator && !(*validator)(value))
	return WHYF("Invalid '%s' argument \"%s\"", label, value);
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
