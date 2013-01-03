#include <stdio.h>
#include <strings.h>
#include "cli.h"
#include "log.h"
#include "serval.h"
#include "rhizome.h"

int cli_usage(const struct command_line_option *options) {
  printf("Usage:\n");
  int i,j;
  for(i=0;options[i].function;i++) {
    for(j=0;options[i].words[j];j++)
      printf(" %s",options[i].words[j]);
    printf("\n   %s\n",options[i].description);
  }
  return 0;
}

int cli_parse(const int argc, const char *const *args, const struct command_line_option *options)
{
  int ambiguous=0;
  int cli_call=-1;
  int i;
  for(i=0;options[i].function;i++)
  {
    int j;
    const char *word = NULL;
    int optional = 0;
    int mandatory = 0;
    for (j = 0; (word = options[i].words[j]); ++j) {
      int wordlen = strlen(word);
      if (optional < 0) {
	WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" not allowed after \"...\"", i, j, word);
	break;
      }
      else if (!(  (wordlen > 2 && word[0] == '<' && word[wordlen-1] == '>')
		 || (wordlen > 4 && word[0] == '[' && word[1] == '<' && word[wordlen-2] == '>' && word[wordlen-1] == ']')
		 || (wordlen > 0)
		 )) {
	WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" is malformed", i, j, word);
	break;
      } else if (word[0] == '<') {
	++mandatory;
	if (optional) {
	  WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" should be optional", i, j, word);
	  break;
	}
      } else if (word[0] == '[') {
	++optional;
      } else if (wordlen == 3 && word[0] == '.' && word[1] == '.' && word[2] == '.') {
	optional = -1;
      } else {
	++mandatory;
	if (j < argc && strcasecmp(word, args[j])) // literal words don't match
	  break;
      }
    }
    if (!word && argc >= mandatory && (optional < 0 || argc <= mandatory + optional)) {
      /* A match!  We got through the command definition with no internal errors and all literal
       args matched and we have a proper number of args.  If we have multiple matches, then note
       that the call is ambiguous. */
      if (cli_call>=0) ambiguous++;
      if (ambiguous==1) {
	WHY("Ambiguous command line call:");
	WHY_argv("   ", argc, args);
	WHY("Matches the following known command line calls:");
	WHY_argv("   ", argc, options[cli_call].words);
      }
      if (ambiguous)
	WHY_argv("   ", argc, options[i].words);
      cli_call=i;
    }
  }
  
  /* Don't process ambiguous calls */
  if (ambiguous) return -1;
  /* Complain if we found no matching calls */
  if (cli_call<0) {
    if (argc) {
      WHY("Unknown command line call:");
      WHY_argv("   ", argc, args);
    }
    INFO("Use \"help\" command to see a list of valid commands");
    return -1;
  }

  return cli_call;
}

int cli_invoke(const struct command_line_option *option, const int argc, const char *const *args, void *context)
{
  IN();
  int ret=option->function(argc, args, option, context);
  RETURN(ret);
}

int cli_arg(int argc, const char *const *argv, const struct command_line_option *o, char *argname, const char **dst, int (*validator)(const char *arg), char *defaultvalue)
{
  int arglen = strlen(argname);
  int i;
  const char *word;
  for(i = 0; (word = o->words[i]); ++i) {
    int wordlen = strlen(word);
    /* No need to check that the "<...>" and "[<...>]" are all intact in the command_line_option,
     because that was already checked in parseCommandLine(). */
    if (i < argc
	&&(  (wordlen == arglen + 2 && word[0] == '<' && !strncasecmp(&word[1], argname, arglen))
	   || (wordlen == arglen + 4 && word[0] == '[' && !strncasecmp(&word[2], argname, arglen)))
	) {
      const char *value = argv[i];
      if (validator && !(*validator)(value))
	return WHYF("Invalid argument %d '%s': \"%s\"", i + 1, argname, value);
      *dst = value;
      return 0;
    }
  }
  /* No matching valid argument was found, so return default value.  It might seem that this should
   never happen, but it can because more than one version of a command line option may exist, one
   with a given argument and another without, and allowing a default value means we can have a
   single function handle both in a fairly simple manner. */
  *dst = defaultvalue;
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
