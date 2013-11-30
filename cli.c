/*
Serval DNA command-line functions
Copyright (C) 2010-2013 Serval Project, Inc.

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

#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include "cli.h"
#include "log.h"
#include "serval.h"
#include "rhizome.h"
#include "strbuf_helpers.h"
#include "dataformats.h"

int cli_usage(const struct cli_schema *commands, XPRINTF xpf)
{
  return cli_usage_args(0, NULL, commands, xpf);
}

int cli_usage_parsed(const struct cli_parsed *parsed, XPRINTF xpf)
{
  if (parsed->varargi == -1)
    return cli_usage(parsed->commands, xpf);
  return cli_usage_args(parsed->argc - parsed->varargi, &parsed->args[parsed->varargi], parsed->commands, xpf);
}

int cli_usage_args(const int argc, const char *const *args, const struct cli_schema *commands, XPRINTF xpf)
{
  unsigned cmd;
  int matched_any = 0;
  for (cmd = 0; commands[cmd].function; ++cmd) {
    unsigned opt;
    const char *word;
    int matched = 1;
    for (opt = 0; matched && opt < argc && (word = commands[cmd].words[opt]); ++opt)
      if (strncmp(word, args[opt], strlen(args[opt])) != 0)
	matched = 0;
    if (matched) {
      matched_any = 1;
      for (opt = 0; (word = commands[cmd].words[opt]); ++opt) {
	if (word[0] == '|')
	  ++word;
	xprintf(xpf, " %s", word);
      }
      xputc('\n', xpf);
      if (commands[cmd].description && commands[cmd].description[0])
	xprintf(xpf, "   %s\n", commands[cmd].description);
    }
  }
  if (!matched_any && argc) {
    strbuf b = strbuf_alloca(160);
    strbuf_append_argv(b, argc, args);
    xprintf(xpf, " No commands matching %s\n", strbuf_str(b));
  }
  return 0;
}

/* Returns 0 if a command is matched and parsed, with the results of the parsing in the '*parsed'
 * structure.
 *
 * Returns 1 and logs an error if no command matches the argument list, contents of '*parsed' are
 * undefined.
 *
 * Returns 2 if the argument list is ambiguous, ie, matches more than one command, contents of
 * '*parsed' are undefined.
 *
 * Returns -1 and logs an error if the parsing fails due to an internal error (eg, malformed command
 * schema), contents of '*parsed' are undefined.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cli_parse(const int argc, const char *const *args, const struct cli_schema *commands, struct cli_parsed *parsed)
{
  int ambiguous = 0;
  int matched_cmd = -1;
  int cmd;
  for (cmd = 0; commands[cmd].function; ++cmd) {
    struct cli_parsed cmdpa;
    memset(&cmdpa, 0, sizeof cmdpa);
    cmdpa.commands = commands;
    cmdpa.cmdi = cmd;
    cmdpa.args = args;
    cmdpa.argc = argc;
    cmdpa.labelc = 0;
    cmdpa.varargi = -1;
    const char *pattern = NULL;
    unsigned arg = 0;
    unsigned opt = 0;
    while ((pattern = commands[cmd].words[opt])) {
      //DEBUGF("cmd=%d opt=%d pattern='%s' args[arg=%d]='%s'", cmd, opt, pattern, arg, arg < argc ? args[arg] : "");
      unsigned patlen = strlen(pattern);
      if (cmdpa.varargi != -1)
	return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - more words not allowed after \"...\"", cmd, opt, commands[cmd].words[opt]);
      /* These are the argument matching rules:
       *
       * "..." consumes all remaining arguments
       *
       * "word" consumes one argument that exactly matches "word", does not label it (this is the
       * "simple" case in the code below; all other rules label something that matched)
       *
       * "word1|word2|...|wordN" consumes one argument that exactly matches "word1" or "word2" etc.
       * or "wordN", labels it with the matched word (an empty alternative, eg "|word" does not
       * match an empty argument)
       *
       * (as a special case of the above rule, "|word" consumes one argument that exactly matches
       * "word" and labels it "word", but it appears in the help description as "word")
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
       * "[ANY]..." consumes all remaining arguments which match ANY, as defined below
       *
       * "[word]" consumes one argument if it exactly matches "word", records it with label
       * "word"
       *
       * "[word1|word2|...|wordN]" consumes one argument if it exactly matches "word1" or "word2"
       * etc. or "wordN", labels it with the matched word
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
       */
      if (patlen == 3 && pattern[0] == '.' && pattern[1] == '.' && pattern[2] == '.') {
	cmdpa.varargi = arg;
	arg = argc;
	++opt;
      } else {
	int optional = 0;
	int repeating = 0;
	if (patlen > 5 && pattern[0] == '[' && pattern[patlen-4] == ']' && pattern[patlen-3] == '.' && pattern[patlen-2] == '.' && pattern[patlen-1] == '.') {
	  optional = repeating = 1;
	  pattern += 1;
	  patlen -= 5;
	}
	else if (patlen > 2 && pattern[0] == '[' && pattern[patlen-1] == ']') {
	  optional = 1;
	  pattern += 1;
	  patlen -= 2;
	}
	unsigned oarg = arg;
	const char *text = NULL;
	const char *label = NULL;
	unsigned labellen = 0;
	const char *word = pattern;
	unsigned wordlen = 0;
	char simple = 0;
	unsigned alt = 0;
	if (patlen && *word == '|') {
	  ++alt;
	  ++word;
	}
	if (patlen == 0)
	  return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - empty words not allowed", cmd, opt, commands[cmd].words[opt]);
	for (; word < &pattern[patlen]; word += wordlen + 1, ++alt) {
	  // Skip over empty "||word" alternative (but still count it).
	  if (*word == '|')
	    return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - empty alternatives not allowed", cmd, opt, commands[cmd].words[opt]);
	  // Find end of "word|" alternative.
	  wordlen = 1;
	  while (&word[wordlen] < &pattern[patlen] && word[wordlen] != '|')
	    ++wordlen;
	  // Skip remaining alternatives if we already got a match.
	  if (text)
	    continue;
	  // Look for a match.
	  const char *prefix = NULL;
	  unsigned prefixlen = 0;
	  char prefixarglen = 0;
	  const char *caret = strchr(word, '<');
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
	    simple = 1;
	    text = args[arg];
	    label = word;
	    labellen = wordlen;
	    ++arg;
	  }
	}
	assert(alt > 0);
	if (arg == oarg && !optional)
	  break;
	if (labellen && text && (optional || !simple || alt > 1)) {
	  if (cmdpa.labelc >= NELS(cmdpa.labelv))
	    return WHYF("Internal error: commands[%d].word[%d]=\"%s\" - label limit exceeded", cmd, opt, commands[cmd].words[opt]);
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
    if (!pattern && arg == argc) {
      /* A match!  We got through the command definition with no internal errors and all literal
      args matched and we have a proper number of args.  If we have multiple matches, then note
      that the call is ambiguous. */
      if (matched_cmd >= 0)
	++ambiguous;
      if (ambiguous == 1) {
	NOWHENCE(WHY_argv("Ambiguous command:", argc, args));
	NOWHENCE(HINT("Matches the following:"));
	NOWHENCE(HINT_argv("   ", argc, commands[matched_cmd].words));
      }
      if (ambiguous)
	NOWHENCE(HINT_argv("   ", argc, commands[cmd].words));
      matched_cmd = cmd;
      *parsed = cmdpa;
    }
  }
  /* Don't process ambiguous calls */
  if (ambiguous)
    return 2;
  /* Complain if we found no matching calls */
  if (matched_cmd < 0) {
    if (argc)
      NOWHENCE(WHY_argv("Unknown command:", argc, args));
    return 1;
  }
  return 0;
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

int cli_invoke(const struct cli_parsed *parsed, struct cli_context *context)
{
  IN();
  int ret = parsed->commands[parsed->cmdi].function(parsed, context);
  RETURN(ret);
  OUT();
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

int cli_path_regular(const char *arg)
{
  return arg[0] != '\0' && arg[strlen(arg) - 1] != '/';
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
  while (isdigit(*s))
    ++s;
  return s != arg && *s == '\0';
}

int cli_interval_ms(const char *arg)
{
  return str_to_uint64_interval_ms(arg, NULL, NULL);
}

int cli_optional_did(const char *text)
{
  return text[0] == '\0' || str_is_did(text);
}
