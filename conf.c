/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010-2012 Paul Gardner-Stephen

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
#include <ctype.h>
#include "conf.h"
#include "log.h"

/* This predicate function defines the constraints on configuration option names.
   Valid:
	foo
	foo.bar
	foo.bar.chow
	_word
	word1
	word_1
   Invalid:
        foo.
	.foo
	1foo
	foo.bar.
	12
	1.2.3
	foo bar
   @author Andrew Bettison <andrew@servalproject.com>
 */
int is_configvarname(const char *arg)
{
  if (arg[0] == '\0')
    return 0;
  if (!(isalnum(arg[0]) || arg[0] == '_'))
    return 0;
  const char *s = arg + 1;
  for (; *s; ++s)
    if (!(isalnum(*s) || *s == '_' || (*s == '.' && s[-1] != '.')))
      return 0;
  return s[-1] != '.';
}

#define MAX_CONFIG_VARS		  (100)
#define CONFIG_BUFFER_ALLOCSIZE	  (1024)

static char *config_buffer = NULL;
static char *config_buffer_top = NULL;
static char *config_buffer_end = NULL;
static unsigned int confc = 0;
static char *confvar[MAX_CONFIG_VARS];
static char *confvalue[MAX_CONFIG_VARS];
static int reading = 0;

static char *grow_config_buffer(size_t needed)
{
  size_t cursize = config_buffer_end - config_buffer;
  size_t used = config_buffer_top - config_buffer;
  size_t newsize = used + needed;
  if (newsize > cursize) {
    // Round up to nearest multiple of CONFIG_BUFFER_ALLOCSIZE.
    newsize = newsize + CONFIG_BUFFER_ALLOCSIZE - ((newsize - 1) % CONFIG_BUFFER_ALLOCSIZE + 1);
    char *newbuf = realloc(config_buffer, newsize);
    if (newbuf == NULL) {
      WHYF_perror("realloc(%llu)", newsize);
      return NULL;
    }
    ssize_t dif = newbuf - config_buffer;
    unsigned int i;
    for (i = 0; i != confc; ++i) {
      confvar[i] += dif;
      confvalue[i] += dif;
    }
    config_buffer_end = newbuf + newsize;
    config_buffer_top = newbuf + used;
    config_buffer = newbuf;
  }
  char *ret = config_buffer_top;
  config_buffer_top += needed;
  return ret;
}

static int _read_config()
{
  char conffile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(conffile, "serval.conf"))
    return -1;
  size_t size = 0;
  confc = 0;
  FILE *f = fopen(conffile, "r");
  if (f == NULL) {
    if (errno != ENOENT)
      return WHYF_perror("fopen(%s)", conffile);
  } else {
    if (fseeko(f, (off_t) 0, SEEK_END) == -1) {
      WHYF_perror("fseeko(%s, 0, SEEK_END)", conffile);
      fclose(f);
      return -1;
    }
    off_t tell = ftello(f);
    if (tell == -1) {
      WHYF_perror("ftello(%s)", conffile);
      fclose(f);
      return -1;
    }
    size = tell;
    if (fseeko(f, (off_t) 0, SEEK_SET) == -1) {
      WHYF_perror("fseeko(%s, 0, SEEK_SET)", conffile);
      fclose(f);
      return -1;
    }
    if (grow_config_buffer(size) == NULL) {
      fclose(f);
      return -1;
    }
    if (fread(config_buffer, size, 1, f) != 1) {
      if (ferror(f))
	WHYF_perror("fread(%s, %llu)", conffile, (unsigned long long) size);
      else
	WHYF("fread(%s, %llu) hit EOF", conffile, (unsigned long long) size);
      free(config_buffer);
      config_buffer = NULL;
      fclose(f);
      return -1;
    }
    if (fclose(f) == EOF)
      return WHYF_perror("fclose(%s)", conffile);
  }
  config_buffer_top = config_buffer_end = config_buffer + size;
  char *c = config_buffer;
  char *e = config_buffer_top;
  unsigned int linenum;
  char *problem = NULL;
  char *extra = "";
  for (linenum = 1; !problem && c < e; ++linenum) {
    if (*c == '#') {
      // skip comment lines
      while (c < e && *c != '\n')
	++c;
    } else if (*c == '\n') {
      // skip empty lines
      ++c;
    } else if (c < e - 1 && *c == '\r' && c[1] == '\n') {
      // skip empty lines
      c += 2;
    } else if (confc < MAX_CONFIG_VARS) {
      char *var = confvar[confc] = c;
      while (c < e && *c != '=' && *c != '\r' && *c != '\n')
	++c;
      if (c < e && *c == '=') {
	*c++ = '\0';
	if (is_configvarname(var)) {
	  confvalue[confc] = c;
	  while (c < e && *c != '\r' && *c != '\n')
	    ++c;
	  if (c < e && *c == '\n') {
	    *c++ = '\0';
	    ++confc;
	  } else if (c < e - 1 && *c == '\r' && c[1] == '\n') {
	    *c++ = '\0';
	    *c++ = '\0';
	    ++confc;
	  } else {
	    problem = "missing end-of-line";
	  }
	} else {
	  problem = "invalid variable name: ";
	  extra = var;
	}
      } else {
	problem = "missing '='";
      }
    } else {
      problem = "too many variables";
    }
  }
  if (problem)
    return WHYF("Error in %s at line %u: %s%s", conffile, linenum, problem, extra);
  return 0;
}

/* Set a flag while reading config, to avoid infinite recursion between here and logging
   that could be caused by any WHY() or WARN() or DEBUG() invoked in _read_config().  The
   problem is that on the first log message, the logging system calls confValueGet() to
   discover the path of the log file, and that will return here.
 */
static int read_config()
{
  if (reading)
    return -1;
  reading = 1;
  int ret = _read_config();
  reading = 0;
  return ret;
}

int confLocked()
{
  return reading;
}

int confVarCount()
{
  if (!config_buffer && read_config() == -1)
    return -1;
  return confc;
}

const char *confVar(unsigned int index)
{
  if (!config_buffer && read_config() == -1)
    return NULL;
  if (index >= confc) {
    WHYF("Config index=%u too big, confc=%u", index, confc);
    return NULL;
  }
  return confvar[index];
}

const char *confValue(unsigned int index)
{
  if (!config_buffer && read_config() == -1)
    return NULL;
  if (index >= confc) {
    WHYF("Config index=%u too big, confc=%u", index, confc);
    return NULL;
  }
  return confvalue[index];
}

const char *confValueGet(const char *var, const char *defaultValue)
{
  if (var == NULL) {
    WHYF("NULL var name, returning default value: %s", defaultValue ? defaultValue : "NULL");
    return defaultValue;
  }
  if (!config_buffer && read_config() == -1) {
    if (defaultValue)
      WARNF("Config option %s: using default value: %s", var, defaultValue);
    return defaultValue;
  }
  unsigned int i;
  for (i = 0; i != confc; ++i)
    if (strcasecmp(confvar[i], var) == 0)
      return confvalue[i];
  return defaultValue;
}

int confValueGetBoolean(const char *var, int defaultValue)
{
  const char *value = confValueGet(var, NULL);
  if (!value)
    return defaultValue;
  int flag = confParseBoolean(value, var);
  if (flag >= 0)
    return flag;
  WARNF("Config option %s: using default value %s", var, defaultValue ? "true" : "false");
  return defaultValue;
}

int64_t confValueGetInt64(const char *var, int64_t defaultValue)
{
  const char *start = confValueGet(var, NULL);
  if (!start)
    return defaultValue;
  const char *end = start;
  long long value = strtoll(start, (char **)&end, 10);
  if (*start && !*end && end != start)
    return value;
  WARNF("Config option %s: '%s' is not an integer, using default value %lld", var, start, (long long) defaultValue);
  return defaultValue;
}

int64_t confValueGetInt64Range(const char *var, int64_t defaultValue, int64_t rangemin, int64_t rangemax)
{
  int64_t value = confValueGetInt64(var, defaultValue);
  if (value >= rangemin || value <= rangemax)
    return value;
  WARNF("Config option %s: configured value %lld out of range [%lld,%lld], using default value %lld",
      var, (long long) value, (long long) rangemin, (long long) rangemax, (long long) defaultValue);
  return defaultValue;
}

void confSetDebugFlags()
{
  if (config_buffer || read_config() != -1) {
    debugflags_t setmask = 0;
    debugflags_t clearmask = 0;
    int setall = 0;
    int clearall = 0;
    unsigned int i;
    for (i = 0; i != confc; ++i) {
      char *var = confvar[i];
      if (strncasecmp(var, "debug.", 6) == 0) {
	debugflags_t mask = debugFlagMask(var + 6);
	if (mask == 0)
	  WARNF("Unsupported debug option '%s'", var);
	else {
	  int flag = confParseBoolean(confvalue[i], var);
	  if (flag != -1) {
	    if (mask == DEBUG_ALL) {
	      if (flag) {
		//DEBUGF("Set all debug flags");
		setall = 1;
	      } else {
		//DEBUGF("Clear all debug flags");
		clearall = 1;
	      }
	    } else {
	      if (flag) {
		//DEBUGF("Set %s", var);
		setmask |= mask;
	      } else {
		//DEBUGF("Clear %s", var);
		clearmask |= mask;
	      }
	    }
	  }
	}
      }
    }
    if (setall)
      debug = DEBUG_ALL;
    else if (clearall)
      debug = 0;
    debug &= ~clearmask;
    debug |= setmask;
  }
}

int confParseBoolean(const char *text, const char *option_name)
{
  if (!strcasecmp(text, "on") || !strcasecmp(text, "yes") || !strcasecmp(text, "true") || !strcmp(text, "1"))
    return 1;
  if (!strcasecmp(text, "off") || !strcasecmp(text, "no") || !strcasecmp(text, "false") || !strcmp(text, "0"))
    return 0;
  WARNF("Config option %s: invalid boolean value '%s'", option_name, text);
  return -1;
}

int confValueSet(const char *var, const char *value)
{
  if (!config_buffer && read_config() == -1)
    return -1;
  if (!is_configvarname(var))
    return WHYF("Cannot %s %s: invalid variable name", value ? "set" : "delete", var);
  if (value == NULL) {
    unsigned int i;
    for (i = 0; i < confc; ++i) {
      if (strcasecmp(var, confvar[i]) == 0) {
	--confc;
	for (; i < confc; ++i) {
	  confvar[i] = confvar[i + 1];
	  confvalue[i] = confvalue[i + 1];
	}
	return 0;
      }
    }
  } else {
    if (confc >= MAX_CONFIG_VARS)
      return WHYF("Cannot set %s: too many variables", var);
    size_t valuelen = strlen(value);
    unsigned int i;
    for (i = 0; i != confc; ++i) {
      if (strcasecmp(var, confvar[i]) == 0) {
	char *valueptr = confvalue[i];
	if (valuelen > strlen(valueptr)) {
	  if ((valueptr = grow_config_buffer(valuelen + 1)) == NULL)
	    return -1;
	}
	strcpy(confvar[i], var);
	confvalue[i] = strcpy(valueptr, value);
	return 0;
      }
    }
    size_t varlen = strlen(var);
    char *buf = grow_config_buffer(varlen + 1 + valuelen + 1);
    if (buf == NULL)
      return -1;
    confvar[confc] = strcpy(buf, var);
    confvalue[confc] = strcpy(buf + varlen + 1, value);
    ++confc;
  }
  return 0;
}

int confWrite()
{
  if (config_buffer) {
    char conffile[1024];
    char tempfile[1024];
    FILE *outf = NULL;
    if (!FORM_SERVAL_INSTANCE_PATH(conffile, "serval.conf"))
      return -1;
    if (!FORM_SERVAL_INSTANCE_PATH(tempfile, "serval.conf.temp"))
      return -1;
    if ((outf = fopen(tempfile, "w")) == NULL)
      return WHYF_perror("fopen(%s, \"w\")", tempfile);
    unsigned int i;
    for (i = 0; i != confc; ++i)
      fprintf(outf, "%s=%s\n", confvar[i], confvalue[i]);
    if (fclose(outf) == EOF)
      return WHYF_perror("fclose(%s)", tempfile);
    if (rename(tempfile, conffile)) {
      WHYF_perror("rename(%s, %s)", tempfile, conffile);
      unlink(tempfile);
      return -1;
    }
  }
  return 0;
}

static char *thisinstancepath = NULL;

const char *serval_instancepath()
{
  if (thisinstancepath)
    return thisinstancepath;
  const char *instancepath = getenv("SERVALINSTANCE_PATH");
  if (!instancepath)
    instancepath = DEFAULT_INSTANCE_PATH;
  return instancepath;
}

void serval_setinstancepath(const char *instancepath)
{
  if (thisinstancepath == NULL)
    free(thisinstancepath);
  
  thisinstancepath = strdup(instancepath);
}

int form_serval_instance_path(char *buf, size_t bufsiz, const char *path)
{
  if (snprintf(buf, bufsiz, "%s/%s", serval_instancepath(), path) < bufsiz)
    return 1;
  WHYF("Cannot form pathname \"%s/%s\" -- buffer too small (%lu bytes)", serval_instancepath(), path, (unsigned long)bufsiz);
  return 0;
}

int create_serval_instance_dir() {
  return mkdirs(serval_instancepath(), 0700);
}
