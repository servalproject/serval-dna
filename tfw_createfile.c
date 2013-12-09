/*
Serval Project testing framework utility - create fixture file
Copyright (C) 2012 Serval Project Inc.

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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include "str.h"

static const char *argv0 = "test_createfile";

static void fatal(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char buf[1024];
  setbuffer(stderr, buf, sizeof buf);
  fprintf(stderr, "%s: ", argv0);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  fflush(stderr);
  setbuf(stderr, NULL);
  exit(1);
}

static inline char stripe(int i)
{
  return (i >= ' ' && i <= '~') ? i : '.';
}

int main(int argc, char **argv)
{
  argv0 = argv[0];
  uint64_t size = 0;
  const char *label = "";
  int i;
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    if (str_startswith(arg, "--size=", &arg)) {
      if (!str_to_uint64_scaled(arg, 10, &size, NULL))
	fatal("illegal --size= argument: %s", arg);
    }
    else if (str_startswith(arg, "--label=", &arg))
      label = arg;
    else
      fatal("unrecognised argument: %s", arg);
  }
  uint64_t offset = 0;
  char buf[127];
  for (i = 0; i != sizeof buf; ++i)
    buf[i] = stripe(i);
  const size_t labellen = strlen(label);
  int bouncemax = sizeof buf - labellen;
  if (bouncemax < 0)
    bouncemax = sizeof buf;
  int bounce = 3;
  int bouncedelta = 1;
  while (!ferror(stdout) && offset < size) {
    int n = sprintf(buf, "%"PRId64, offset);
    buf[n] = stripe(n);
    size_t labelsiz = labellen;
    if (labelsiz && bounce < sizeof buf) {
      if (labelsiz > sizeof buf - bounce)
	labelsiz = sizeof buf - bounce;
      memcpy(buf + bounce, label, labelsiz);
    }
    int remain = size - offset - 1;
    if (remain > sizeof buf)
      remain = sizeof buf;
    fwrite(buf, remain, 1, stdout);
    fputc('\n', stdout);
    offset += remain + 1;
    if (bounce <= n || bounce >= bouncemax)
      bouncedelta *= -1;
    if (labelsiz) {
      if (bouncedelta > 0)
	buf[bounce] = stripe(bounce);
      else
	buf[bounce + labelsiz - 1] = stripe(bounce + labelsiz - 1);
    }
    bounce += bouncedelta;
  }
  fflush(stdout);
  if (ferror(stdout))
    fatal("write error: %s [errno=%d]", strerror(errno), errno);
  exit(0);
}
