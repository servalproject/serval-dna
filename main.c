/*
Serval daemon
Copyright (C) 2012 The Serval Project

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

#include "serval.h"

int main(int argc, char **argv)
{
#if defined WIN32
  WSADATA wsa_data;
  WSAStartup(MAKEWORD(1,1), &wsa_data);
#endif
  memabuseInit();
  srandomdev();
  server_save_argv(argc, (const char*const*)argv);
  int status = 0;
  /* If first argument starts with a dash, assume it is for the old command line parser. */
  if (argv[1] && argv[1][0] == '-')
    status = parseCommandLine(argc, (const char*const*)argv);
  else
    status = parseCommandLine(argc - 1, (const char*const*)&argv[1]);
#if defined WIN32
  WSACleanup();
#endif
  return status;
}

const char *thisinstancepath = NULL;

const char *serval_instancepath()
{
  if (thisinstancepath)
    return thisinstancepath;
  const char *instancepath = getenv("SERVALINSTANCE_PATH");
  if (!instancepath)
    instancepath = DEFAULT_INSTANCE_PATH;
  return instancepath;
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
