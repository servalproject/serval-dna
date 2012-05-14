/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

#include <sys/types.h>
#include <alloca.h>
#include <dirent.h>
#include "serval.h"

int mkdirs(const char *path, mode_t mode)
{
  return mkdirsn(path, strlen(path), mode);
}

int mkdirsn(const char *path, size_t len, mode_t mode)
{
  if (len == 0)
    return WHY("Bug: empty path");
  char *pathfrag = alloca(len + 1);
  strncpy(pathfrag, path, len);
  pathfrag[len] = '\0';
  if (mkdir(pathfrag, mode) != -1)
    return 0;
  if (errno == EEXIST) {
    DIR *d = opendir(pathfrag);
    if (!d) {
      WHY_perror("opendir");
      return WHYF("cannot access %s", pathfrag);
    }
    closedir(d);
    return 0;
  }
  if (errno == ENOENT) {
    const char *lastsep = path + len - 1;
    while (lastsep != path && *--lastsep != '/')
      ;
    while (lastsep != path && *--lastsep == '/')
      ;
    if (lastsep != path) {
      if (mkdirsn(path, lastsep - path + 1, mode) == -1)
	return -1;
      if (mkdir(pathfrag, mode) != -1)
	return 0;
    }
  }
  WHY_perror("mkdir");
  return WHYF("cannot mkdir %s", pathfrag);
}

