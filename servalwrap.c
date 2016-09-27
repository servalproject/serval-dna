/*
Serval DNA - executable wrapper around shared library
Copyright 2010-2012 Paul Gardner-Stephen
Copyright 2012-2013 Serval Project Inc.
Copyright 2016 Flinders University
 
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

#include <dlfcn.h>
#include <stdio.h>

int main(int argc,char **argv)
{
  const char *libservald_path =
#ifdef ANDROID
    "/data/data/org.servalproject/lib/libservald.so"
#else
    "libservald.so"
#endif
  ;
  const char *entry_point ="servald_main";

  void *h = dlopen(libservald_path, RTLD_LAZY);
  if (!h) {
    fprintf(stderr, "%s\n", dlerror());
    return 1;
  }

  int (*servald_main)(int, char **) = dlsym(h, entry_point);
  if (!servald_main) {
    fprintf(stderr, "Could not resolve %s in %s\n", entry_point, libservald_path);
    return 1;
  }
 
  return (*servald_main)(argc, argv);
}
