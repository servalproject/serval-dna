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

#include <dlfcn.h>
#include <stdio.h>

int main(int argc,char **argv)
{
 void *h = dlopen("/data/data/org.servalproject/lib/libdnalib.so",RTLD_LAZY);
 int (*dnamain)(int,char **) = dlsym(h,"main");
 if (!dnamain) return fprintf(stderr,"Could not load libdnalib.so\n");
 return (*dnamain)(argc,argv);

}
