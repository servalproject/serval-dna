/*
 Serval string primitives
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

#ifndef __STR_H__
#define __STR_H__

/* Check if a given string starts with a given sub-string.  If so, return 1 and, if afterp is not
 NULL, set *afterp to point to the character immediately following the substring.  Otherwise
 return 0.
 This function is used to parse HTTP headers and responses, which are typically not
 nul-terminated, but are held in a buffer which has an associated length.  To avoid this function
 running past the end of the buffer, the caller must ensure that the buffer contains a sub-string
 that is not part of the sub-string being sought, eg, "\r\n\r\n" as detected by
 http_header_complete().  This guarantees that this function will return nonzero before running
 past the end of the buffer.
 @author Andrew Bettison <andrew@servalproject.com>
 */
int str_startswith(char *str, const char *substring, char **afterp);

/* Case-insensitive form of str_startswith().
 */
int strcase_startswith(char *str, const char *substring, char **afterp);

/* like strstr(), but doesn't depend on null termination.
   @author Paul Gardner-Stephen <paul@servalproject.org>
   @author Andrew Bettison <andrew@servalproject.com>
 */
char *str_str(char *haystack, const char *needle, int haystack_len);

#endif
