/*
Serval DNA logging
Copyright 2015 Serval Project Inc.

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

// This compilation unit provides an initialised log_context strbuf for clients that do not provide
// their own.

#include "log.h"
#include "strbuf.h"

static char _log_context[16];
struct strbuf log_context = STRUCT_STRBUF_INIT_STATIC(_log_context);
