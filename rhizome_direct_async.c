/*
Serval Mesh Software
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

/*
  We wish to be able to synchronise Rhizome repositories over asynchonous and/or
  low-bandwidth links.

  One of the challenges is to maximise the usage of the messages, and minimise the
  number of messages, because they can be quite expensive (e.g., sms or satellite
  sms which can cost $0.25 per 140bytes (sms) or $0.25 - $1.00 per 160 bytes 
  (satellite sms).

  If there are very few new items, it may be more efficient to just send them
  rather than negotiate about them because of the high per-message cost.

*/

#include <stdlib.h>
#include "serval.h"
#include "cli.h"

int app_rhizome_direct_async(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  const char *message_bytes,*max_messages,*token;
  cli_arg(argc, argv, o, "message bytes", &message_bytes, NULL, "140");
  cli_arg(argc, argv, o, "max messages", &max_messages, NULL, "10");
  cli_arg(argc, argv, o, "token", &token, NULL, "0");

  DEBUGF("[%s,%s,%s]",
	 message_bytes,max_messages,token);

  int messageBytes=message_bytes?atoi(message_bytes):140;
  int maxMessages=max_messages?atoi(max_messages):10;
  long long firstInsertTime=token?strtoll(token,NULL,10):0;
					 
  DEBUGF("Preparing upto %d messages of upto %d bytes, for rhizome content arrived or updated since %lld",
	 maxMessages,messageBytes,firstInsertTime);

  long long freshBundles=0;
  // sqlite_exec_int64(&freshBundles,"SELECT COUNT(*) FROM MANIFESTS WHERE AT SOME POINT I FINISH WRITING THIS QUERY");

  return 0;
}

