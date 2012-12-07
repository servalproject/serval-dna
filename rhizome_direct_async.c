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
#include "rhizome.h"
#include "cli.h"
#include "overlay_buffer.h"

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

#define MAX_FRESH 128
  int freshBundles=0;
  unsigned char bars[MAX_FRESH][RHIZOME_BAR_BYTES]; // 128x32 = 4KB

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry,   
					   "SELECT rowid FROM MANIFESTS WHERE inserttime>=%lld ORDER BY inserttime LIMIT %d",
					   firstInsertTime,MAX_FRESH);
  while (freshBundles<MAX_FRESH
	 && sqlite_step_retry(&retry, statement) == SQLITE_ROW
	 ) {
    unsigned long long rowid;
    sqlite3_blob *blob;
    if (sqlite3_column_type(statement, 0)==SQLITE_INTEGER)
      rowid = sqlite3_column_int64(statement, 0);
    int ret;
    do ret = sqlite3_blob_open(rhizome_db, "main", "MANIFESTS", "bar", rowid, 0,
			       &blob);
    while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
    if (ret != SQLITE_OK) {
      WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
      continue;
    }
    if(sqlite3_blob_read(blob,&bars[freshBundles][0],RHIZOME_BAR_BYTES,0)
       !=SQLITE_OK) {
      sqlite3_blob_close(blob);
      WHYF("sqlite3_blob_read() failed, %s", sqlite3_errmsg(rhizome_db));
      continue;
    }
    sqlite3_blob_close(blob);
    dump("BAR",bars[freshBundles],RHIZOME_BAR_BYTES);
    freshBundles++;    
  }
  sqlite3_finalize(statement);

  DEBUGF("There are %d bundles that we need to tell the far side about.",
	 freshBundles);
  if (!freshBundles) {
    DEBUG("There is nothing to do.");
    return 0;
  }

  /* If there are very few fresh bundles, it is more efficient to just send the
     manifests, rather than go back and forth to see what they already have.     

     We only keep the latest version of any given manifest, so rather annoyingly
     we can't tell if the far end already knows about a manifest.  What we can do
     is send abbreviated BIDs and versions, which will allow the far end to
     work out with high probability (but not certainty) whether they have the
     bundle in question.
  */
  
  struct overlay_buffer *newContentAnnouncement=ob_new();

  int i;
  // for(i=0;i<freshBundles;i++)

  return 0;
}

