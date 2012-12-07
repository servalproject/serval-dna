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

#define RDA_MSG_BARS_RAW 0x01
#define RDA_MSG_MANIFESTS 0x02

static int messagesRequired(int bytesPerMessage,int bytesToSend)
{
  /* Overhead per message is as follows to deal with out-of-order delivery.
     We don't do retransmission or detection of dropped messages.     
     1 byte - conversation ID 
     1 byte - message sequence number
  */
  int netBytesPerMessage=bytesPerMessage-1-1;

  return bytesToSend/netBytesPerMessage+(bytesToSend%netBytesPerMessage?1:0);
}

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
  unsigned long long rowids[MAX_FRESH];
  int manifestBytes[MAX_FRESH];
  unsigned long long insertTimes[MAX_FRESH];

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry,   
					   "SELECT rowid, inserttime FROM MANIFESTS WHERE inserttime>=%lld ORDER BY inserttime LIMIT %d",
					   firstInsertTime,MAX_FRESH);
  while (freshBundles<MAX_FRESH
	 && sqlite_step_retry(&retry, statement) == SQLITE_ROW
	 ) {
    unsigned long long rowid;
    sqlite3_blob *blob;
    if (sqlite3_column_type(statement, 0)==SQLITE_INTEGER)
      rowid = sqlite3_column_int64(statement, 0);
    if (sqlite3_column_type(statement, 1)==SQLITE_INTEGER)
      insertTimes[freshBundles] = sqlite3_column_int64(statement, 1);
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

    do ret = sqlite3_blob_open(rhizome_db, "main", "MANIFESTS", "manifest", rowid, 0,
			       &blob);
    while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
    if (ret != SQLITE_OK) {
      WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
      continue;
    }
    manifestBytes[freshBundles]=sqlite3_blob_bytes(blob);
    sqlite3_blob_close(blob);

    rowids[freshBundles]=rowid;
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

  /* Work out the last insert time covered.
     It is either the insert time of the last manifest we read, or
     if more than one manifest exists with that insert time, and we have
     not included all of them, then we need to decremebt lastInsertTimeCovered
     so that we include the rest next time.

     Of course, if there are too many with the same insert time, then we have
     a problem.  Rather than get stuck in an infinite loop, in that case we just
     assume we have them all.
  */
  uint64_t lastInsertTimeCovered=insertTimes[freshBundles-1];
  int64_t countIncluded=0,countTotal=0;
  int i;
  sqlite_exec_int64_retry(&retry, &countTotal, "select COUNT(*) FROM MANIFESTS WHERE inserttime=%lld",lastInsertTimeCovered);
  for(i=freshBundles-1;i>=0;i--) {
    if (insertTimes[i]==lastInsertTimeCovered) countIncluded++;
    else break;
  }
  if (i>=0&&countIncluded<countTotal) {
    DEBUGF("We have only %d of %d bundles with inserttime=%lld -- decrementing lastInsertTimeCovered",
	   countIncluded,countTotal,lastInsertTimeCovered);
    lastInsertTimeCovered--;
  } else {
    DEBUGF("We have all %d bundles with inserttime=%lld",
	   countTotal,lastInsertTimeCovered);
  }

  /* If there are very few fresh bundles, it is more efficient to just send the
     manifests, rather than go back and forth to see what they already have.     

     We only keep the latest version of any given manifest, so rather annoyingly
     we can't tell if the far end already knows about a manifest.  What we can do
     is send abbreviated BIDs and versions, which will allow the far end to
     work out with high probability (but not certainty) whether they have the
     bundle in question.
  */
  
  struct overlay_buffer *header=ob_new();
  struct overlay_buffer *announceAsBars=ob_new();
  struct overlay_buffer *announceAsManifests=ob_new();
  
  /* Start of time range */
  ob_append_ui32(header,firstInsertTime>>32);
  ob_append_ui32(header,firstInsertTime&0xffffffff);
  if (lastInsertTimeCovered-firstInsertTime>0xffffffffLL)
    ob_append_ui32(header,0xffffffff);
  else
    ob_append_ui32(header,(unsigned int)(lastInsertTimeCovered-firstInsertTime));

  ob_append_bytes(announceAsBars,header->bytes,header->position);
  ob_append_byte(announceAsBars,RDA_MSG_BARS_RAW);
  for(i=0;i<freshBundles;i++) {
    /* XXX compact BARs (geobounding box and version are low entropy).
       Version is also potentially low entropy.  We can certainly order
       the BARs by version so that the entropy of the BARs is reduced. */
    ob_append_bytes(announceAsBars,bars[i],RHIZOME_BAR_BYTES);
  }

  ob_append_bytes(announceAsManifests,header->bytes,header->position);
  ob_append_byte(announceAsManifests,RDA_MSG_MANIFESTS);
  for(i=0;i<freshBundles;i++) {    
    int ret;
    sqlite3_blob *blob=NULL;
    do ret = sqlite3_blob_open(rhizome_db, "main", "MANIFESTS", "manifest", 
			       rowids[i], 0, &blob);
    while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
    if (ret != SQLITE_OK) {
      WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
      continue;
    }
    if (manifestBytes[i]<250)
      ob_append_byte(announceAsManifests,manifestBytes[i]);
    else {
      ob_append_byte(announceAsManifests,250+manifestBytes[i]/250);
      ob_append_byte(announceAsManifests,manifestBytes[i]%255);
    }      
    ob_makespace(announceAsManifests,manifestBytes[i]);
    sqlite3_blob_read(blob,
		      &announceAsManifests->bytes[announceAsManifests->position],
		      manifestBytes[i],0);
    announceAsManifests->position+=manifestBytes[i];
    sqlite3_blob_close(blob);
  }

  DEBUGF("Requires %d bytes (%d messages) as raw BARs",
	 announceAsBars->position,
	 messagesRequired(messageBytes,announceAsBars->position));
  DEBUGF("Requires %d bytes (%d messages) as raw Manifests",
	 announceAsManifests->position,
	 messagesRequired(messageBytes,announceAsManifests->position));

  /* Work out best format.
     We want the fewest messages, but also the most information.
     So we compare on the number of messages required, not the exact number
     of bytes, because we might be able to use the spare bytes productively.
     Thus the order of these tests is with most preferable last, but trumping
     previous decisions.  */
  int bestMessagesRequired=messagesRequired(messageBytes,announceAsBars->position);
  struct overlay_buffer *bestbuffer=announceAsBars;
  if (messagesRequired(messageBytes,announceAsManifests->position)
      <=bestMessagesRequired) {
    bestMessagesRequired=messagesRequired(messageBytes,
					  announceAsManifests->position);
    bestbuffer=announceAsManifests;
  }

  DEBUGF("Sending using %d bytes (%d messages)",
	 bestbuffer->position,bestMessagesRequired);

  return 0;
}

static int uchar_to_limited_alphabet(unsigned char *in,int in_len,
				     unsigned char *alphabet,int alphabet_size,
				     unsigned char *out,int *out_len)
{
  int i;
  *out_len=0;

  int output_digits=in_len*256/alphabet_size;
  if (in_len*256%alphabet_size) output_digits++;

  return 0;
}

static int limited_alphabet_to_uchar(unsigned char *in,int in_len,
				     unsigned char *alphabet,int alphabet_size,
				     unsigned char *out,int *out_len)
{
  int i;
  
  int m=1;
  int a=0;
  for(i=0;<in_len;i++)
    {
      int c=in[i];
      a+=(c%alphabet_size);
      c=c/alphabet_size;
    }
}
