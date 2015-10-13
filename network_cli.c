/*
 Serval network command line functions
 Copyright (C) 2014 Serval Project Inc.
 
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

#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <math.h>
#include "cli.h"
#include "dataformats.h"
#include "mdp_client.h"
#include "conf.h"
#include "commandline.h"
#include "sighandlers.h"
#include "instance.h"
#include "serval.h"
#include "overlay_buffer.h"


DEFINE_CMD(app_mdp_ping, 0,
  "Attempts to ping specified node via Mesh Datagram Protocol (MDP).",
  "mdp","ping","[--interval=<ms>]","[--timeout=<seconds>]","[--wait-for-duplicates]",
  "<SID>|broadcast","[<count>]");
static int app_mdp_ping(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);
  const char *sidhex, *count, *opt_timeout, *opt_interval;
  int opt_wait_for_duplicates = 0 == cli_arg(parsed, "--wait-for-duplicates", NULL, NULL, NULL);
  if (   cli_arg(parsed, "--timeout", &opt_timeout, cli_interval_ms, "1") == -1
      || cli_arg(parsed, "--interval", &opt_interval, cli_interval_ms, "1") == -1
      || cli_arg(parsed, "SID", &sidhex, str_is_subscriber_id, "broadcast") == -1
      || cli_arg(parsed, "count", &count, cli_uint, "0") == -1)
    return -1;

  /* Get SID that we want to ping.
     TODO - allow lookup of SID prefixes and telephone numbers
     (that would require MDP lookup of phone numbers, which doesn't yet occur) */
  sid_t ping_sid;
  if (str_to_sid_t(&ping_sid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");
  
  // assume we wont hear any responses
  int ret=1;
  unsigned icount = atoi(count);
  int64_t timeout_ms = 1000;
  str_to_uint64_interval_ms(opt_timeout, &timeout_ms, NULL);
  if (timeout_ms == 0)
    timeout_ms = 60 * 60000; // 1 hour...
  int64_t interval_ms = 1000;
  str_to_uint64_interval_ms(opt_interval, &interval_ms, NULL);
  if (interval_ms == 0)
    interval_ms = 1000;
    
  /* First sequence number in the echo frames */
  uint32_t firstSeq = random();
  uint32_t sequence_number = firstSeq;

  int broadcast = is_sid_t_broadcast(ping_sid);

  /* Bind to MDP socket and await confirmation */
  if ((mdp_sockfd = mdp_socket()) < 0)
    return WHY("Cannot create MDP socket");

  set_nonblock(mdp_sockfd);
  struct mdp_header mdp_header;
  bzero(&mdp_header, sizeof(mdp_header));

  mdp_header.local.sid = BIND_PRIMARY;
  mdp_header.remote.sid = ping_sid;
  mdp_header.remote.port = MDP_PORT_ECHO;
  mdp_header.qos = OQ_MESH_MANAGEMENT;
  mdp_header.ttl = PAYLOAD_TTL_DEFAULT;
  mdp_header.flags = MDP_FLAG_BIND;
  if (broadcast)
    mdp_header.flags |= MDP_FLAG_NO_CRYPT;
  
  /* TODO Eventually we should try to resolve SID to phone number and vice versa */
  cli_printf(context, "MDP PING %s: 12 data bytes", alloca_tohex_sid_t(ping_sid));
  cli_delim(context, "\n");
  cli_flush(context);

  unsigned tx_count = 0;
  unsigned missing_pong_count = 0;
  unsigned rx_count = 0;
  unsigned rx_dupcount = 0;
  unsigned rx_igncount = 0;
  time_ms_t rx_mintime_ms = -1;
  time_ms_t rx_maxtime_ms = -1;
  time_ms_t rx_tottime_ms = 0;
  struct packet_stat {
    uint32_t sequence;
    time_ms_t tx_time;
    time_ms_t rx_time;
    unsigned pong_count;
  } stats[1024];
  bzero(stats, sizeof stats);

  if (broadcast)
    WARN("broadcast ping packets will not be encrypted");
  
  sigIntFlag = 0;
  signal(SIGINT, sigIntHandler);
  
  while (!sigIntFlag && (icount == 0 || tx_count < icount)) {
    time_ms_t now = gettime_ms();
    
    // send a ping packet
    if (tx_count == 0 || !(mdp_header.flags & MDP_FLAG_BIND)) {
      uint8_t payload[12];
      write_uint32(&payload[0], sequence_number);
      write_uint64(&payload[4], now);
      int r = mdp_send(mdp_sockfd, &mdp_header, payload, sizeof(payload));
      if (r != -1) {
	DEBUGF(mdprequests, "ping seq=%lu", (unsigned long)(sequence_number - firstSeq) + 1);
	unsigned i = (unsigned long)(sequence_number - firstSeq) % NELS(stats);
	assert(i == tx_count % NELS(stats));
	struct packet_stat *stat = &stats[i];
	if (stat->tx_time && stat->pong_count == 0) {
	  assert(missing_pong_count > 0);
	  --missing_pong_count;
	}
	stat->sequence = sequence_number;
	stat->tx_time = now;
	stat->pong_count = 0;
	++missing_pong_count;
	++sequence_number;
	++tx_count;
      }
    }

    // Now look for replies ("pongs") until one second has passed, and print any replies with
    // appropriate information as required
    int all_sent = icount && tx_count >= icount;
    time_ms_t finish = now + (all_sent ? timeout_ms : interval_ms);
    while (!sigIntFlag && now < finish && (!all_sent || opt_wait_for_duplicates || missing_pong_count)) {
      time_ms_t poll_timeout_ms = finish - now;
      if (mdp_poll(mdp_sockfd, poll_timeout_ms) <= 0) {
	now = gettime_ms();
	continue;
      }

      struct mdp_header mdp_recv_header;
      uint8_t recv_payload[12];
      ssize_t len = mdp_recv(mdp_sockfd, &mdp_recv_header, recv_payload, sizeof(recv_payload));
      if (len == -1)
	break;
      if (mdp_recv_header.flags & MDP_FLAG_ERROR) {
	WHY("error from daemon, please check the log for more information");
	continue;
      }
      if (mdp_recv_header.flags & MDP_FLAG_BIND){
	// received port binding confirmation
	mdp_header.local = mdp_recv_header.local;
	mdp_header.flags &= ~MDP_FLAG_BIND;
	DEBUGF(mdprequests, "bound to %s:%d", alloca_tohex_sid_t(mdp_header.local.sid), mdp_header.local.port);
	continue;
      }
      if ((size_t)len < sizeof(recv_payload)){
	DEBUGF(mdprequests, "ignoring short pong");
	continue;
      }
      uint32_t rxseq = read_uint32(&recv_payload[0]);
      time_ms_t txtime = read_uint64(&recv_payload[4]);
      int hop_count = 64 - mdp_recv_header.ttl;
      now = gettime_ms();
      time_ms_t delay = now - txtime;

      struct packet_stat *stat = &stats[(unsigned long)(rxseq - firstSeq) % NELS(stats)];
      if (stat->sequence != rxseq || stat->tx_time != txtime) {
	DEBUGF(mdprequests, "ignoring spurious pong");
	++rx_igncount;
	stat = NULL; // old or corrupted reply (either sequence or txtime is wrong)
      } else if (stat->pong_count++ == 0) {
	assert(missing_pong_count > 0);
	--missing_pong_count;
	stat->rx_time = now;
	rx_tottime_ms += delay;
	++rx_count;
	if (rx_mintime_ms > delay || rx_mintime_ms == -1)
	  rx_mintime_ms = delay;
	if (delay > rx_maxtime_ms)
	  rx_maxtime_ms = delay;
      } else
	++rx_dupcount;

      cli_put_hexvalue(context, mdp_recv_header.remote.sid.binary, SID_SIZE, ": seq=");
      cli_put_long(context, (unsigned long)(rxseq - firstSeq) + 1, " time=");
      cli_put_long(context, delay, "ms hops=");
      cli_put_long(context, hop_count, "");
      cli_put_string(context, (mdp_recv_header.flags & MDP_FLAG_NO_CRYPT) ? "" : " ENCRYPTED", "");
      cli_put_string(context, (mdp_recv_header.flags & MDP_FLAG_NO_SIGN) ? "" : " SIGNED", "\n");
      cli_flush(context);

      ret=0;
    }
  }

  signal(SIGINT, SIG_DFL);
  sigIntFlag = 0;
  mdp_close(mdp_sockfd);
  
  {
    float rx_stddev = 0;
    float rx_mean = rx_tottime_ms * 1.0 / rx_count;
    unsigned tx_samples = tx_count < NELS(stats) ? tx_count : NELS(stats);
    unsigned rx_samples = 0;
    unsigned i;
    for (i = 0; i < tx_samples; ++i) {
      struct packet_stat *stat = &stats[i];
      if (stat->pong_count) {
	float dev = rx_mean - (stat->rx_time - stat->tx_time);
	rx_stddev += dev * dev;
	++rx_samples;
      }
    }
    rx_stddev /= rx_samples;
    rx_stddev = sqrtf(rx_stddev);

    /* XXX Report final statistics before going */
    cli_printf(context, "--- %s ping statistics ---\n", alloca_tohex_sid_t(ping_sid));
    cli_printf(context, "%u packets transmitted, %u packets received (plus %u duplicates, %u ignored), %3.1f%% packet loss\n",
	   tx_count,
	   rx_count,
	   rx_dupcount,
	   rx_igncount,
	   tx_count ? (tx_count - rx_count) * 100.0 / tx_count : 0
	  );
    if (rx_samples)
      cli_printf(context, "round-trip min/avg/max/stddev = %"PRId64"/%.3f/%"PRId64"/%.3f ms (%u samples)\n",
	    rx_mintime_ms, rx_mean, rx_maxtime_ms, rx_stddev, rx_samples);
    cli_delim(context, NULL);
    cli_flush(context);
  }
  return ret;
}

DEFINE_CMD(app_trace, 0,
   "Trace through the network to the specified node via MDP.",
   "mdp","trace","[--timeout=<seconds>]","<SID>");
static int app_trace(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  const char *sidhex, *opt_timeout;
  if (   cli_arg(parsed, "--timeout", &opt_timeout, cli_interval_ms, "5") == -1
      || cli_arg(parsed, "SID", &sidhex, str_is_subscriber_id, NULL) == -1)
    return -1;
  
  sid_t srcsid;
  sid_t dstsid;
  if (str_to_sid_t(&dstsid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

  int64_t timeout_ms = 5000;
  str_to_uint64_interval_ms(opt_timeout, &timeout_ms, NULL);
  if (timeout_ms == 0)
    timeout_ms = 60 * 60000; // 1 hour...
    
  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");
  mdp_port_t port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(mdp_sockfd, 0, &srcsid)) {
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Could not get local address");
  }
  if (overlay_mdp_bind(mdp_sockfd, &srcsid, port)) {
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Could not bind to MDP socket");
  }
  
  cli_printf(context, "Tracing the network path from %s to %s", 
	alloca_tohex_sid_t(srcsid), alloca_tohex_sid_t(dstsid));
  cli_delim(context, "\n");
  cli_flush(context);
  // TODO keep sending packets till we get a response?
  int ret=0;
  time_ms_t end = gettime_ms() + timeout_ms;
  overlay_mdp_frame mdp;
  do{
    bzero(&mdp, sizeof(mdp));
    
    mdp.out.src.sid = srcsid;
    mdp.out.dst.sid = srcsid;
    mdp.out.src.port=port;
    mdp.out.dst.port=MDP_PORT_TRACE;
    mdp.packetTypeAndFlags=MDP_TX;
    struct overlay_buffer *b = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
    ob_append_byte(b, SID_SIZE);
    ob_append_bytes(b, srcsid.binary, SID_SIZE);
    ob_append_byte(b, SID_SIZE);
    ob_append_bytes(b, dstsid.binary, SID_SIZE);
    if (ob_overrun(b)){
      ret = WHY("overlay buffer overrun");
      break;
    }
    mdp.out.payload_length = ob_position(b);
    ret = overlay_mdp_send(mdp_sockfd, &mdp, MDP_AWAITREPLY, 500);
    ob_free(b);
  }while(ret && gettime_ms() < end);
  
  if (ret)
    WHYF("overlay_mdp_send returned %d, %s", ret, mdp.error.message);
  if (ret == 0) {
    int offset=0;
    {
      // skip the first two sid's
      uint len = mdp.out.payload[offset++];
      offset+=len;
      if (offset<mdp.out.payload_length){
	len = mdp.out.payload[offset++];
	offset+=len;
      }
    }
    int i=0;
    while(offset<mdp.out.payload_length){
      uint len = mdp.out.payload[offset++];
      cli_put_long(context, i, ":");
      cli_put_string(context, alloca_tohex(&mdp.out.payload[offset], len), "\n");
      offset+=len;
      i++;
    }
  }
  overlay_mdp_client_close(mdp_sockfd);
  return ret;
}

DEFINE_CMD(app_id_self, 0,
  "Return identity(s) as URIs of own node, or of known routable peers, or all known peers",
  "id","self|peers|allpeers");
static int app_id_self(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);
  /* List my own identities */
  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  int result;
  
  a.packetTypeAndFlags=MDP_GETADDRS;
  const char *arg = parsed->labelc ? parsed->labelv[0].text : "";
  if (!strcasecmp(arg,"self"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_SELF; /* get own identities */
  else if (!strcasecmp(arg,"allpeers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ALL_PEERS; /* get all known peers */
  else if (!strcasecmp(arg,"peers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS; /* get routable (reachable) peers */
  else
    return WHYF("unsupported arg '%s'", arg);
  a.addrlist.first_sid=0;

  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");

  const char *names[]={
    "sid"
  };
  cli_columns(context, 1, names);
  size_t rowcount=0;

  do{
    result=overlay_mdp_send(mdp_sockfd, &a, MDP_AWAITREPLY, 5000);
    if (result) {
      if (a.packetTypeAndFlags==MDP_ERROR){
	WHYF("  MDP Server error #%d: '%s'",
	     a.error.error,a.error.message);
      } else
	WHYF("Could not get list of local MDP addresses");
      overlay_mdp_client_close(mdp_sockfd);
      return WHY("Failed to get local address list");
    }
    if ((a.packetTypeAndFlags&MDP_TYPE_MASK)!=MDP_ADDRLIST) {
      overlay_mdp_client_close(mdp_sockfd);
      return WHY("MDP Server returned something other than an address list");
    }
    unsigned i;
    for(i=0;i<a.addrlist.frame_sid_count;i++) {
      rowcount++;
      cli_put_string(context, alloca_tohex_sid_t(a.addrlist.sids[i]), "\n");
    }
    /* get ready to ask for next block of SIDs */
    a.packetTypeAndFlags=MDP_GETADDRS;
    a.addrlist.first_sid=a.addrlist.last_sid+1;
  }while(a.addrlist.frame_sid_count==MDP_MAX_SID_REQUEST);
  cli_row_count(context, rowcount);
  overlay_mdp_client_close(mdp_sockfd);
  return 0;
}

DEFINE_CMD(app_count_peers, 0,
  "Return a count of routable peers on the network",
  "peer","count");
static int app_count_peers(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);

  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");

  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS;
  a.addrlist.first_sid = OVERLAY_MDP_ADDRLIST_MAX_SID_COUNT;
  int ret=overlay_mdp_send(mdp_sockfd, &a,MDP_AWAITREPLY,5000);
  overlay_mdp_client_close(mdp_sockfd);
  if (ret){
    if (a.packetTypeAndFlags==MDP_ERROR)
      return WHYF("  MDP Server error #%d: '%s'",a.error.error,a.error.message);
    return WHYF("Failed to send request");
  }
  cli_put_long(context, a.addrlist.server_sid_count, "\n");
  return 0;
}

DEFINE_CMD(app_route_print, 0,
  "Print the routing table",
  "route","print");
static int app_route_print(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);
    
  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_ROUTING_TABLE;
  overlay_mdp_send(mdp_sockfd, &mdp,0,0);
  
  const char *names[]={
    "Subscriber id",
    "Routing flags",
    "Interface",
    "Next hop"
  };
  cli_columns(context, 4, names);
  size_t rowcount=0;
  
  while(overlay_mdp_client_poll(mdp_sockfd, 200)){
    overlay_mdp_frame rx;
    int ttl;
    if (overlay_mdp_recv(mdp_sockfd, &rx, 0, &ttl))
      continue;
    
    int ofs=0;
    while(ofs + sizeof(struct overlay_route_record) <= rx.out.payload_length){
      struct overlay_route_record *p=&rx.out.route_record;
      ofs+=sizeof(struct overlay_route_record);
      
      if (p->reachable==REACHABLE_NONE)
	continue;

      cli_put_string(context, alloca_tohex_sid_t(p->sid), ":");
      char flags[32];
      strbuf b = strbuf_local_buf(flags);
      
      switch (p->reachable){
	case REACHABLE_SELF:
	  strbuf_puts(b, "SELF");
	  break;
	case REACHABLE_BROADCAST:
	  strbuf_puts(b, "BROADCAST");
	  break;
	case REACHABLE_UNICAST:
	  strbuf_puts(b, "UNICAST");
	  break;
	case REACHABLE_INDIRECT:
	  strbuf_puts(b, "INDIRECT");
	  break;
	default:
	  strbuf_sprintf(b, "%d", p->reachable);
      }
      cli_put_string(context, strbuf_str(b), ":");
      cli_put_string(context, p->interface_name, ":");
      cli_put_string(context, alloca_tohex_sid_t(p->neighbour), "\n");
      rowcount++;
    }
  }
  overlay_mdp_client_close(mdp_sockfd);
  cli_row_count(context, rowcount);
  return 0;
}

DEFINE_CMD(app_network_scan, 0,
  "Scan the network for serval peers. If no argument is supplied, all local addresses will be scanned.",
  "scan","[<address>]");
static int app_network_scan(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_SCAN;
  
  struct overlay_mdp_scan *scan = (struct overlay_mdp_scan *)&mdp.raw;
  const char *address;
  if (cli_arg(parsed, "address", &address, NULL, NULL) == -1)
    return -1;
  
  if (address){
    if (!inet_aton(address, &scan->addr))
      return WHY("Unable to parse the address");
  }else
    INFO("Scanning local networks");
  
  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");
  overlay_mdp_send(mdp_sockfd, &mdp, MDP_AWAITREPLY, 5000);
  overlay_mdp_client_close(mdp_sockfd);
  
  if (mdp.packetTypeAndFlags!=MDP_ERROR)
    return -1;
  cli_put_string(context, mdp.error.message, "\n");
  return mdp.error.error;
}

static void lookup_send_request(int mdp_sockfd, const sid_t *srcsid, int srcport, const sid_t *dstsid, const char *did)
{
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  /* set source address to the local address and port */
  mdp.out.src.port = srcport;
  mdp.out.src.sid = *srcsid;

  /* Send to destination address and DNA lookup port */
  if (dstsid) {
    /* Send an encrypted unicast packet */
    mdp.packetTypeAndFlags=MDP_TX;
    mdp.out.dst.sid = *dstsid;
  }else{
    /* Send a broadcast packet, flooding across the local mesh network */
    mdp.packetTypeAndFlags=MDP_TX|MDP_NOCRYPT;
    mdp.out.dst.sid = SID_BROADCAST;
  }
  mdp.out.dst.port=MDP_PORT_DNALOOKUP;

  /* put DID into packet */
  bcopy(did,&mdp.out.payload[0],strlen(did)+1);
  mdp.out.payload_length=strlen(did)+1;

  overlay_mdp_send(mdp_sockfd, &mdp, 0, 0);

  /* Also send an encrypted unicast request to a configured directory service */
  if (!dstsid){
    if (!is_sid_t_any(config.directory.service)) {
      mdp.out.dst.sid = config.directory.service;
      mdp.packetTypeAndFlags=MDP_TX;
      overlay_mdp_send(mdp_sockfd, &mdp,0,0);
    }
  }
}

DEFINE_CMD(app_dna_lookup, 0,
  "Lookup the subscribers (SID) with the supplied telephone number (DID).",
  "dna","lookup","<did>","[<timeout>]");
static int app_dna_lookup(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);

  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;

  int uri_count=0;
#define MAXREPLIES 256
#define MAXURILEN 256
  char uris[MAXREPLIES][MAXURILEN];

  const char *did, *delay;
  if (cli_arg(parsed, "did", &did, cli_lookup_did, "*") == -1)
    return -1;
  if (cli_arg(parsed, "timeout", &delay, NULL, "3000") == -1)
    return -1;

  int idelay=atoi(delay);
  int one_reply=0;

  // Ugly hack, if timeout is negative, stop after first reply
  if (idelay<0){
    one_reply=1;
    idelay=-idelay;
  }

  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");

  /* Bind to MDP socket and await confirmation */
  sid_t srcsid;
  mdp_port_t port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(mdp_sockfd, 0, &srcsid)) {
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Could not get local address");
  }
  if (overlay_mdp_bind(mdp_sockfd, &srcsid, port)) {
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Could not bind to MDP socket");
  }

  /* use MDP to send the lookup request to MDP_PORT_DNALOOKUP, and wait for
     replies. */

  /* Now repeatedly send resolution request and collect results until we reach
     timeout. */
  time_ms_t timeout = gettime_ms() + idelay;
  time_ms_t last_tx = 0;
  time_ms_t now;
  int interval=125;

  const char *names[]={
    "uri",
    "did",
    "name"
  };
  cli_columns(context, 3, names);
  size_t rowcount = 0;

  while (timeout > (now = gettime_ms())){
    if ((last_tx+interval)<now){
      lookup_send_request(mdp_sockfd, &srcsid, port, NULL, did);
      last_tx=now;
      interval+=interval>>1;
    }
    time_ms_t short_timeout=125;
    while(short_timeout>0) {
      if (overlay_mdp_client_poll(mdp_sockfd, short_timeout)){
	overlay_mdp_frame rx;
	int ttl;
	if (overlay_mdp_recv(mdp_sockfd, &rx, port, &ttl)==0){
	  if (rx.packetTypeAndFlags==MDP_ERROR){
	    WHYF("       Error message: %s", rx.error.message);
	  } else if ((rx.packetTypeAndFlags&MDP_TYPE_MASK)==MDP_TX) {
	    /* Extract DID, Name, URI from response. */
	    if (strlen((char *)rx.out.payload)<512) {
	      char sidhex[SID_STRLEN + 1];
	      char did[DID_MAXSIZE + 1];
	      char name[64];
	      char uri[512];
	      if ( !parseDnaReply((char *)rx.out.payload, rx.out.payload_length, sidhex, did, name, uri, NULL)
		|| !str_is_subscriber_id(sidhex)
		|| !str_is_did(did)
		|| !str_is_uri(uri)
	      ) {
		WHYF("Received malformed DNA reply: %s", alloca_toprint(160, (const char *)rx.out.payload, rx.out.payload_length));
	      } else {
		/* Have we seen this response before? */
		int i;
		for(i=0;i<uri_count;i++)
		  if (!strcmp(uri,uris[i])) break;
		if (i==uri_count) {
		  /* Not previously seen, so report it */
		  cli_put_string(context, uri, ":");
		  cli_put_string(context, did, ":");
		  cli_put_string(context, name, "\n");
		  rowcount++;

		  if (one_reply){
		    timeout=now;
		    short_timeout=0;
		  }

		  /* Remember that we have seen it */
		  if (uri_count<MAXREPLIES&&strlen(uri)<MAXURILEN) {
		    strcpy(uris[uri_count++],uri);
		  }
		}
	      }
	    }
	  }
	  else WHYF("packettype=0x%x",rx.packetTypeAndFlags);
	}
      }
      short_timeout=125-(gettime_ms()-now);
    }
  }

  overlay_mdp_client_close(mdp_sockfd);
  cli_row_count(context, rowcount);
  return 0;
}

DEFINE_CMD(app_reverse_lookup, 0,
  "Lookup the phone number (DID) and name of a given subscriber (SID)",
  "reverse", "lookup", "<sid>", "[<timeout>]");
static int app_reverse_lookup(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  DEBUG_cli_parsed(verbose, parsed);
  const char *sidhex, *delay;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1)
    return -1;
  if (cli_arg(parsed, "timeout", &delay, NULL, "3000") == -1)
    return -1;

  mdp_port_t port=32768+(random()&0xffff);

  sid_t srcsid;
  sid_t dstsid;

  if (str_to_sid_t(&dstsid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

  if ((mdp_sockfd = overlay_mdp_client_socket()) < 0)
    return WHY("Cannot create MDP socket");

  if (overlay_mdp_getmyaddr(mdp_sockfd, 0, &srcsid)){
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Unable to get my address");
  }
  if (overlay_mdp_bind(mdp_sockfd, &srcsid, port)){
    overlay_mdp_client_close(mdp_sockfd);
    return WHY("Unable to bind port");
  }

  time_ms_t now = gettime_ms();
  time_ms_t timeout = now + atoi(delay);
  time_ms_t next_send = now;
  overlay_mdp_frame mdp_reply;

  while (now < timeout){
    now=gettime_ms();

    if (now >= next_send){
      /* Send a unicast packet to this node, asking for any did */
      lookup_send_request(mdp_sockfd, &srcsid, port, &dstsid, "");
      next_send+=125;
      continue;
    }

    time_ms_t poll_timeout = (next_send>timeout?timeout:next_send) - now;
    if (overlay_mdp_client_poll(mdp_sockfd, poll_timeout)<=0)
      continue;

    int ttl=-1;
    if (overlay_mdp_recv(mdp_sockfd, &mdp_reply, port, &ttl))
      continue;

    if ((mdp_reply.packetTypeAndFlags&MDP_TYPE_MASK)==MDP_ERROR){
      // TODO log error?
      continue;
    }

    if (mdp_reply.packetTypeAndFlags!=MDP_TX) {
      WHYF("MDP returned an unexpected message (type=0x%x)",
	   mdp_reply.packetTypeAndFlags);

      if (mdp_reply.packetTypeAndFlags==MDP_ERROR)
	WHYF("MDP message is return/error: %d:%s",
	     mdp_reply.error.error,mdp_reply.error.message);
      continue;
    }

    // we might receive a late response from an ealier request on the same socket, ignore it
    if (cmp_sid_t(&mdp_reply.out.src.sid, &dstsid) != 0) {
      WHYF("Unexpected result from SID %s", alloca_tohex_sid_t(mdp_reply.out.src.sid));
      continue;
    }

    {
      char sidhex[SID_STRLEN + 1];
      char did[DID_MAXSIZE + 1];
      char name[64];
      char uri[512];
      if ( !parseDnaReply((char *)mdp_reply.out.payload, mdp_reply.out.payload_length, sidhex, did, name, uri, NULL)
	  || !str_is_subscriber_id(sidhex)
	  || !str_is_did(did)
	  || !str_is_uri(uri)
	  ) {
	WHYF("Received malformed DNA reply: %s",
	     alloca_toprint(160, (const char *)mdp_reply.out.payload, mdp_reply.out.payload_length));
	continue;
      }

      /* Got a good DNA reply, copy it into place and stop polling */
      cli_field_name(context, "sid", ":");
      cli_put_string(context, sidhex, "\n");
      cli_field_name(context, "did", ":");
      cli_put_string(context, did, "\n");
      cli_field_name(context, "name", ":");
      cli_put_string(context, name, "\n");
      overlay_mdp_client_close(mdp_sockfd);
      return 0;
    }
  }
  overlay_mdp_client_close(mdp_sockfd);
  return 1;
}
