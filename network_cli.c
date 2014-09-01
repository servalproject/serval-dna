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

DEFINE_CMD(app_mdp_ping, 0,
  "Attempts to ping specified node via Mesh Datagram Protocol (MDP).",
  "mdp","ping","[--interval=<ms>]","[--timeout=<seconds>]","[--wait-for-duplicates]",
  "<SID>|broadcast","[<count>]");
static int app_mdp_ping(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
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
	if (config.debug.mdprequests)
	  DEBUGF("ping seq=%lu", (unsigned long)(sequence_number - firstSeq) + 1);
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
	if (config.debug.mdprequests)
	  DEBUGF("bound to %s:%d", alloca_tohex_sid_t(mdp_header.local.sid), mdp_header.local.port);
	continue;
      }
      if ((size_t)len < sizeof(recv_payload)){
	if (config.debug.mdprequests)
	  DEBUGF("ignoring short pong");
	continue;
      }
      uint32_t rxseq = read_uint32(&recv_payload[0]);
      time_ms_t txtime = read_uint64(&recv_payload[4]);
      int hop_count = 64 - mdp_recv_header.ttl;
      now = gettime_ms();
      time_ms_t delay = now - txtime;

      struct packet_stat *stat = &stats[(unsigned long)(rxseq - firstSeq) % NELS(stats)];
      if (stat->sequence != rxseq || stat->tx_time != txtime) {
	if (config.debug.mdprequests)
	  DEBUGF("ignoring spurious pong");
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
   "mdp","trace","<SID>");
static int app_trace(const struct cli_parsed *parsed, struct cli_context *context)
{
  int mdp_sockfd;
  const char *sidhex;
  if (cli_arg(parsed, "SID", &sidhex, str_is_subscriber_id, NULL) == -1)
    return -1;
  
  sid_t srcsid;
  sid_t dstsid;
  if (str_to_sid_t(&dstsid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

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
  
  overlay_mdp_frame mdp;
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
  int ret;
  if (ob_overrun(b))
    ret = WHY("overlay buffer overrun");
  else {
    mdp.out.payload_length = ob_position(b);
    cli_printf(context, "Tracing the network path from %s to %s", 
	  alloca_tohex_sid_t(srcsid), alloca_tohex_sid_t(dstsid));
    cli_delim(context, "\n");
    cli_flush(context);
    ret = overlay_mdp_send(mdp_sockfd, &mdp, MDP_AWAITREPLY, 5000);
    if (ret)
      WHYF("overlay_mdp_send returned %d", ret);
  }
  ob_free(b);
  if (ret == 0) {
    int offset=0;
    {
      // skip the first two sid's
      int len = mdp.out.payload[offset++];
      offset+=len;
      len = mdp.out.payload[offset++];
      offset+=len;
    }
    int i=0;
    while(offset<mdp.out.payload_length){
      int len = mdp.out.payload[offset++];
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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);

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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
    
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
      struct overlay_route_record *p=(struct overlay_route_record *)&rx.out.payload[ofs];
      ofs+=sizeof(struct overlay_route_record);
      
      if (p->reachable==REACHABLE_NONE)
	continue;

      cli_put_string(context, alloca_tohex_sid_t(p->sid), ":");
      char flags[32];
      strbuf b = strbuf_local(flags, sizeof flags);
      
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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
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
