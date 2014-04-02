/* 
Serval DNA header file
Copyright (C) 2010-2012 Paul Gardner-Stephen 
Copyright (C) 2012-2013 Serval Project Inc.

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
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef __SERVAL_DNA__SERVAL_H
#define __SERVAL_DNA__SERVAL_H

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#ifdef WIN32
#   include "win32/win32.h"
#else
#   include <unistd.h>
#   ifdef HAVE_SYS_SOCKET_H
#     include <sys/socket.h>
#   endif
#   ifdef HAVE_NET_ROUTE_H
#     include <net/route.h>
#   endif
#   ifdef HAVE_LINUX_IF_H
#     include <linux/if.h>
#   else
#     ifdef HAVE_NET_IF_H
#       include <net/if.h>
#     endif
#   endif
#   ifdef HAVE_NETINET_IN_H
#     include <netinet/in.h>
#   endif
#   ifdef HAVE_LINUX_NETLINK_H
#     include <linux/netlink.h>
#   endif
#   ifdef HAVE_LINUX_RTNETLINK_H
#     include <linux/rtnetlink.h>
#   endif
#   ifdef HAVE_IFADDRS_H
#     include <ifaddrs.h>
#   endif
#   ifdef HAVE_SYS_SOCKIO_H
#     include <sys/sockio.h>
#   endif
#   ifdef HAVE_SYS_UCRED_H
#     include <sys/ucred.h>
#   endif
#endif //!WIN32

#if !defined(FORASTERISK) && !defined(s_addr)
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#else
typedef uint32_t in_addr_t;
struct in_addr {
   in_addr_t s_addr;
};
#endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifndef WIN32
#include <sys/ioctl.h>
#include <sys/un.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>

#include "instance.h"
#include "fdqueue.h"
#include "cli.h"
#include "constants.h"
#include "mem.h"
#include "xprintf.h"
#include "log.h"
#include "net.h"
#include "os.h"

/* UDP Port numbers for various Serval services.
 The overlay mesh works over DNA */
#define PORT_DNA 4110

#define BATCH 1
#define NONBATCH 0

#define REQ_SERIAL 0
#define REQ_PARALLEL -1
#define REQ_FIRSTREPLY -2
#define REQ_REPLY -101


#define SET_NOREPLACE 1
#define SET_REPLACE 2
#define SET_NOCREATE 3
#define SET_FRAGMENT 0x80

#define WITHDATA 1
#define WITHOUTDATA 0

/* Limit packet payloads to minimise packet loss of big packets in mesh networks */
#define MAX_DATA_BYTES 256


extern const char version_servald[];
extern const char copyright_servald[];

/* Fundamental types.
 */

typedef struct sid_binary {
    unsigned char binary[SID_SIZE];
} sid_t;

#define SID_ANY         ((sid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})
#define SID_BROADCAST   ((sid_t){{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}})

// is the SID entirely 0xFF?
#define is_sid_t_broadcast(SID) is_all_matching((SID).binary, sizeof (*(sid_t*)0).binary, 0xFF)

// is the SID entirely 0x00?
#define is_sid_t_any(SID) is_all_matching((SID).binary, sizeof (*(sid_t*)0).binary, 0)

#define alloca_tohex_sid_t(sid)         alloca_tohex((sid).binary, sizeof (*(sid_t*)0).binary)
#define alloca_tohex_sid_t_trunc(sid,strlen)  tohex((char *)alloca((strlen)+1), (strlen), (sid).binary)

int cmp_sid_t(const sid_t *a, const sid_t *b);
int str_to_sid_t(sid_t *sid, const char *hex);
int strn_to_sid_t(sid_t *sid, const char *hex, const char **endp);

#define alloca_tohex_sas(sas)           alloca_tohex((sas), SAS_SIZE)

#define SERVER_CONFIG_RELOAD_INTERVAL_MS	1000

struct cli_parsed;

extern int servalShutdown;

extern char *gatewayspec;

int rhizome_enabled();
int rhizome_http_server_running();

#define MAX_PEERS 1024
extern int peer_count;
extern struct in_addr peers[MAX_PEERS];

extern char *outputtemplate;
extern char *instrumentation_file;
extern char *batman_socket;
extern char *batman_peerfile;

struct subscriber;
struct decode_context;
struct socket_address;
struct overlay_interface;
struct network_destination;
struct internal_mdp_header;

/* Make sure we have space to put bytes of the packet as we go along */
#define CHECK_PACKET_LEN(B) {if (((*packet_len)+(B))>=packet_maxlen) { return WHY("Packet composition ran out of space."); } }

struct limit_state{
  // length of time for a burst
  time_ms_t burst_length;
  // how many in a burst
  int burst_size;
  
  // how many have we sent in this burst so far
  int sent;
  // when can we allow another burst
  time_ms_t next_interval;
};

struct overlay_buffer;
struct overlay_frame;
struct broadcast;

#define STRUCT_SCHED_ENT_UNUSED {.poll={.fd=-1}, ._poll_index=-1,}

extern int overlayMode;

// Specify the size of the receive buffer.
// This effectively sets the MRU for packet radio interfaces
// where we have to buffer packets on the receive side
#define OVERLAY_INTERFACE_RX_BUFFER_SIZE 2048
// TX buffer must handle FEC encoded and encapsulated data, so needs to be
// larger.
#define OVERLAY_INTERFACE_TX_BUFFER_SIZE (2+2048*2)
// buffer size for reading RFD900 RSSI reports
// (minimum length is ~87 bytes, and includes 13 numeric fields
// each of which may presumably end up being ~10 bytes, so 256 bytes
// should be a safe size).
#define RSSI_TEXT_SIZE 256

struct slip_decode_state{
#define SLIP_FORMAT_SLIP 0
#define SLIP_FORMAT_UPPER7 1
#define SLIP_FORMAT_MAVLINK 2
  int encapsulator;
  int state;
  unsigned char *src;
  unsigned src_size;
  char rssi_text[RSSI_TEXT_SIZE];
  unsigned rssi_len;
  unsigned packet_length;
  unsigned char dst[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
  uint32_t crc;
  unsigned src_offset;
  unsigned dst_offset;
};


int server_pid();
const char *_server_pidfile_path(struct __sourceloc);
#define server_pidfile_path() (_server_pidfile_path(__WHENCE__))
void server_save_argv(int argc, const char *const *argv);
int server(const struct cli_parsed *parsed);
int server_write_pid();
int server_write_proc_state(const char *path, const char *fmt, ...);
int server_get_proc_state(const char *path, char *buff, size_t buff_len);
int server_create_stopfile();
int server_remove_stopfile();
int server_check_stopfile();
void overlay_mdp_clean_socket_files();
void serverCleanUp();
int isTransactionInCache(unsigned char *transaction_id);
void insertTransactionInCache(unsigned char *transaction_id);

int overlay_forward_payload(struct overlay_frame *f);
int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    struct socket_address *recvaddr);
int parseMdpPacketHeader(struct decode_context *context, struct overlay_frame *frame, 
			 struct overlay_buffer *buffer, struct subscriber **nexthop);
int parseEnvelopeHeader(struct decode_context *context, struct overlay_interface *interface, 
			struct socket_address *addr, struct overlay_buffer *buffer);
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, 
			   struct overlay_frame *f, struct decode_context *context);

int overlay_frame_process(struct overlay_interface *interface, struct overlay_frame *f);

int overlay_frame_append_payload(struct decode_context *context, int encapsulation,
				 struct overlay_frame *p, struct overlay_buffer *b,
				 char will_retransmit);
int overlay_packet_init_header(int packet_version, int encapsulation, 
			       struct decode_context *context, struct overlay_buffer *buff, 
			       char unicast, char interface, int seq);
void overlay_rhizome_advertise(struct sched_ent *alarm);
void rhizome_sync_status_html(struct strbuf *b, struct subscriber *subscriber);
int rhizome_cache_count();

int overlayServerMode(const struct cli_parsed *parsed);
int overlay_payload_enqueue(struct overlay_frame *p);
int overlay_queue_remaining(int queue);
int overlay_queue_schedule_next(time_ms_t next_allowed_packet);
int overlay_send_tick_packet(struct network_destination *destination);
int overlay_queue_ack(struct subscriber *neighbour, struct network_destination *destination, uint32_t ack_mask, int ack_seq);

int overlay_rhizome_saw_advertisements(struct decode_context *context, struct overlay_frame *f);
int rhizome_saw_voice_traffic();
int overlay_saw_mdp_containing_frame(struct overlay_frame *f);

int serval_packetvisualise(const char *message, const unsigned char *packet, size_t len);
int serval_packetvisualise_xpf(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len);
void logServalPacket(int level, struct __sourceloc __whence, const char *message, const unsigned char *packet, size_t len);
#define DEBUG_packet_visualise(M,P,N) logServalPacket(LOG_LEVEL_DEBUG, __WHENCE__, (M), (P), (N))

int rhizome_opendb();

int parseCommandLine(struct cli_context *context, const char *argv0, int argc, const char *const *argv);

typedef uint32_t mdp_port_t;
#define PRImdp_port_t "#08" PRIx32


/* Server-side MDP functions */
void mdp_init_response(const struct internal_mdp_header *in, struct internal_mdp_header *out);
void overlay_mdp_encode_ports(struct overlay_buffer *plaintext, mdp_port_t dst_port, mdp_port_t src_port);
int overlay_mdp_dnalookup_reply(struct subscriber *dest, mdp_port_t dest_port, 
    struct subscriber *resolved_sid, const char *uri, const char *did, const char *name);
int overlay_send_frame(struct internal_mdp_header *header, struct overlay_buffer *payload);

int mdp_bind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(struct internal_mdp_header *header, struct overlay_buffer *payload));
int mdp_unbind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(struct internal_mdp_header *header, struct overlay_buffer *payload));

int allow_incoming_packet(struct internal_mdp_header *header);
void load_mdp_packet_rules(const char *filename);

struct vomp_call_state;

void set_codec_flag(int codec, unsigned char *flags);

struct vomp_call_state *vomp_find_call_by_session(unsigned int session_token);
int vomp_mdp_received(struct internal_mdp_header *header, struct overlay_buffer *payload);
int vomp_parse_dtmf_digit(char c);
int vomp_dial(struct subscriber *local, struct subscriber *remote, const char *local_did, const char *remote_did);
int vomp_pickup(struct vomp_call_state *call);
int vomp_hangup(struct vomp_call_state *call);
int vomp_ringing(struct vomp_call_state *call);
int vomp_received_audio(struct vomp_call_state *call, int audio_codec, int time, int sequence,
			const unsigned char *audio, int audio_length);
void monitor_get_all_supported_codecs(unsigned char *codecs);

int directory_registration();
int directory_service_init();

int app_nonce_test(const struct cli_parsed *parsed, struct cli_context *context);
int app_rhizome_direct_sync(const struct cli_parsed *parsed, struct cli_context *context);
int app_monitor_cli(const struct cli_parsed *parsed, struct cli_context *context);
int app_vomp_console(const struct cli_parsed *parsed, struct cli_context *context);
int app_meshms_conversations(const struct cli_parsed *parsed, struct cli_context *context);
int app_meshms_send_message(const struct cli_parsed *parsed, struct cli_context *context);
int app_meshms_list_messages(const struct cli_parsed *parsed, struct cli_context *context);
int app_meshms_mark_read(const struct cli_parsed *parsed, struct cli_context *context);
int app_msp_connection(const struct cli_parsed *parsed, struct cli_context *context);

int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);

int monitor_setup_sockets();
int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int monitor_announce_peer(const sid_t *sidp);
int monitor_announce_unreachable_peer(const sid_t *sidp);
int monitor_announce_link(int hop_count, struct subscriber *transmitter, struct subscriber *receiver);
int monitor_tell_clients(char *msg, int msglen, int mask);
int monitor_tell_formatted(int mask, char *fmt, ...);
int monitor_client_interested(int mask);

int scrapeProcNetRoute();
int lsif();
int doifaddrs();

#define SERVER_UNKNOWN 1
#define SERVER_NOTRESPONDING 2
#define SERVER_NOTRUNNING 3
#define SERVER_RUNNING 4
int server_probe(int *pid);

int dna_helper_start();
int dna_helper_shutdown();
int dna_helper_enqueue(struct subscriber *source, mdp_port_t source_port, const char *did);
int parseDnaReply(const char *buf, size_t len, char *token, char *did, char *name, char *uri, const char **bufp);
extern int sigPipeFlag;
extern int sigIoFlag;
extern int sigIntFlag;
void sigPipeHandler(int signal);
void sigIoHandler(int signal);
void sigIntHandler(int signal);

int overlay_mdp_setup_sockets();

int overlay_packetradio_setup_port(struct overlay_interface *interface);
void server_config_reload(struct sched_ent *alarm);
void server_shutdown_check(struct sched_ent *alarm);
void overlay_mdp_bind_internal_services();
int overlay_send_probe(struct subscriber *peer, struct network_destination *destination, int queue);
int overlay_send_stun_request(struct subscriber *server, struct subscriber *request);
void fd_periodicstats(struct sched_ent *alarm);
void rhizome_check_connections(struct sched_ent *alarm);

int overlay_queue_init();

void monitor_client_poll(struct sched_ent *alarm);
void monitor_poll(struct sched_ent *alarm);
void rhizome_fetch_poll(struct sched_ent *alarm);
void rhizome_server_poll(struct sched_ent *alarm);

int overlay_mdp_service_stun_req(struct internal_mdp_header *header, struct overlay_buffer *payload);
int overlay_mdp_service_stun(struct internal_mdp_header *header, struct overlay_buffer *payload);
int overlay_mdp_service_probe(struct internal_mdp_header *header, struct overlay_buffer *payload);

time_ms_t limit_next_allowed(struct limit_state *state);
int limit_is_allowed(struct limit_state *state);
int limit_init(struct limit_state *state, int rate_micro_seconds);

int olsr_init_socket(void);
int olsr_send(struct overlay_frame *frame);

int pack_uint(unsigned char *buffer, uint64_t v);
int measure_packed_uint(uint64_t v);
int unpack_uint(unsigned char *buffer, int buff_size, uint64_t *v);

int slip_encode(int format,
		const unsigned char *src, int src_bytes, unsigned char *dst, int dst_len);
int slip_decode(struct slip_decode_state *state);
int upper7_decode(struct slip_decode_state *state,unsigned char byte);
uint32_t Crc32_ComputeBuf( uint32_t inCrc32, const void *buf,
			  size_t bufLen );
void rhizome_fetch_log_short_status();
extern char crash_handler_clue[1024];


int link_received_duplicate(struct subscriber *subscriber, int previous_seq);
int link_received_packet(struct decode_context *context, int sender_seq, char unicast);
int link_receive(struct internal_mdp_header *header, struct overlay_buffer *payload);
void link_explained(struct subscriber *subscriber);
void link_interface_down(struct overlay_interface *interface);
int link_state_announce_links();
int link_state_legacy_ack(struct overlay_frame *frame, time_ms_t now);
int link_state_ack_soon(struct subscriber *sender);
int link_state_should_forward_broadcast(struct subscriber *transmitter);
int link_unicast_ack(struct subscriber *subscriber, struct overlay_interface *interface, struct socket_address *addr);
int link_add_destinations(struct overlay_frame *frame);
void link_neighbour_short_status_html(struct strbuf *b, const char *link_prefix);
void link_neighbour_status_html(struct strbuf *b, struct subscriber *neighbour);
int link_stop_routing(struct subscriber *subscriber);

int generate_nonce(unsigned char *nonce,int bytes);

#endif // __SERVAL_DNA__SERVAL_H
