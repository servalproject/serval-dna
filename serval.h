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

/*
 * INSTANCE_PATH can be set via the ./configure option --enable-instance-path=<path>
 */
#ifdef INSTANCE_PATH
#define DEFAULT_INSTANCE_PATH INSTANCE_PATH
#else
#ifdef ANDROID
#define DEFAULT_INSTANCE_PATH "/data/data/org.servalproject/var/serval-node"
#else
#define DEFAULT_INSTANCE_PATH "/var/serval-node"
#endif
#endif

/* Handy statement for forming a path to an instance file in a char buffer whose declaration
 * is in scope (so that sizeof(buf) will work).  Evaluates to true if the pathname fitted into
 * the provided buffer, false (0) otherwise (after logging an error).
 */
#define FORM_SERVAL_INSTANCE_PATH(buf, path) (formf_serval_instance_path(__WHENCE__, buf, sizeof(buf), "%s", (path)))

const char *serval_instancepath();
int create_serval_instance_dir();
int formf_serval_instance_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int vformf_serval_instance_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, va_list);
void serval_setinstancepath(const char *instancepath);

#define SERVER_CONFIG_RELOAD_INTERVAL_MS	1000

struct cli_parsed;

extern int servalShutdown;

extern char *gatewayspec;

int rhizome_enabled();
int rhizome_http_server_running();
const char *rhizome_datastore_path();

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

/* Make sure we have space to put bytes of the packet as we go along */
#define CHECK_PACKET_LEN(B) {if (((*packet_len)+(B))>=packet_maxlen) { return WHY("Packet composition ran out of space."); } }

extern int sock;

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

#define INTERFACE_STATE_FREE 0
#define INTERFACE_STATE_UP 1
#define INTERFACE_STATE_DOWN 2
#define INTERFACE_STATE_DETECTING 3

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

struct overlay_interface;

// where should packets be sent to?
struct network_destination {
  int _ref_count;
  
  // which interface are we actually sending packets out of
  struct overlay_interface *interface;
  
  // The IPv4 destination address, this may be the interface broadcast address.
  struct sockaddr_in address;
  
  // should outgoing packets be marked as unicast?
  char unicast;
  
  char packet_version;
  
  // should we aggregate packets, or send one at a time
  char encapsulation;

  // time last packet was sent
  time_ms_t last_tx;
  
  int min_rtt;
  int max_rtt;
  int resend_delay;

  // sequence number of last packet sent to this destination.
  // Used to allow NACKs that can request retransmission of recent packets.
  int sequence_number;

  // rate limit for outgoing packets
  struct limit_state transfer_limit;

  /* Number of milli-seconds per tick for this interface, which is basically
   * related to the     the typical TX range divided by the maximum expected
   * speed of nodes in the network.  This means that short-range communications
   * has a higher bandwidth requirement than long-range communications because
   * the tick interval has to be shorter to still allow fast-convergence time
   * to allow for mobility.
   *
   * For wifi (nominal range 100m) it is usually 500ms.
   * For ~100K ISM915MHz (nominal range 1000m) it will probably be about 5000ms.
   * For ~10K ISM915MHz (nominal range ~3000m) it will probably be about 15000ms.
   *
   * These figures will be refined over time, and we will allow people to set
   * them per-interface.
   */
  unsigned tick_ms;

  // Number of milliseconds of no packets until we assume the link is dead.
  unsigned reachable_timeout_ms;
};

struct network_destination * new_destination(struct overlay_interface *interface, char encapsulation);
struct network_destination * create_unicast_destination(struct sockaddr_in addr, struct overlay_interface *interface);
struct network_destination * add_destination_ref(struct network_destination *ref);
void release_destination_ref(struct network_destination *ref);
int set_destination_ref(struct network_destination **ptr, struct network_destination *ref);

typedef struct overlay_interface {
  struct sched_ent alarm;
  
  char name[256];
  
  int recv_offset; /* file offset */
  
  int recv_count;
  int tx_count;
  
  struct radio_link_state *radio_link_state;

  // copy of ifconfig flags
  uint16_t drop_packets;
  char drop_broadcasts;
  char drop_unicasts;
  int port;
  int type;
  int socket_type;
  char send_broadcasts;
  char prefer_unicast;
  /* Not necessarily the real MTU, but the largest frame size we are willing to TX.
   For radio links the actual maximum and the maximum that is likely to be delivered reliably are
   potentially two quite different values. */
  int mtu;
  // can we use this interface for routes to addresses in other subnets?
  int default_route;
  // should we log more debug info on this interace? eg hex dumps of packets
  char debug;
  char local_echo;

  unsigned int uartbps; // set serial port speed (which might be different from link speed)
  int ctsrts; // enabled hardware flow control if non-zero

  struct network_destination *destination;

  // can we assume that we will only receive packets from one device?
  char point_to_point;
  struct subscriber *other_device;
  
  // the actual address of the interface.
  struct sockaddr_in address;
  struct in_addr netmask;
  
  /* Use one of the INTERFACE_STATE_* constants to indicate the state of this interface. 
     If the interface stops working or disappears, it will be marked as DOWN and the socket closed.
     But if it comes back up again, we should try to reuse this structure, even if the broadcast address has changed.
   */
  int state;
} overlay_interface;

/* Maximum interface count is rather arbitrary.
 Memory consumption is O(n) with respect to this parameter, so let's not make it too big for now.
 */
extern overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
extern int overlay_last_interface_number; // used to remember where a packet came from
extern unsigned int overlay_sequence_number;

int server_pid();
void server_save_argv(int argc, const char *const *argv);
int server(const struct cli_parsed *parsed);
int server_create_stopfile();
int server_remove_stopfile();
int server_check_stopfile();
void serverCleanUp();
int isTransactionInCache(unsigned char *transaction_id);
void insertTransactionInCache(unsigned char *transaction_id);

int overlay_forward_payload(struct overlay_frame *f);
int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    struct socket_address *recvaddr);
int parseMdpPacketHeader(struct decode_context *context, struct overlay_frame *frame, 
			 struct overlay_buffer *buffer, struct subscriber **nexthop);
int parseEnvelopeHeader(struct decode_context *context, struct overlay_interface *interface, 
			struct sockaddr_in *addr, struct overlay_buffer *buffer);
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, 
			   struct overlay_frame *f, struct decode_context *context);

int overlay_frame_process(struct overlay_interface *interface, struct overlay_frame *f);
int overlay_frame_resolve_addresses(struct overlay_frame *f);

time_ms_t overlay_time_until_next_tick();

int overlay_frame_append_payload(struct decode_context *context, int encapsulation,
				 struct overlay_frame *p, struct overlay_buffer *b,
				 char will_retransmit);
int overlay_packet_init_header(int packet_version, int encapsulation, 
			       struct decode_context *context, struct overlay_buffer *buff, 
			       char unicast, char interface, int seq);
int overlay_interface_args(const char *arg);
void overlay_rhizome_advertise(struct sched_ent *alarm);
void rhizome_sync_status_html(struct strbuf *b, struct subscriber *subscriber);
int rhizome_cache_count();
int overlay_add_local_identity(unsigned char *s);

extern unsigned overlay_interface_count;

extern int overlay_local_identity_count;
extern unsigned char *overlay_local_identities[OVERLAY_MAX_LOCAL_IDENTITIES];

int rfs_length(int l);
int rfs_encode(int l,unsigned char *b);
int rfs_decode(unsigned char *b,int *offset);

int overlayServerMode(const struct cli_parsed *parsed);
int overlay_payload_enqueue(struct overlay_frame *p);
int overlay_queue_remaining(int queue);
int overlay_queue_schedule_next(time_ms_t next_allowed_packet);
int overlay_send_tick_packet(struct network_destination *destination);
int overlay_queue_ack(struct subscriber *neighbour, struct network_destination *destination, uint32_t ack_mask, int ack_seq);

int overlay_rhizome_saw_advertisements(struct decode_context *context, struct overlay_frame *f);
int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_saw_voice_traffic();
int overlay_saw_mdp_containing_frame(struct overlay_frame *f);

int serval_packetvisualise(const char *message, const unsigned char *packet, size_t len);
int serval_packetvisualise_xpf(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len);
void logServalPacket(int level, struct __sourceloc __whence, const char *message, const unsigned char *packet, size_t len);
#define DEBUG_packet_visualise(M,P,N) logServalPacket(LOG_LEVEL_DEBUG, __WHENCE__, (M), (P), (N))

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_opendb();

int parseCommandLine(struct cli_context *context, const char *argv0, int argc, const char *const *argv);

int overlay_mdp_get_fds(struct pollfd *fds,int *fdcount,int fdmax);

typedef uint32_t mdp_port_t;
#define PRImdp_port_t "#08" PRIx32

typedef struct sockaddr_mdp {
  sid_t sid;
  mdp_port_t port;
} sockaddr_mdp;

typedef struct overlay_mdp_data_frame {
  sockaddr_mdp src;
  sockaddr_mdp dst;
  uint16_t payload_length;
  int queue;
  int ttl;
  unsigned char payload[MDP_MTU-100];
} overlay_mdp_data_frame;

typedef struct overlay_mdp_error {
  unsigned int error;
  char message[128];
} overlay_mdp_error;

typedef struct overlay_mdp_addrlist {
  int mode;
#define OVERLAY_MDP_ADDRLIST_MAX_SID_COUNT (~(unsigned int)0)
  unsigned int server_sid_count;
  unsigned int first_sid;
  unsigned int last_sid;
  unsigned int frame_sid_count; /* how many of the following 59 slots are populated */
  sid_t sids[MDP_MAX_SID_REQUEST];
} overlay_mdp_addrlist;

typedef struct overlay_mdp_nodeinfo {
  sid_t sid;
  int sid_prefix_length; /* must be long enough to be unique */
  int foundP;
  int localP;
  int neighbourP;
  int score;
  int interface_number;
  time_ms_t time_since_last_observation;
} overlay_mdp_nodeinfo;

typedef struct overlay_mdp_frame {
  uint16_t packetTypeAndFlags;
  union {
    overlay_mdp_data_frame out;
    overlay_mdp_data_frame in;
    sockaddr_mdp bind;
    overlay_mdp_addrlist addrlist;
    overlay_mdp_nodeinfo nodeinfo;
    overlay_mdp_error error;
    /* 2048 is too large (causes EMSGSIZE errors on OSX, but probably fine on
       Linux) */
    char raw[MDP_MTU];
  };
} overlay_mdp_frame;

/* Server-side MDP functions */
int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp);
int overlay_mdp_dispatch(overlay_mdp_frame *mdp, struct socket_address *client);
void overlay_mdp_encode_ports(struct overlay_buffer *plaintext, mdp_port_t dst_port, mdp_port_t src_port);
int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const sid_t *resolved_sidp, const char *uri, const char *did, const char *name);

struct mdp_header;
int mdp_bind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(const struct mdp_header *header, const uint8_t *payload, size_t len));
int mdp_unbind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(const struct mdp_header *header, const uint8_t *payload, size_t len));


struct vomp_call_state;

void set_codec_flag(int codec, unsigned char *flags);
int is_codec_set(int codec, unsigned char *flags);

struct vomp_call_state *vomp_find_call_by_session(unsigned int session_token);
int vomp_mdp_received(overlay_mdp_frame *mdp);
int vomp_parse_dtmf_digit(char c);
int vomp_dial(struct subscriber *local, struct subscriber *remote, const char *local_did, const char *remote_did);
int vomp_pickup(struct vomp_call_state *call);
int vomp_hangup(struct vomp_call_state *call);
int vomp_ringing(struct vomp_call_state *call);
int vomp_received_audio(struct vomp_call_state *call, int audio_codec, int time, int sequence,
			const unsigned char *audio, int audio_length);
void monitor_get_all_supported_codecs(unsigned char *codecs);

int overlay_route_node_info(overlay_mdp_nodeinfo *node_info);
int overlay_interface_register(char *name,
			       struct in_addr addr,
			       struct in_addr mask);
overlay_interface * overlay_interface_get_default();
overlay_interface * overlay_interface_find(struct in_addr addr, int return_default);
overlay_interface * overlay_interface_find_name(const char *name);
int overlay_interface_compare(overlay_interface *one, overlay_interface *two);
int overlay_broadcast_ensemble(struct network_destination *destination, struct overlay_buffer *buffer);
void interface_state_html(struct strbuf *b, struct overlay_interface *interface);

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

int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);

int monitor_setup_sockets();
int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int monitor_announce_peer(const sid_t *sidp);
int monitor_announce_unreachable_peer(const sid_t *sidp);
int monitor_announce_link(int hop_count, struct subscriber *transmitter, struct subscriber *receiver);
int monitor_tell_clients(char *msg, int msglen, int mask);
int monitor_tell_formatted(int mask, char *fmt, ...);
int monitor_client_interested(int mask);
extern int monitor_socket_count;


typedef struct monitor_audio {
  char name[128];
  int (*start)();
  int (*stop)();
  int (*poll_fds)(struct pollfd *,int);
  int (*read)(unsigned char *,int);
  int (*write)(unsigned char *,int);
} monitor_audio;
extern monitor_audio *audev;

monitor_audio *audio_msm_g1_detect();
monitor_audio *audio_alsa_detect();
monitor_audio *audio_reflector_detect();
int detectAudioDevice();
int getAudioPlayFd();
int getAudioRecordFd();
int getAudioBytes(unsigned char *buffer,
		  int offset,
		  int bufferSize);
int encodeAndDispatchRecordedAudio(int fd,int callSessionToken,
				   int recordCodec,
				   unsigned char *sampleData,
				   int sampleBytes);
int scrapeProcNetRoute();
int lsif();
int doifaddrs();
int bufferAudioForPlayback(int codec, time_ms_t start_time, time_ms_t end_time,
			   unsigned char *data,int dataLen);
int startAudio();
int stopAudio();

#define SERVER_UNKNOWN 1
#define SERVER_NOTRESPONDING 2
#define SERVER_NOTRUNNING 3
#define SERVER_RUNNING 4
int server_probe(int *pid);

int dna_helper_start();
int dna_helper_shutdown();
int dna_helper_enqueue(overlay_mdp_frame *mdp, const char *did, const sid_t *requestorSidp);
int dna_return_resolution(overlay_mdp_frame *mdp, unsigned char *fromSid,
			  const char *did,const char *name,const char *uri);
int parseDnaReply(const char *buf, size_t len, char *token, char *did, char *name, char *uri, const char **bufp);
extern int sigPipeFlag;
extern int sigIoFlag;
void sigPipeHandler(int signal);
void sigIoHandler(int signal);

int overlay_mdp_setup_sockets();

void overlay_interface_discover(struct sched_ent *alarm);
void overlay_packetradio_poll(struct sched_ent *alarm);
int overlay_packetradio_setup_port(overlay_interface *interface);
int overlay_packetradio_tx_packet(struct overlay_frame *frame);
void overlay_dummy_poll(struct sched_ent *alarm);
void server_config_reload(struct sched_ent *alarm);
void server_shutdown_check(struct sched_ent *alarm);
int overlay_mdp_try_internal_services(struct overlay_frame *frame, overlay_mdp_frame *mdp);
int overlay_send_probe(struct subscriber *peer, struct network_destination *destination, int queue);
int overlay_send_stun_request(struct subscriber *server, struct subscriber *request);
void fd_periodicstats(struct sched_ent *alarm);
void rhizome_check_connections(struct sched_ent *alarm);

int overlay_tick_interface(int i, time_ms_t now);
int overlay_queue_init();

void monitor_client_poll(struct sched_ent *alarm);
void monitor_poll(struct sched_ent *alarm);
void rhizome_fetch_poll(struct sched_ent *alarm);
void rhizome_server_poll(struct sched_ent *alarm);

int overlay_mdp_service_stun_req(overlay_mdp_frame *mdp);
int overlay_mdp_service_stun(overlay_mdp_frame *mdp);
int overlay_mdp_service_probe(struct overlay_frame *frame, overlay_mdp_frame *mdp);

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
extern int64_t bundles_available;
extern char crash_handler_clue[1024];


int link_received_duplicate(struct subscriber *subscriber, int previous_seq);
int link_received_packet(struct decode_context *context, int sender_seq, char unicast);
int link_receive(struct overlay_frame *frame, overlay_mdp_frame *mdp);
void link_explained(struct subscriber *subscriber);
void link_interface_down(struct overlay_interface *interface);
int link_state_announce_links();
int link_state_legacy_ack(struct overlay_frame *frame, time_ms_t now);
int link_state_ack_soon(struct subscriber *sender);
int link_state_should_forward_broadcast(struct subscriber *transmitter);
int link_unicast_ack(struct subscriber *subscriber, struct overlay_interface *interface, struct sockaddr_in addr);
int link_add_destinations(struct overlay_frame *frame);
void link_neighbour_short_status_html(struct strbuf *b, const char *link_prefix);
void link_neighbour_status_html(struct strbuf *b, struct subscriber *neighbour);
int link_stop_routing(struct subscriber *subscriber);

int generate_nonce(unsigned char *nonce,int bytes);

#endif // __SERVAL_DNA__SERVAL_H
