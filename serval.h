/* 
Serval Daemon
Copyright (C) 2010-2012 Paul Gardner-Stephen 
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

#ifndef __SERVALD_SERVALD_H
#define __SERVALD_SERVALD_H

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
#include "win32/win32.h"
#else
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NET_ROUTE_H
     #include <net/route.h>
#endif
#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
#else
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_NETLINK_H
#include <linux/netlink.h>
#endif
#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#endif

#if !defined(FORASTERISK) && !defined(s_addr)
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#else
typedef unsigned int in_addr_t;
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
#ifdef HAVE_POLL_H
#include <poll.h>
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
#include <ctype.h>
#include <sys/stat.h>

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
#define FORM_SERVAL_INSTANCE_PATH(buf, path) (form_serval_instance_path(buf, sizeof(buf), (path)))

const char *serval_instancepath();
int create_serval_instance_dir();
int form_serval_instance_path(char *buf, size_t bufsiz, const char *path);
void serval_setinstancepath(const char *instancepath);

#define SERVER_CONFIG_RELOAD_INTERVAL_MS	1000

struct cli_parsed;

extern int servalShutdown;

extern char *gatewayspec;

int rhizome_enabled();
int rhizome_http_server_running();
const char *rhizome_datastore_path();

extern struct in_addr client_addr;
extern int client_port;

#define MAX_PEERS 1024
extern int peer_count;
extern struct in_addr peers[MAX_PEERS];

extern char *outputtemplate;
extern char *instrumentation_file;
extern char *batman_socket;
extern char *batman_peerfile;


struct subscriber;
struct decode_context;

typedef struct keypair {
  int type;
  unsigned char *private_key;
  size_t private_key_len;
  unsigned char *public_key;
  size_t public_key_len;
} keypair;

/* Contains just the list of private:public key pairs and types,
   the pin used to extract them, and the slot in the keyring file
   (so that it can be replaced/rewritten as required). */
#define PKR_MAX_KEYPAIRS 64
#define PKR_SALT_BYTES 32
#define PKR_MAC_BYTES 64
typedef struct keyring_identity {
  char *PKRPin;
  struct subscriber *subscriber;
  unsigned int slot;
  unsigned int keypair_count;
  keypair *keypairs[PKR_MAX_KEYPAIRS];
} keyring_identity;

/* 64K identities, can easily be increased should the need arise,
   but keep it low-ish for now so that the 64K pointers don't eat too
   much ram on a small device.  Should probably think about having
   small and large device settings for some of these things */
#define KEYRING_MAX_IDENTITIES 65536
typedef struct keyring_context {
  char *KeyRingPin;
  unsigned char *KeyRingSalt;
  int KeyRingSaltLen;
  unsigned int identity_count;
  keyring_identity *identities[KEYRING_MAX_IDENTITIES];
} keyring_context;

#define KEYRING_PAGE_SIZE 4096LL
#define KEYRING_BAM_BYTES 2048LL
#define KEYRING_BAM_BITS (KEYRING_BAM_BYTES<<3)
#define KEYRING_SLAB_SIZE (KEYRING_PAGE_SIZE*KEYRING_BAM_BITS)
typedef struct keyring_bam {
  off_t file_offset;
  unsigned char bitmap[KEYRING_BAM_BYTES];
  struct keyring_bam *next;
} keyring_bam;

#define KEYRING_MAX_CONTEXTS 256
typedef struct keyring_file {
  int context_count;
  keyring_bam *bam;
  keyring_context *contexts[KEYRING_MAX_CONTEXTS];
  FILE *file;
  off_t file_size;
} keyring_file;

void keyring_free(keyring_file *k);
void keyring_free_context(keyring_context *c);
void keyring_free_identity(keyring_identity *id);
#define KEYTYPE_CRYPTOBOX 0x01 // must be lowest
#define KEYTYPE_CRYPTOSIGN 0x02
#define KEYTYPE_RHIZOME 0x03
/* DIDs aren't really keys, but the keyring is a real handy place to keep them,
   and keep them private if people so desire */
#define KEYTYPE_DID 0x04

/* handle to keyring file for use in running instance */
extern keyring_file *keyring;

/* Public calls to keyring management */
keyring_file *keyring_open(const char *path, int writeable);
keyring_file *keyring_open_instance();
keyring_file *keyring_open_instance_cli(const struct cli_parsed *parsed);
int keyring_enter_pin(keyring_file *k, const char *pin);
int keyring_set_did(keyring_identity *id, const char *did, const char *name);
int keyring_sanitise_position(const keyring_file *k,int *cn,int *in,int *kp);
int keyring_next_keytype(const keyring_file *k, int *cn, int *in, int *kp, int keytype);
int keyring_next_identity(const keyring_file *k,int *cn,int *in,int *kp);
int keyring_identity_find_keytype(const keyring_file *k, int cn, int in, int keytype);
int keyring_find_did(const keyring_file *k,int *cn,int *in,int *kp,char *did);
int keyring_find_sid(const keyring_file *k,int *cn,int *in,int *kp, const unsigned char *sid);
unsigned char *keyring_find_sas_private(keyring_file *k,unsigned char *sid,
					unsigned char **sas_public);
int keyring_send_sas_request(struct subscriber *subscriber);

int keyring_commit(keyring_file *k);
keyring_identity *keyring_create_identity(keyring_file *k,keyring_context *c, const char *pin);
int keyring_seed(keyring_file *k);
void keyring_identity_extract(const keyring_identity *id, const unsigned char **sidp, const char **didp, const char **namep);
int keyring_load(keyring_file *k, int cn, unsigned pinc, const char **pinv, FILE *input);
int keyring_dump(keyring_file *k, XPRINTF xpf, int include_secret);

/* Make sure we have space to put bytes of the packet as we go along */
#define CHECK_PACKET_LEN(B) {if (((*packet_len)+(B))>=packet_maxlen) { return WHY("Packet composition ran out of space."); } }

extern int sock;

struct profile_total {
  struct profile_total *_next;
  int _initialised;
  const char *name;
  time_ms_t max_time;
  time_ms_t total_time;
  time_ms_t child_time;
  int calls;
};

struct call_stats{
  time_ms_t enter_time;
  time_ms_t child_time;
  struct profile_total *totals;
  struct call_stats *prev;
};

struct sched_ent;

typedef void (*ALARM_FUNCP) (struct sched_ent *alarm);

struct sched_ent{
  struct sched_ent *_next;
  struct sched_ent *_prev;
  
  ALARM_FUNCP function;
  void *context;
  struct pollfd poll;
  // when we should first consider the alarm
  time_ms_t alarm;
  // the order we will prioritise the alarm
  time_ms_t deadline;
  struct profile_total *stats;
  int _poll_index;
};

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

#define STRUCT_SCHED_ENT_UNUSED {.poll.fd=-1, ._poll_index=-1,}

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
  int src_size;
  char rssi_text[RSSI_TEXT_SIZE];
  int rssi_len;
  int packet_length;
  unsigned char dst[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
  uint32_t crc;
  int src_offset;
  int dst_offset;

  uint8_t mavlink_payload_length;
  uint8_t mavlink_payload_offset;
  uint8_t mavlink_payload[256];
  uint8_t mavlink_sequence;
  uint8_t mavlink_sysid;
  uint8_t mavlink_componentid;
  uint8_t mavlink_msgid;
  uint32_t mavlink_rxcrc;
  uint32_t mavlink_crc;
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

  /* Number of milli-seconds per tick for this interface, which is basically related to the     
   the typical TX range divided by the maximum expected speed of nodes in the network.
   This means that short-range communications has a higher bandwidth requirement than
   long-range communications because the tick interval has to be shorter to still allow
   fast-convergence time to allow for mobility.
   
   For wifi (nominal range 100m) it is usually 500ms.
   For ~100K ISM915MHz (nominal range 1000m) it will probably be about 5000ms.
   For ~10K ISM915MHz (nominal range ~3000m) it will probably be about 15000ms.
   These figures will be refined over time, and we will allow people to set them per-interface.
   */
  unsigned tick_ms; /* milliseconds per tick */
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
  
  // stream socket tx state;
  struct overlay_buffer *tx_packet;
  unsigned char txbuffer[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
  int tx_bytes_pending;
  // Throttle TX rate if required (stream interfaces only for now)
  uint32_t throttle_bytes_per_second;
  uint32_t throttle_burst_write_size;
  uint64_t next_tx_allowed;
  
  
  struct slip_decode_state slip_decode_state;

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

typedef struct sid_binary {
    unsigned char binary[SID_SIZE];
} sid_t;

#define SID_ANY         ((sid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})
#define SID_BROADCAST   ((sid_t){{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}})

// is the SID entirely 0xFF?
#define is_sid_broadcast(SID) is_all_matching(SID, SID_SIZE, 0xFF)

// is the SID entirely 0x00?
#define is_sid_any(SID) is_all_matching(SID, SID_SIZE, 0)

#define alloca_tohex_sid_t(sid)         alloca_tohex((sid).binary, sizeof (*(sid_t*)0).binary)

int str_to_sid_t(sid_t *sid, const char *hex);
int strn_to_sid_t(sid_t *sid, const char *hex, const char **endp);

int str_is_subscriber_id(const char *sid);
int strn_is_subscriber_id(const char *sid, size_t *lenp);
int str_is_did(const char *did);
int strn_is_did(const char *did, size_t *lenp);

int stowSid(unsigned char *packet, int ofs, const char *sid);
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
		    int recvttl, struct sockaddr *recvaddr, size_t recvaddrlen);
int parseMdpPacketHeader(struct decode_context *context, struct overlay_frame *frame, 
			 struct overlay_buffer *buffer, struct subscriber **nexthop);
int parseEnvelopeHeader(struct decode_context *context, struct overlay_interface *interface, 
			struct sockaddr_in *addr, struct overlay_buffer *buffer);
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, 
			   struct overlay_frame *f, struct decode_context *context);

int overlay_frame_process(struct overlay_interface *interface, struct overlay_frame *f);
int overlay_frame_resolve_addresses(struct overlay_frame *f);

#define alloca_tohex_sid(sid)           alloca_tohex((sid), SID_SIZE)
#define alloca_tohex_sas(sas)           alloca_tohex((sas), SAS_SIZE)

time_ms_t overlay_time_until_next_tick();

int overlay_frame_append_payload(struct decode_context *context, int encapsulation,
				 struct overlay_frame *p, struct overlay_buffer *b,
				 char will_retransmit);
int overlay_packet_init_header(int packet_version, int encapsulation, 
			       struct decode_context *context, struct overlay_buffer *buff, 
			       char unicast, char interface, int seq);
int overlay_interface_args(const char *arg);
void overlay_rhizome_advertise(struct sched_ent *alarm);
int overlay_add_local_identity(unsigned char *s);

extern int overlay_interface_count;

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

int overlay_rhizome_saw_advertisements(int i, struct decode_context *context, struct overlay_frame *f,  time_ms_t now);
int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_saw_voice_traffic();
int overlay_saw_mdp_containing_frame(struct overlay_frame *f, time_ms_t now);

int serval_packetvisualise(const char *message, const unsigned char *packet, size_t len);
int serval_packetvisualise_xpf(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len);

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_opendb();

int parseCommandLine(struct cli_context *context, const char *argv0, int argc, const char *const *argv);

int overlay_mdp_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int overlay_mdp_reply_error(int sock,
			    struct sockaddr_un *recvaddr,int recvaddrlen,
			    int error_number,char *message);
extern struct sched_ent mdp_abstract;
extern struct sched_ent mdp_named;


typedef struct sockaddr_mdp {
  unsigned char sid[SID_SIZE];
  unsigned int port;
} sockaddr_mdp;
unsigned char *keyring_get_nm_bytes(unsigned char *known_sid, unsigned char *unknown_sid);

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
  unsigned char sids[MDP_MAX_SID_REQUEST][SID_SIZE];
} overlay_mdp_addrlist;

typedef struct overlay_mdp_nodeinfo {
  unsigned char sid[SID_SIZE];
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

int keyring_mapping_request(keyring_file *k,overlay_mdp_frame *req);

/* Server-side MDP functions */
int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp);
int overlay_mdp_reply(int sock,struct sockaddr_un *recvaddr,int recvaddrlen,
			  overlay_mdp_frame *mdpreply);
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int userGeneratedFrameP,
		     struct sockaddr_un *recvaddr,int recvaddlen);
int overlay_mdp_encode_ports(struct overlay_buffer *plaintext, int dst_port, int src_port);
int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const unsigned char *resolved_sid, const char *uri, const char *did, const char *name);

struct vomp_call_state;

void set_codec_flag(int codec, unsigned char *flags);
int is_codec_set(int codec, unsigned char *flags);

struct vomp_call_state *vomp_find_call_by_session(int session_token);
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
int monitor_announce_peer(const unsigned char *sid);
int monitor_announce_unreachable_peer(const unsigned char *sid);
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
int dna_helper_enqueue(overlay_mdp_frame *mdp, const char *did, const unsigned char *requestorSid);
int dna_return_resolution(overlay_mdp_frame *mdp, unsigned char *fromSid,
			  const char *did,const char *name,const char *uri);
int parseDnaReply(const char *buf, size_t len, char *token, char *did, char *name, char *uri, const char **bufp);
extern int sigPipeFlag;
extern int sigIoFlag;
void sigPipeHandler(int signal);
void sigIoHandler(int signal);

int overlay_mdp_setup_sockets();

int is_scheduled(const struct sched_ent *alarm);
int _schedule(struct __sourceloc whence, struct sched_ent *alarm);
int _unschedule(struct __sourceloc whence, struct sched_ent *alarm);
int _watch(struct __sourceloc whence, struct sched_ent *alarm);
int _unwatch(struct __sourceloc whence, struct sched_ent *alarm);
#define schedule(alarm)   _schedule(__WHENCE__, alarm)
#define unschedule(alarm) _unschedule(__WHENCE__, alarm)
#define watch(alarm)      _watch(__WHENCE__, alarm)
#define unwatch(alarm)    _unwatch(__WHENCE__, alarm)
int fd_poll();

void overlay_interface_discover(struct sched_ent *alarm);
void overlay_packetradio_poll(struct sched_ent *alarm);
int overlay_packetradio_setup_port(overlay_interface *interface);
int overlay_packetradio_tx_packet(struct overlay_frame *frame);
void overlay_dummy_poll(struct sched_ent *alarm);
void server_config_reload(struct sched_ent *alarm);
void server_shutdown_check(struct sched_ent *alarm);
void overlay_mdp_poll(struct sched_ent *alarm);
int overlay_mdp_try_interal_services(struct overlay_frame *frame, overlay_mdp_frame *mdp);
int overlay_send_probe(struct subscriber *peer, struct network_destination *destination, int queue);
int overlay_send_stun_request(struct subscriber *server, struct subscriber *request);
void fd_periodicstats(struct sched_ent *alarm);
void rhizome_check_connections(struct sched_ent *alarm);

int overlay_tick_interface(int i, time_ms_t now);
int overlay_queue_init();

void monitor_client_poll(struct sched_ent *alarm);
void monitor_poll(struct sched_ent *alarm);
void rhizome_client_poll(struct sched_ent *alarm);
void rhizome_fetch_poll(struct sched_ent *alarm);
void rhizome_server_poll(struct sched_ent *alarm);

int overlay_mdp_service_stun_req(overlay_mdp_frame *mdp);
int overlay_mdp_service_stun(overlay_mdp_frame *mdp);
int overlay_mdp_service_probe(struct overlay_frame *frame, overlay_mdp_frame *mdp);

time_ms_t limit_next_allowed(struct limit_state *state);
int limit_is_allowed(struct limit_state *state);
int limit_init(struct limit_state *state, int rate_micro_seconds);

/* function timing routines */
int fd_clearstats();
int fd_showstats();
int fd_checkalarms();
int fd_func_enter(struct __sourceloc __whence, struct call_stats *this_call);
int fd_func_exit(struct __sourceloc __whence, struct call_stats *this_call);
void dump_stack(int log_level);

#define IN() static struct profile_total _aggregate_stats={NULL,0,__FUNCTION__,0,0,0}; \
    struct call_stats _this_call={.totals=&_aggregate_stats}; \
    fd_func_enter(__HERE__, &_this_call);

#define OUT() fd_func_exit(__HERE__, &_this_call)
#define RETURN(X) do { OUT(); return (X); } while (0);
#define RETURNNULL do { OUT(); return (NULL); } while (0);

int olsr_init_socket(void);
int olsr_send(struct overlay_frame *frame);

void write_uint64(unsigned char *o,uint64_t v);
void write_uint16(unsigned char *o,uint16_t v);
void write_uint32(unsigned char *o,uint32_t v);
uint64_t read_uint64(unsigned char *o);
uint32_t read_uint32(unsigned char *o);
uint16_t read_uint16(unsigned char *o);

int pack_uint(unsigned char *buffer, uint64_t v);
int measure_packed_uint(uint64_t v);
int unpack_uint(unsigned char *buffer, int buff_size, uint64_t *v);

int slip_encode(int format,
		const unsigned char *src, int src_bytes, unsigned char *dst, int dst_len);
int slip_decode(struct slip_decode_state *state);
int upper7_decode(struct slip_decode_state *state,unsigned char byte);
uint32_t Crc32_ComputeBuf( uint32_t inCrc32, const void *buf,
			  size_t bufLen );
extern int last_radio_rssi;
extern int last_radio_temperature;
extern int last_radio_rxpackets;
int rhizome_active_fetch_count();
int rhizome_active_fetch_bytes_received(int q);
extern int64_t bundles_available;
extern char crash_handler_clue[1024];


int link_received_duplicate(struct subscriber *subscriber, struct overlay_interface *interface, int sender_interface, int previous_seq, int unicast);
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

int generate_nonce(unsigned char *nonce,int bytes);

int mavlink_decode(struct slip_decode_state *state,uint8_t c);
int mavlink_heartbeat(unsigned char *frame,int *outlen);
int mavlink_encode_packet(struct overlay_interface *interface);

#endif // __SERVALD_SERVALD_H
