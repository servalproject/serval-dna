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

// #define MALLOC_PARANOIA

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

#include "constants.h"
#include "xprintf.h"
#include "log.h"
#include "net.h"
#include "conf.h"

/* All wall clock times in the Serval daemon are represented in milliseconds
 * since the Unix epoch.  The gettime_ms() function uses gettimeofday(2) to
 * return this value when called.  The time_ms_t typedef should be used
 * wherever this time value is handled or stored.
 *
 * This type could perfectly well be unsigned, but is defined as signed to
 * avoid the need to cast or define a special signed timedelta_ms_t type at **
 * (1):
 *
 *      static time_ms_t then = 0;
 *      time_ms_t now = gettime_ms();
 *      time_ms_t ago = now - then;  // ** (1)
 *      if (then && ago < 0) {
 *          ... time going backwards ...
 *      } else {
 *          ... time has advanced ...
 *          then = now;
 *      }
 */
typedef long long time_ms_t;

/* bzero(3) is deprecated in favour of memset(3). */
#define bzero(addr,len) memset((addr), 0, (len))

/* UDP Port numbers for various Serval services.
 The overlay mesh works over DNA */
#define PORT_DNA 4110

/* OpenWRT libc doesn't have bcopy, but has memmove */
#define bcopy(A,B,C) memmove(B,A,C)

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

double simulatedBER;

extern int serverMode;
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
  int private_key_len;
  unsigned char *public_key;
  int public_key_len;
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
  int keypair_count;
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

  int identity_count;
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
void keyring_free_keypair(keypair *kp);
int keyring_identity_mac(keyring_context *c,keyring_identity *id,
			 unsigned char *pkrsalt,unsigned char *mac);
#define KEYTYPE_CRYPTOBOX 0x01
#define KEYTYPE_CRYPTOSIGN 0x02
#define KEYTYPE_RHIZOME 0x03
/* DIDs aren't really keys, but the keyring is a real handy place to keep them,
   and keep them private if people so desire */
#define KEYTYPE_DID 0x04

/* handle to keyring file for use in running instance */
extern keyring_file *keyring;

/* Public calls to keyring management */
keyring_file *keyring_open(char *file);
keyring_file *keyring_open_with_pins(const char *pinlist);
int keyring_enter_pin(keyring_file *k, const char *pin);
int keyring_enter_pins(keyring_file *k, const char *pinlist);
int keyring_set_did(keyring_identity *id,char *did,char *name);
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

struct overlay_buffer;

#define STRUCT_SCHED_ENT_UNUSED ((struct sched_ent){NULL, NULL, NULL, NULL, {-1, 0, 0}, 0LL, 0LL, NULL, -1})

extern int overlayMode;

#define INTERFACE_STATE_FREE 0
#define INTERFACE_STATE_UP 1
#define INTERFACE_STATE_DOWN 2
#define INTERFACE_STATE_DETECTING 3

typedef struct overlay_interface {
  struct sched_ent alarm;
  char name[256];
  int recv_offset;
  int fileP;
  int bits_per_second;
  int port;
  int type;
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
  int tick_ms; /* milliseconds per tick */
  int send_broadcasts;
  /* The time of the last tick on this interface in milli seconds */
  time_ms_t last_tick_ms;
  /* How many times have we abbreviated our address since we last announced it in full? */
  int ticks_since_sent_full_address;
  
  /* sequence number of last packet sent on this interface.
   Used to allow NACKs that can request retransmission of recent packets.
   */
  int sequence_number;
  /* XXX need recent packet buffers to support the above */
  
  /* We need to make sure that interface name and broadcast address is unique for all interfaces that are UP.
   We bind a separate socket per interface / broadcast address Broadcast address and netmask, if known
   We really only case about distinct broadcast addresses on interfaces.
   Also simplifies aliases on interfaces. */
  struct sockaddr_in address;
  struct sockaddr_in broadcast_address;
  struct in_addr netmask;
  
  /* Not necessarily the real MTU, but the largest frame size we are willing to TX on this interface.
   For radio links the actual maximum and the maximum that is likely to be delivered reliably are
   potentially two quite different values. */
  int mtu;
  
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

typedef struct overlay_txqueue {
  struct overlay_frame *first;
  struct overlay_frame *last;
  int length; /* # frames in queue */
  int maxLength; /* max # frames in queue before we consider ourselves congested */
  
  /* wait until first->enqueued_at+transmit_delay before trying to force the transmission of a packet */
  int transmit_delay;
  
  /* if servald is busy, wait this long before trying to force the transmission of a packet */
  int grace_period;
  
  /* Latency target in ms for this traffic class.
   Frames older than the latency target will get dropped. */
  int latencyTarget;
  
  /* XXX Need to initialise these:
   Real-time queue for voice (<200ms ?)
   Real-time queue for video (<200ms ?) (lower priority than voice)
   Ordinary service queue (<3 sec ?)
   Rhizome opportunistic queue (infinity)
   
   (Mesh management doesn't need a queue, as each overlay packet is tagged with some mesh management information)
   */
} overlay_txqueue;


extern overlay_txqueue overlay_tx[OQ_MAX];

ssize_t recvwithttl(int sock, unsigned char *buffer, size_t bufferlen, int *ttl, struct sockaddr *recvaddr, socklen_t *recvaddrlen);

// is the SID entirely 0xFF?
#define is_sid_broadcast(SID) is_all_matching(SID, SID_SIZE, 0xFF)

// is the SID entirely 0x00?
#define is_sid_any(SID) is_all_matching(SID, SID_SIZE, 0)

int str_is_subscriber_id(const char *sid);
int strn_is_subscriber_id(const char *sid, size_t *lenp);
int str_is_did(const char *did);
int strn_is_did(const char *did, size_t *lenp);
int str_is_uri(const char *uri);

int stowSid(unsigned char *packet, int ofs, const char *sid);
void srandomdev();
time_ms_t gettime_ms();
time_ms_t sleep_ms(time_ms_t milliseconds);
int server_pid();
void server_save_argv(int argc, const char *const *argv);
int server(char *backing_file);
int server_create_stopfile();
int server_remove_stopfile();
int server_check_stopfile();
void serverCleanUp();
int isTransactionInCache(unsigned char *transaction_id);
void insertTransactionInCache(unsigned char *transaction_id);

int packetOk(struct overlay_interface *interface,unsigned char *packet, size_t len,
	     unsigned char *transaction_id, int recvttl,
	     struct sockaddr *recvaddr, size_t recvaddrlen,int parseP);

int overlay_forward_payload(struct overlay_frame *f);
int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    unsigned char *transaction_id,int recvttl,
		    struct sockaddr *recvaddr, size_t recvaddrlen,int parseP);

int overlay_frame_process(struct overlay_interface *interface, struct overlay_frame *f);
int overlay_frame_resolve_addresses(struct overlay_frame *f);

#define alloca_tohex(buf,len)           tohex((char *)alloca((len)*2+1), (buf), (len))
#define alloca_tohex_sid(sid)           alloca_tohex((sid), SID_SIZE)
#define alloca_tohex_sas(sas)           alloca_tohex((sas), SAS_SIZE)

time_ms_t overlay_time_until_next_tick();

int overlay_add_selfannouncement();
int overlay_frame_append_payload(overlay_interface *interface, struct overlay_frame *p, struct subscriber *next_hop, struct overlay_buffer *b);
int overlay_interface_args(const char *arg);
int overlay_rhizome_add_advertisements(int interface_number,struct overlay_buffer *e);
int overlay_add_local_identity(unsigned char *s);
void overlay_update_queue_schedule(overlay_txqueue *queue, struct overlay_frame *frame);
void overlay_send_packet(struct sched_ent *alarm);

extern int overlay_interface_count;

extern int overlay_local_identity_count;
extern unsigned char *overlay_local_identities[OVERLAY_MAX_LOCAL_IDENTITIES];

int rfs_length(int l);
int rfs_encode(int l,unsigned char *b);
int rfs_decode(unsigned char *b,int *offset);

typedef struct overlay_node_observation {
  unsigned char observed_score; /* serves as validty check also */
  unsigned char corrected_score;
  unsigned char gateways_en_route;
  unsigned char RESERVED; /* for alignment */
  unsigned char interface;
  time_ms_t rx_time;
  struct subscriber *sender;
} overlay_node_observation;


typedef struct overlay_node {
  struct subscriber *subscriber;
  int neighbour_id; /* 0=not a neighbour */
  int most_recent_observation_id;
  int best_link_score;
  int best_observation;
  unsigned int last_first_hand_observation_time_millisec;
  time_ms_t last_observation_time_ms;
  /* When did we last advertise this node on each interface, and what score
     did we advertise? */
  time_ms_t most_recent_advertisment_ms[OVERLAY_MAX_INTERFACES];
  unsigned char most_recent_advertised_score[OVERLAY_MAX_INTERFACES];
  overlay_node_observation observations[OVERLAY_MAX_OBSERVATIONS];
} overlay_node;

int overlay_route_saw_selfannounce_ack(struct overlay_frame *f, time_ms_t now);
int overlay_route_saw_selfannounce(struct overlay_frame *f, time_ms_t now);
overlay_node *overlay_route_find_node(const unsigned char *sid,int prefixLen,int createP);

int overlayServerMode();
int overlay_payload_enqueue(struct overlay_frame *p);
int overlay_route_record_link( time_ms_t now,unsigned char *to,
			      unsigned char *via,int sender_interface,
			      unsigned int s1,unsigned int s2,int score,int gateways_en_route);
int overlay_route_dump();
int overlay_route_add_advertisements(overlay_interface *interface, struct overlay_buffer *e);
int ovleray_route_please_advertise(overlay_node *n);

int overlay_route_saw_advertisements(int i, struct overlay_frame *f, struct decode_context *context, time_ms_t now);
int overlay_rhizome_saw_advertisements(int i, struct overlay_frame *f,  time_ms_t now);
int overlay_route_please_advertise(overlay_node *n);
int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_saw_voice_traffic();
int overlay_saw_mdp_containing_frame(struct overlay_frame *f, time_ms_t now);

int serval_packetvisualise(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len);

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_opendb();

int parseCommandLine(const char *argv0, int argc, const char *const *argv);

int form_serval_instance_path(char * buf, size_t bufsiz, const char *path);
int create_serval_instance_dir();

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
  // temporary hack to improve reliability before implementing per-packet nack's
  int send_copies;
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
int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const unsigned char *resolved_sid, const char *uri, const char *did, const char *name);

int dump_payload(struct overlay_frame *p, char *message);

int urandombytes(unsigned char *x,unsigned long long xlen);

#ifdef MALLOC_PARANOIA
#define malloc(X) _serval_debug_malloc(X,__WHENCE__)
#define calloc(X,Y) _serval_debug_calloc(X,Y,__WHENCE__)
#define free(X) _serval_debug_free(X,__WHENCE__)

void *_serval_debug_malloc(unsigned int bytes, struct __sourceloc whence);
void *_serval_debug_calloc(unsigned int bytes, unsigned int count, struct __sourceloc whence);
void _serval_debug_free(void *p, struct __sourceloc whence);
#endif


struct vomp_call_state;

void set_codec_flag(int codec, unsigned char *flags);
int is_codec_set(int codec, unsigned char *flags);

struct vomp_call_state *vomp_find_call_by_session(int session_token);
int vomp_mdp_received(overlay_mdp_frame *mdp);
int vomp_tick_interval();
int vomp_sample_size(int c);
int vomp_codec_timespan(int c);
int vomp_parse_dtmf_digit(char c);
int vomp_dial(unsigned char *local_sid, unsigned char *remote_sid, const char *local_did, const char *remote_did);
int vomp_pickup(struct vomp_call_state *call);
int vomp_hangup(struct vomp_call_state *call);
int vomp_ringing(struct vomp_call_state *call);
int vomp_received_audio(struct vomp_call_state *call, int audio_codec, const unsigned char *audio, int audio_length);
void monitor_get_all_supported_codecs(unsigned char *codecs);

int cli_putchar(char c);
int cli_puts(const char *str);
int cli_printf(const char *fmt, ...);
int cli_delim(const char *opt);

int is_configvarname(const char *arg);

int overlay_mdp_getmyaddr(int index,unsigned char *sid);
int overlay_mdp_bind(unsigned char *localaddr,int port); 
int overlay_route_node_info(overlay_mdp_nodeinfo *node_info);
int overlay_interface_register(char *name,
			       struct in_addr addr,
			       struct in_addr mask);
overlay_interface * overlay_interface_find(struct in_addr addr);
overlay_interface * overlay_interface_find_name(const char *name);

int directory_registration();
int directory_service_init();

struct command_line_option;
int app_rhizome_direct_sync(int argc, const char *const *argv, struct command_line_option *o, void *context);
#ifdef HAVE_VOIPTEST
int app_pa_phone(int argc, const char *const *argv, struct command_line_option *o, void *context);
#endif
int app_monitor_cli(int argc, const char *const *argv, struct command_line_option *o, void *context);
int app_vomp_console(int argc, const char *const *argv, struct command_line_option *o, void *context);

int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);

int monitor_setup_sockets();
int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int monitor_announce_peer(const unsigned char *sid);
int monitor_announce_unreachable_peer(const unsigned char *sid);
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
void overlay_dummy_poll(struct sched_ent *alarm);
void overlay_route_tick(struct sched_ent *alarm);
void server_shutdown_check(struct sched_ent *alarm);
void overlay_mdp_poll(struct sched_ent *alarm);
void fd_periodicstats(struct sched_ent *alarm);
void rhizome_check_connections(struct sched_ent *alarm);

void monitor_client_poll(struct sched_ent *alarm);
void monitor_poll(struct sched_ent *alarm);
void rhizome_client_poll(struct sched_ent *alarm);
void rhizome_fetch_poll(struct sched_ent *alarm);
void rhizome_server_poll(struct sched_ent *alarm);

/* function timing routines */
int fd_clearstats();
int fd_showstats();
int fd_checkalarms();
int fd_func_enter(struct __sourceloc __whence, struct call_stats *this_call);
int fd_func_exit(struct __sourceloc __whence, struct call_stats *this_call);
void dump_stack();

#define IN() static struct profile_total _aggregate_stats={NULL,0,__FUNCTION__,0,0,0}; \
    struct call_stats _this_call; \
    _this_call.totals=&_aggregate_stats; \
    fd_func_enter(__HERE__, &_this_call);

#define OUT() fd_func_exit(__HERE__, &_this_call)
#define RETURN(X) do { OUT(); return (X); } while (0);
#define RETURNNULL do { OUT(); return (NULL); } while (0);

int olsr_init_socket(void);
int olsr_send(struct overlay_frame *frame);

#endif // __SERVALD_SERVALD_H
