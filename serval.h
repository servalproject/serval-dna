/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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
//FIXME #include <getopt.h>
#include <ctype.h>
#include <sys/stat.h>

#include "constants.h"
#include "log.h"
#include "conf.h"


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

extern int dnatimeout;
extern int hlr_size;
extern unsigned char *hlr;

double simulatedBER;

extern int serverMode;
extern int servalShutdown;

extern int returnMultiVars;

extern char *gatewayspec;

int rhizome_enabled();
int rhizome_http_server_running();
const char *rhizome_datastore_path();

extern struct in_addr client_addr;
extern int client_port;

#define MAX_PEERS 1024
extern int peer_count;
extern struct in_addr peers[MAX_PEERS];

struct mphlr_variable {
  unsigned char id;
  char *name;
  char *desc;
};

extern struct mphlr_variable vars[];

extern char *outputtemplate;
extern char *instrumentation_file;
extern char *batman_socket;
extern char *batman_peerfile;


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
unsigned char *keyring_find_sas_public(keyring_file *k,unsigned char *sid);

int keyring_commit(keyring_file *k);
keyring_identity *keyring_create_identity(keyring_file *k,keyring_context *c, const char *pin);
int keyring_seed(keyring_file *k);
void keyring_identity_extract(const keyring_identity *id, const unsigned char **sidp, const char **didp, const char **namep);

/* Make sure we have space to put bytes of the packet as we go along */
#define CHECK_PACKET_LEN(B) {if (((*packet_len)+(B))>=packet_maxlen) { return WHY("Packet composition ran out of space."); } }

extern int sock;

typedef struct overlay_address_table {
  unsigned char epoch;
  char sids[256][SID_SIZE];
  /* 0x00 = not set, which thus limits us to using only 255 (0x01-0xff) of the indexes for
   storing addresses.
   By spending an extra 256 bytes we reduce, but not eliminate the problem of collisions.
   Will think about a complete solution later.
   */
  unsigned char byfirstbyte[256][2];
  /* next free entry in sid[] */
  unsigned char next_free;
} overlay_address_table;

typedef struct sid {
  unsigned char b[SID_SIZE];
} sid;

typedef struct overlay_address_cache {
  int size;
  int shift; /* Used to calculat lookup function, which is (b[0].b[1].b[2]>>shift) */
  sid *sids; /* one entry per bucket, to keep things simple. */
  /* XXX Should have a means of changing the hash function so that naughty people can't try
   to force our cache to flush with duplicate addresses? 
   But we must use only the first 24 bits of the address due to abbreviation policies, 
   so our options are limited.
   For now the hash will be the first k bits.
   */
} overlay_address_cache;

extern sid overlay_abbreviate_current_sender;

typedef struct overlay_frame {
  struct overlay_frame *prev;
  struct overlay_frame *next;
  
  unsigned int type;
  unsigned int modifiers;
  
  unsigned char ttl;
  
  /* Mark which interfaces the frame has been sent on,
   so that we can ensure that broadcast frames get sent
   exactly once on each interface */
  int isBroadcast;
  unsigned char broadcast_sent_via[OVERLAY_MAX_INTERFACES];
  
  unsigned char nexthop[32];
  int nexthop_address_status;
  int nexthop_interface; /* which interface the next hop should be attempted on */
  
  unsigned char destination[32];
  unsigned char source[32];
  
  /* IPv4 node frame was received from (if applicable) */
  struct sockaddr *recvaddr;
  
  /* Actual payload */
  // TODO refactor *all* packet parsing so that the payload is not copied or allocated unless it must be forwarded.
  struct overlay_buffer *payload;
  
  int rfs; /* remainder of frame size */
  
  long long enqueued_at;
  
} overlay_frame;


struct profile_total {
  struct profile_total *_next;
  int _initialised;
  const char *name;
  long long max_time;
  long long total_time;
  long long child_time;
  int calls;
};

struct call_stats{
  long long enter_time;
  long long child_time;
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
  long long alarm;
  // the order we will prioritise the alarm
  long long deadline;
  struct profile_total *stats;
  int _poll_index;
};

#define STRUCT_SCHED_ENT_UNUSED ((struct sched_ent){NULL, NULL, NULL, NULL, {-1, 0, 0}, 0LL, 0LL, NULL, -1})

extern int overlayMode;

#define INTERFACE_STATE_FREE 0
#define INTERFACE_STATE_UP 1
#define INTERFACE_STATE_DOWN 2
#define INTERFACE_STATE_DETECTING 3

typedef struct overlay_interface {
  struct sched_ent alarm;
  char name[80];
  int offset;
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
  
  /* The time of the last tick on this interface in milli seconds */
  long long last_tick_ms;
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


typedef struct overlay_peer {
  unsigned char address[SIDDIDFIELD_LEN];
  
  /* Scores and score update times for reaching this node via various interfaces */
  int known_routes[OVERLAY_MAX_INTERFACES];
  unsigned short scores[OVERLAY_MAX_INTERFACES][OVERLAY_MAX_PEERS];
  
  /* last_regeneration is the time that this peer was created/replaced with another peer.
   lastupdate[] indicates the time that another peer's reachability report
   caused us to update our score to reach via that peer.
   If lastupdate[x][y] is older than last_regeneration[y], then we must
   ignore the entry, because the lastupdate[x][y] entry references a previous
   generation of that peer, i.e., not to the peer we think it does.
   
   This slight convolution allows us to replace peers without having to touch the
   records of every other peer in our list.
   */
  int last_regeneration;
  unsigned int lastupdate[OVERLAY_MAX_INTERFACES][OVERLAY_MAX_PEERS];
} overlay_peer;

extern overlay_peer overlay_peers[OVERLAY_MAX_PEERS];

typedef struct overlay_buffer {
  unsigned char *bytes;
  // position of data read / written
  int length;
  // allocated size of buffer
  int allocSize;
  // remembered position for rewinding
  int checkpointLength;
  // maximum allowed bytes for reading / writing
  int sizeLimit;
  int var_length_offset;
  int var_length_bytes;
} overlay_buffer;

int ob_unlimitsize(overlay_buffer *b);


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

int is_xsubstring(const char *text, int len);
int is_xstring(const char *text, int len);
char *tohex(char *dstHex, const unsigned char *srcBinary, size_t bytes);
size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t bytes);
int fromhexstr(unsigned char *dstBinary, const char *srcHex, size_t bytes);
int hexvalue(char c);
char *str_toupper_inplace(char *s);

int str_is_subscriber_id(const char *sid);
int strn_is_subscriber_id(const char *sid, size_t *lenp);
int str_is_did(const char *did);
int strn_is_did(const char *did, size_t *lenp);
int str_is_uri(const char *uri);

int stowSid(unsigned char *packet, int ofs, const char *sid);
int stowDid(unsigned char *packet,int *ofs,char *did);
int isFieldZeroP(unsigned char *packet,int start,int count);
void srandomdev();
int respondSimple(keyring_identity *id,
		  int action,unsigned char *action_text,int action_len,
		  unsigned char *transaction_id,int recvttl,
		  struct sockaddr *recvaddr,int cryptoFlags);
long long gettime_ms();
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
int process_packet(unsigned char *packet, size_t len, int recvttl,struct sockaddr *sender, size_t sender_len);
int packetMakeHeader(unsigned char *packet,int packet_maxlen,int *packet_len,unsigned char *transaction_id,int cryptoflags);
int packetSetDid(unsigned char *packet,int packet_maxlen,int *packet_len,char *did);
int packetSetSidFromId(unsigned char *packet,int packet_maxlen,int *packet_len,
		       keyring_identity *id);
int packetFinalise(unsigned char *packet,int packet_maxlen,int recvttl,
		   int *packet_len,int cryptoflags);
int extractResponses(struct in_addr sender,unsigned char *buffer,int len,struct response_set *responses);
int packetGetID(unsigned char *packet,int len,char *did,char *sid);
int getPeerList();
int sendToPeers(unsigned char *packet,int packet_len,int method,int peerId,struct response_set *responses);
int getReplyPackets(int method,int peer,int batchP,struct response_set *responses,
		    unsigned char *transaction_id,struct sockaddr *recvaddr,int timeout);
int clearResponse(struct response **response);
int packageVariableSegment(unsigned char *data,int *dlen,
			   struct response *h,
			   int offset,int buffer_size);
int packetDecipher(unsigned char *packet,int len,int cipher);
int safeZeroField(unsigned char *packet,int start,int count);
int unpackageVariableSegment(unsigned char *data,int dlen,int flags,struct response *r);
int extractSid(const unsigned char *packet,int *ofs, char *sid);
int hlrSetVariable(unsigned char *hlr,int hofs,int varid,int varinstance,
		   unsigned char *value,int len);
int extractDid(unsigned char *packet,int *ofs,char *did);
char *hlrSid(unsigned char *hlr, int ofs, char *sid);
int processRequest(unsigned char *packet,int len,struct sockaddr *sender,int sender_len,
		   unsigned char *transaction_id,int recvttl,char *did,char *sid);

int extractRequest(unsigned char *packet,int *packet_ofs,int packet_len,
		   int *itemId,int *instance,unsigned char *value,
		   int *start_offset,int *max_offset,int *flags);
int hlrGetVariable(unsigned char *hlr,int hofs,int varid,int varinstance,
		   unsigned char *value,int *len);
int dumpResponses(struct response_set *responses);
int eraseLastResponse(struct response_set *responses);
int dropPacketP(size_t packet_len);
int clearResponses(struct response_set *responses);
int responseFromPeerP(struct response_set *responses,int peerId);
int responseFromPeer(struct response_set *responses,int peerId);
int additionalPeer(char *peer);
int readRoutingTable(struct in_addr peers[],int *peer_count,int peer_max);
int readBatmanPeerFile(char *file_path,struct in_addr peers[],int *peer_count,int peer_max);
int getBatmanPeerList(char *socket_path,struct in_addr peers[],int *peer_count,int peer_max);
int hlrDump(unsigned char *hlr,int hofs);
int fixResponses(struct response_set *responses);
int importHlr(char *textfile);
int exportHlr(unsigned char *hlr,char *text);
int openHlrFile(char *backing_file,int size);
int asteriskObtainGateway(char *requestor_sid,char *did,char *uri_out);
int packetOkDNA(unsigned char *packet,int len,unsigned char *transaction_id,
		int recvttl,struct sockaddr *recvaddr, size_t recvaddrlen,int parseP);
int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    unsigned char *transaction_id,int recvttl,
		    struct sockaddr *recvaddr, size_t recvaddrlen,int parseP);
int prepareGateway(char *gatewayspec);
int packetSendRequest(int method,unsigned char *packet,int packet_len,int batchP,
		      unsigned char *transaction_id,struct sockaddr *recvaddr,
		      struct response_set *responses);
int readArpTable(struct in_addr peers[],int *peer_count,int peer_max);

int overlay_frame_process(struct overlay_interface *interface,overlay_frame *f);
int overlay_frame_resolve_addresses(overlay_frame *f);

#define alloca_toprint(dstlen,buf,len)  toprint((char *)alloca(toprint_strlen((dstlen), (buf), (len)) + 1), (dstlen), (buf), (len))

#define alloca_tohex(buf,len)           tohex((char *)alloca((len)*2+1), (buf), (len))
#define alloca_tohex_sid(sid)           alloca_tohex((sid), SID_SIZE)

overlay_buffer *ob_new(int size);
overlay_buffer *ob_static(unsigned char *bytes, int size);
int ob_free(overlay_buffer *b);
int ob_checkpoint(overlay_buffer *b);
int ob_rewind(overlay_buffer *b);
int ob_setlength(overlay_buffer *b,int bytes);
int ob_limitsize(overlay_buffer *b,int bytes);
int ob_unlimitsize(overlay_buffer *b);
int ob_makespace(overlay_buffer *b,int bytes);
int ob_append_byte(overlay_buffer *b,unsigned char byte);
int ob_append_bytes(overlay_buffer *b,unsigned char *bytes,int count);
unsigned char *ob_append_space(overlay_buffer *b,int count);
int ob_append_short(overlay_buffer *b,unsigned short v);
int ob_append_int(overlay_buffer *b,unsigned int v);
int ob_patch_rfs(overlay_buffer *b,int l);
int ob_indel_space(overlay_buffer *b,int offset,int shift);
int ob_append_rfs(overlay_buffer *b,int l);
int ob_setbyte(overlay_buffer *b,int ofs,unsigned char value);
int ob_getbyte(overlay_buffer *b,int ofs);
int ob_dump(overlay_buffer *b,char *desc);
unsigned int ob_get_int(overlay_buffer *b,int offset);

int op_free(overlay_frame *p);
overlay_frame *op_dup(overlay_frame *f);

long long parse_quantity(char *q);

int overlay_interface_init(char *name,struct sockaddr_in *src_addr,struct sockaddr_in *broadcast,
			   int speed_in_bits,int port,int type);
int overlay_interface_init_socket(int i);
long long overlay_time_until_next_tick();
int overlay_rx_messages();

int overlay_add_selfannouncement();
int overlay_frame_package_fmt1(overlay_frame *p,overlay_buffer *b);
int overlay_interface_args(const char *arg);
int overlay_get_nexthop(unsigned char *d,unsigned char *nexthop,int *interface);
int overlay_sendto(struct sockaddr_in *recipientaddr,unsigned char *bytes,int len);
int overlay_rhizome_add_advertisements(int interface_number,overlay_buffer *e);
int overlay_add_local_identity(unsigned char *s);
int overlay_address_is_local(unsigned char *s);
void overlay_update_queue_schedule(overlay_txqueue *queue, overlay_frame *frame);
void overlay_send_packet(struct sched_ent *alarm);
int overlay_resolve_next_hop(overlay_frame *frame);

extern int overlay_interface_count;

extern int overlay_local_identity_count;
extern unsigned char *overlay_local_identities[OVERLAY_MAX_LOCAL_IDENTITIES];

int overlay_abbreviate_address(unsigned char *in,unsigned char *out,int *ofs);
int overlay_abbreviate_append_address(overlay_buffer *b,unsigned char *a);

int overlay_abbreviate_expand_address(unsigned char *in,int *inofs,unsigned char *out,int *ofs);
int overlay_abbreviate_cache_address(unsigned char *sid);
int overlay_abbreviate_cache_lookup(unsigned char *in,unsigned char *out,int *ofs,
				    int prefix_bytes,int index_bytes);
int overlay_abbreviate_remember_index(int index_byte_count,unsigned char *in,unsigned char *index_bytes);
extern int overlay_abbreviate_repeat_policy;
int overlay_abbreviate_set_most_recent_address(unsigned char *in);
int overlay_abbreviate_clear_most_recent_address();

int rfs_length(int l);
int rfs_encode(int l,unsigned char *b);
int rfs_decode(unsigned char *b,int *offset);

typedef struct overlay_neighbour_observation {
  /* Sequence numbers are handled as ranges because the tick
     rate can vary between interfaces, and we want to be able to
     estimate the reliability of links to nodes that may have
     several available interfaces.
     We don't want sequence numbers to wrap too often, but we
     would also like to support fairly fast ticking interfaces,
     e.g., for gigabit type links. So lets go with 1ms granularity. */
  unsigned int s1;
  unsigned int s2;
  long long time_ms;
  unsigned char sender_interface;
  unsigned char valid;
} overlay_neighbour_observation;

typedef struct overlay_node_observation {
  unsigned char observed_score; /* serves as validty check also */
  unsigned char corrected_score;
  unsigned char gateways_en_route;
  unsigned char RESERVED; /* for alignment */
  unsigned char interface;
  long long rx_time;
  unsigned char sender_prefix[OVERLAY_SENDER_PREFIX_LENGTH];
} overlay_node_observation;


typedef struct overlay_node {
  unsigned char sid[SID_SIZE];
  int neighbour_id; /* 0=not a neighbour */
  int most_recent_observation_id;
  int best_link_score;
  int best_observation;
  unsigned int last_first_hand_observation_time_millisec;
  long long last_observation_time_ms;
  /* When did we last advertise this node on each interface, and what score
     did we advertise? */
  long long most_recent_advertisment[OVERLAY_MAX_INTERFACES];
  unsigned char most_recent_advertised_score[OVERLAY_MAX_INTERFACES];
  overlay_node_observation observations[OVERLAY_MAX_OBSERVATIONS];
} overlay_node;

typedef struct overlay_neighbour {
  long long last_observation_time_ms;
  long long last_metric_update;
  int most_recent_observation_id;
  overlay_neighbour_observation observations[OVERLAY_MAX_OBSERVATIONS];
  overlay_node *node;

  /* Scores of visibility from each of the neighbours interfaces.
     This is so that the sender knows which interface to use to reach us.
   */
  unsigned char scores[OVERLAY_MAX_INTERFACES];

  /* One-byte index entries for address abbreviation */
  unsigned char one_byte_index_address_prefixes[256][OVERLAY_SENDER_PREFIX_LENGTH];
} overlay_neighbour;
extern overlay_neighbour *overlay_neighbours;

long long overlay_gettime_ms();
int overlay_route_init(int mb_ram);
int overlay_route_saw_selfannounce_ack(overlay_frame *f,long long now);
int overlay_route_recalc_node_metrics(overlay_node *n,long long now);
int overlay_route_recalc_neighbour_metrics(overlay_neighbour *n,long long now);
int overlay_route_saw_selfannounce(overlay_frame *f,long long now);
overlay_node *overlay_route_find_node(const unsigned char *sid,int prefixLen,int createP);
unsigned int overlay_route_hash_sid(const unsigned char *sid);
int overlay_route_init(int mb_ram);
overlay_neighbour *overlay_route_get_neighbour_structure(unsigned char *packed_sid, 
							 int prefixLen,int createP);
unsigned char *overlay_get_my_sid();
int overlay_frame_set_me_as_source(overlay_frame *f);
int overlay_frame_set_neighbour_as_source(overlay_frame *f,overlay_neighbour *n);
int overlay_frame_set_neighbour_as_destination(overlay_frame *f,overlay_neighbour *n);
int overlay_frame_set_broadcast_as_destination(overlay_frame *f);
int overlay_broadcast_generate_address(unsigned char *a);
int packetEncipher(unsigned char *packet,int maxlen,int *len,int cryptoflags);
int overlayServerMode();
int overlay_payload_enqueue(int q,overlay_frame *p,int forceBroadcastP);
long long overlay_time_in_ms();
int overlay_abbreviate_lookup_sender_id();
int overlay_route_record_link(long long now,unsigned char *to,
			      unsigned char *via,int sender_interface,
			      unsigned int s1,unsigned int s2,int score,int gateways_en_route);
int overlay_route_dump();
int overlay_route_tick_neighbour(int neighbour_id,long long now);
int overlay_route_tick_node(int bin,int slot,long long now);
int overlay_route_add_advertisements(overlay_buffer *e);
int ovleray_route_please_advertise(overlay_node *n);
int overlay_abbreviate_set_current_sender(unsigned char *in);

extern int overlay_bin_count;
extern int overlay_bin_size; /* associativity, i.e., entries per bin */
extern int overlay_bin_bytes;
extern overlay_node **overlay_nodes;

int overlay_route_saw_advertisements(int i,overlay_frame *f, long long now);
int overlay_rhizome_saw_advertisements(int i,overlay_frame *f, long long now);
int overlay_route_please_advertise(overlay_node *n);
int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_saw_voice_traffic();
int overlay_saw_mdp_containing_frame(overlay_frame *f,long long now);

#include "nacl.h"

int serval_packetvisualise(FILE *f,char *message,unsigned char *packet,int plen);

int overlay_broadcast_drop_check(unsigned char *a);
int overlay_address_is_broadcast(unsigned char *a);
int overlay_broadcast_generate_address(unsigned char *a);
int overlay_abbreviate_unset_current_sender();
int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_opendb();

typedef struct dna_identity_status {
  char sid[SID_STRLEN];
  char did[64+1];
  char name[255+1];

  int initialisedP;
  time_t startofvalidity;
  time_t endofvalidity;
  int verifier_count;
  /* Dynamically allocate these so that we don't waste a memory
     (well, if we are talking about running on a feature phone, 4KB per entry
     (16*256 bytes) is best avoided if we can.) */
  unsigned char *verifiers[MAX_SIGNATURES];
  int verificationStatus;

  /* Set if we know that there are no duplicates of this DID/name
     combination, as it allows us to avoid a database lookup. */
  int uniqueDidAndName;
} dna_identity_status;

int parseCommandLine(const char *argv0, int argc, const char *const *argv);

dna_identity_status *dnacache_lookup(char *did,char *name,char *sid);
dna_identity_status *dnacache_lookup_next();
int dnacache_update_verification(char *did,char *sid,char *name,
				 char *signature,int revokeVerificationP);
int dnacache_vouch_for_identity(char *did,char *sid,char *name);

#undef DEBUG_MEM_ABUSE
#ifdef DEBUG_MEM_ABUSE
int memabuseInit();
int _memabuseCheck(const char *func,const char *file,const int line);
#define memabuseCheck() _memabuseCheck(__FUNCTION__,__FILE__,__LINE__)
#else
#define memabuseInit() /* */
#define memabuseCheck() /* */
#endif

const char *thisinstancepath;
const char *serval_instancepath();
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
unsigned char *keyring_get_nm_bytes(sockaddr_mdp *priv,sockaddr_mdp *pub);

typedef struct overlay_mdp_data_frame {
  sockaddr_mdp src;
  sockaddr_mdp dst;
  unsigned short payload_length;
  unsigned char payload[MDP_MTU-100];
} overlay_mdp_data_frame;

typedef struct overlay_mdp_bind_request {
  unsigned int port_number;
  unsigned char sid[SID_SIZE];
} overlay_mdp_bind_request;

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

/* elements sorted by size for alignment */
typedef struct overlay_mdp_vompevent {
  /* Once a call has been established, this is how the MDP/VoMP server
     and user-end process talk about the call. */
  unsigned int call_session_token;
  unsigned long long audio_sample_endtime;
  unsigned long long audio_sample_starttime;
  unsigned long long last_activity;
  unsigned int flags;
  unsigned short audio_sample_bytes;
  unsigned char audio_sample_codec;  
  unsigned char local_state;
  unsigned char remote_state;
  /* list of codecs the registering party is willing to support
       (for VOMPEVENT_REGISTERINTEREST) */
  unsigned char supported_codecs[257];
  union {
    struct {
      /* Used to precisely define the call end points during call
	 setup. */
      char local_did[64];
      char remote_did[64];
      unsigned char local_sid[SID_SIZE];
      unsigned char remote_sid[SID_SIZE];
      /* session numbers of other calls in progress 
	 (for VOMPEVENT_CALLINFO) */
      unsigned int other_calls_sessions[VOMP_MAX_CALLS];
      unsigned char other_calls_states[VOMP_MAX_CALLS];
    };
    unsigned char audio_bytes[MAX_AUDIO_BYTES];
  };
} overlay_mdp_vompevent;

typedef struct overlay_mdp_nodeinfo {
  unsigned char sid[SID_SIZE];
  int sid_prefix_length; /* allow wildcard matching */
  char did[64];
  char name[64];
  int foundP;
  int localP;
  int neighbourP;
  int score;
  int interface_number;
  int resolve_did;
  unsigned long long time_since_last_observation;
  int index; /* which record to return or was returned (incase there are multiple matches) */
  int count; /* number of matching records */
} overlay_mdp_nodeinfo;

typedef struct overlay_mdp_frame {
  unsigned int packetTypeAndFlags;
  union {
    overlay_mdp_data_frame out;
    overlay_mdp_data_frame in;
    overlay_mdp_bind_request bind;
    overlay_mdp_addrlist addrlist;
    overlay_mdp_vompevent vompevent;
    overlay_mdp_nodeinfo nodeinfo;
    overlay_mdp_error error;
    /* 2048 is too large (causes EMSGSIZE errors on OSX, but probably fine on
       Linux) */
    char raw[MDP_MTU];
  };
} overlay_mdp_frame;

int keyring_mapping_request(keyring_file *k,overlay_mdp_frame *req);

/* Client-side MDP function */
extern int mdp_client_socket;
int overlay_mdp_client_init();
int overlay_mdp_client_done();
int overlay_mdp_client_poll(long long timeout_ms);
int overlay_mdp_recv(overlay_mdp_frame *mdp,int *ttl);
int overlay_mdp_send(overlay_mdp_frame *mdp,int flags,int timeout_ms);

/* Server-side MDP functions */
int overlay_saw_mdp_frame(overlay_mdp_frame *mdp,long long now);
int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp);
int overlay_mdp_reply(int sock,struct sockaddr_un *recvaddr,int recvaddrlen,
			  overlay_mdp_frame *mdpreply);
int overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp);
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int userGeneratedFrameP,
		     struct sockaddr_un *recvaddr,int recvaddlen);
int overlay_mdp_dnalookup_reply(const overlay_mdp_data_frame *mdpd, const unsigned char *sid, const char *uri, const char *did, const char *name);

int dump_payload(overlay_frame *p,char *message);

int urandombytes(unsigned char *x,unsigned long long xlen);

#ifdef MALLOC_PARANOIA
#define malloc(X) _serval_debug_malloc(X,__FILE__,__FUNCTION__,__LINE__)
#define calloc(X,Y) _serval_debug_calloc(X,Y,__FILE__,__FUNCTION__,__LINE__)
#define free(X) _serval_debug_free(X,__FILE__,__FUNCTION__,__LINE__)

void *_serval_debug_malloc(unsigned int bytes,char *file,const char *func,int line);
void *_serval_debug_calloc(unsigned int bytes,unsigned int count,char *file,const char *func,int line);
void _serval_debug_free(void *p,char *file,const char *func,int line);
#endif


typedef struct vomp_call_half {
  unsigned char sid[SID_SIZE];
  unsigned char did[64];
  unsigned char state;
  unsigned char codec;
  unsigned int session;
  unsigned int sequence;
  /* the following is from call creation, not start of audio flow */
  unsigned long long milliseconds_since_call_start;
} vomp_call_half;

typedef struct vomp_sample_block {
  unsigned int codec;
  unsigned long long starttime;
  unsigned long long endtime;
  unsigned char bytes[1024];
} vomp_sample_block;

typedef struct vomp_call_state {
  struct sched_ent alarm;
  vomp_call_half local;
  vomp_call_half remote;
  int initiated_call;
  int ringing;
  int fast_audio;
  unsigned long long create_time;
  unsigned long long last_activity;
  unsigned long long audio_clock;
  int audio_started;
  // last local & remote status we sent to all interested parties
  int last_sent_status;
  unsigned char remote_codec_list[256];
  int recent_sample_rotor;
  vomp_sample_block recent_samples[VOMP_MAX_RECENT_SAMPLES];
  
  int sample_pos;
  unsigned int seen_samples[VOMP_MAX_RECENT_SAMPLES *4];
} vomp_call_state;

extern int vomp_call_count;
extern int vomp_active_call;
extern vomp_call_state vomp_call_states[VOMP_MAX_CALLS];


vomp_call_state *vomp_find_call_by_session(int session_token);
int vomp_mdp_event(overlay_mdp_frame *mdp,
		   struct sockaddr_un *recvaddr,int recvaddrlen);
int vomp_mdp_received(overlay_mdp_frame *mdp);
char *vomp_describe_state(int state);
char *vomp_describe_codec(int c);
int vomp_tick_interval();
int vomp_sample_size(int c);
int vomp_codec_timespan(int c);
int vomp_parse_dtmf_digit(char c);
int vomp_dial(unsigned char *local_sid, unsigned char *remote_sid, char *local_did, char *remote_did);
int vomp_pickup(vomp_call_state *call);
int vomp_hangup(vomp_call_state *call);
int vomp_send_status_remote_audio(vomp_call_state *call, int audio_codec, const unsigned char *audio, int audio_length);


typedef struct command_line_option {
  int (*function)(int argc, const char *const *argv, struct command_line_option *o);
  const char *words[32]; // 32 words should be plenty!
  unsigned long long flags;
#define CLIFLAG_NONOVERLAY (1<<0) /* Uses a legacy IPv4 DNA call instead of overlay mnetwork */
#define CLIFLAG_STANDALONE (1<<1) /* Cannot be issued to a running instance */
  const char *description; // describe this invocation
} command_line_option;

extern command_line_option command_line_options[];
int cli_arg(int argc, const char *const *argv, command_line_option *o, char *argname, const char **dst, int (*validator)(const char *arg), char *defaultvalue);
int cli_putchar(char c);
int cli_puts(const char *str);
int cli_printf(const char *fmt, ...);
int cli_delim(const char *opt);

int is_configvarname(const char *arg);

int overlay_mdp_getmyaddr(int index,unsigned char *sid);
int overlay_mdp_bind(unsigned char *localaddr,int port); 
int overlay_route_node_info(overlay_mdp_frame *mdp,
			    struct sockaddr_un *addr,int addrlen);
int overlay_interface_register(char *name,
			       struct sockaddr_in *local,
			       struct sockaddr_in *broadcast);
int overlay_queue_dump(overlay_txqueue *q);
int overlay_broadcast_ensemble(int interface_number,
			       struct sockaddr_in *recipientaddr /* NULL == broadcast */,
			       unsigned char *bytes,int len);

int app_vomp_status(int argc, const char *const *argv, struct command_line_option *o);
int app_vomp_dial(int argc, const char *const *argv, struct command_line_option *o);
int app_vomp_pickup(int argc, const char *const *argv, struct command_line_option *o);
int app_vomp_hangup(int argc, const char *const *argv, struct command_line_option *o);
int app_vomp_monitor(int argc, const char *const *argv, struct command_line_option *o);
#ifdef HAVE_VOIPTEST
int app_pa_phone(int argc, const char *const *argv, struct command_line_option *o);
#endif
int app_vomp_dtmf(int argc, const char *const *argv, struct command_line_option *o);
int app_monitor_cli(int argc, const char *const *argv, struct command_line_option *o);

int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);

int monitor_setup_sockets();
int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int monitor_call_status(vomp_call_state *call);
int monitor_send_audio(vomp_call_state *call, int audio_codec, unsigned int start_time, unsigned int end_time, const unsigned char *audio, int audio_length);
int monitor_announce_peer(const unsigned char *sid);
int monitor_announce_unreachable_peer(const unsigned char *sid);
int monitor_tell_clients(char *msg, int msglen, int mask);
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
int bufferAudioForPlayback(int codec,long long start_time,long long end_time,
			   unsigned char *data,int dataLen);
int startAudio();
int stopAudio();

#define SERVER_UNKNOWN 1
#define SERVER_NOTRESPONDING 2
#define SERVER_NOTRUNNING 3
#define SERVER_RUNNING 4
int server_probe(int *pid);

int dna_helper_shutdown();
int dna_helper_enqueue(overlay_mdp_frame *mdp, const char *did, const unsigned char *requestorSid);
int dna_return_resolution(overlay_mdp_frame *mdp, unsigned char *fromSid,
			  const char *did,const char *name,const char *uri);
int parseDnaReply(const char *buf, size_t len, char *token, char *did, char *name, char *uri, const char **bufp);
extern int sigPipeFlag;
extern int sigIoFlag;
void sigPipeHandler(int signal);
void sigIoHandler(int signal);

#define set_nonblock(fd)                (_set_nonblock(fd, __FILE__, __LINE__, __FUNCTION__))
#define set_block(fd)                   (_set_block(fd, __FILE__, __LINE__, __FUNCTION__))
#define read_nonblock(fd,buf,len)       (_read_nonblock(fd, buf, len, __FILE__, __LINE__, __FUNCTION__))
#define write_all(fd,buf,len)           (_write_all(fd, buf, len, __FILE__, __LINE__, __FUNCTION__))
#define write_nonblock(fd,buf,len)      (_write_nonblock(fd, buf, len, __FILE__, __LINE__, __FUNCTION__))
#define write_all_nonblock(fd,buf,len)  (_write_all_nonblock(fd, buf, len, __FILE__, __LINE__, __FUNCTION__))
#define write_str(fd,str)               (_write_str(fd, str, __FILE__, __LINE__, __FUNCTION__))
#define write_str_nonblock(fd,str)      (_write_str_nonblock(fd, str, __FILE__, __LINE__, __FUNCTION__))

int _set_nonblock(int fd, const char *file, unsigned int line, const char *function);
int _set_block(int fd, const char *file, unsigned int line, const char *function);
ssize_t _read_nonblock(int fd, void *buf, size_t len, const char *file, unsigned int line, const char *function);
ssize_t _write_all(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function);
ssize_t _write_nonblock(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function);
ssize_t _write_all_nonblock(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function);
ssize_t _write_str(int fd, const char *str, const char *file, unsigned int line, const char *function);
ssize_t _write_str_nonblock(int fd, const char *str, const char *file, unsigned int line, const char *function);

int rhizome_http_server_start();
int overlay_mdp_setup_sockets();

int schedule(struct sched_ent *alarm);
int unschedule(struct sched_ent *alarm);
int watch(struct sched_ent *alarm);
int unwatch(struct sched_ent *alarm);
int fd_poll();

void overlay_interface_discover(struct sched_ent *alarm);
void overlay_dummy_poll(struct sched_ent *alarm);
void overlay_route_tick(struct sched_ent *alarm);
void rhizome_enqueue_suggestions(struct sched_ent *alarm);
void server_shutdown_check(struct sched_ent *alarm);
void overlay_mdp_poll(struct sched_ent *alarm);
void fd_periodicstats(struct sched_ent *alarm);
void rhizome_check_connections(struct sched_ent *alarm);

void monitor_client_poll(struct sched_ent *alarm);
void monitor_poll(struct sched_ent *alarm);
void overlay_interface_poll(struct sched_ent *alarm);
void rhizome_client_poll(struct sched_ent *alarm);
void rhizome_fetch_poll(struct sched_ent *alarm);
void rhizome_server_poll(struct sched_ent *alarm);

/* function timing routines */
int fd_clearstats();
int fd_showstats();
int fd_checkalarms();
int fd_func_exit(struct call_stats *this_call);
int fd_func_enter(struct call_stats *this_call);
void dump_stack();

#define IN() static struct profile_total _aggregate_stats={NULL,0,__FUNCTION__,0,0,0}; \
    struct call_stats _this_call; \
    _this_call.totals=&_aggregate_stats; \
    fd_func_enter(&_this_call);

#define OUT() fd_func_exit(&_this_call);
#define RETURN(X) { OUT() return(X); }
