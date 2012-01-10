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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <signal.h>

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
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_IF_H
#include <linux/if.h>
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
#include <net/if.h>
#endif

#include <fcntl.h>
//FIXME #include <getopt.h>
#include <ctype.h>

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

extern int debug;
extern int timeout;
extern int hlr_size;
extern unsigned char *hlr;

double simulatedBER;

extern int serverMode;

extern int returnMultiVars;

extern char *gatewayspec;

extern char *rhizome_datastore_path;

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

extern char *outputtemplate;
extern char *instrumentation_file;
extern char *batman_socket;
extern char *batman_peerfile;

/* HLR records can be upto 4GB, so 4x8bits are needed to encode the size */
#define HLR_RECORD_LEN_SIZE 4

/* Packet format:

   16 bit - Magic value 0x4110
   16 bit - Version number (0001 initially)
   16 bit - Payload length
   16 bit - Cipher method (0000 = clear text)
   
   Ciphered payload follows:
   (needs to have no predictable data to protect against known plain-text attacks)
   
   64bit transaction id (random)
   8bit - payload rotation (random, to help protect encryption from cribs)

   Remainder of payload, after correcting for rotation:
   
   33byte did|subscriber id
   16byte salt
   16byte hash of PIN+salt
   
   Remainder of packet is interpretted as a series of operations

   8 bit operation: 
   00 = get, 01 = set, 02 = delete, 03 = update,
   80 = decline, 81 = okay (+optional result),
   f0 = xfer HLR record
   fe = random padding follows (to help protect cryptography from cribs)
   ff = end of transaction
   
   get - 8 bit variable value

*/
#define SID_SIZE 32 
#define DID_MAXSIZE 32
#define SIDDIDFIELD_LEN (SID_SIZE+1)
#define PINFIELD_LEN 32
#define HEADERFIELDS_LEN (2+2+2+2+8+1)
#define OFS_TRANSIDFIELD (2+2+2+2)
#define TRANSID_SIZE 8
#define OFS_ROTATIONFIELD (OFS_TRANSIDFIELD+TRANSID_SIZE)
#define OFS_SIDDIDFIELD HEADERFIELDS_LEN
#define OFS_PINFIELD (OFS_SIDDIDFIELD+SIDDIDFIELD_LEN)
#define OFS_PAYLOAD (OFS_PINFIELD+16+16)

struct response {
  int code;
  unsigned char sid[32];
  struct in_addr sender;
  unsigned char *response;
  int response_len;
  int var_id;
  int var_instance;
  int value_len;
  int value_offset;
  int value_bytes;
  struct response *next,*prev;

  /* who sent it? */
  unsigned short peer_id;
  /* have we checked it to see if it allows us to stop requesting? */
  unsigned char checked;
};

struct response_set {
  struct response *responses;
  struct response *last_response;
  int response_count;

  /* Bit mask of peers who have replied */
  unsigned char *reply_bitmask;
};

struct hlrentry_handle {
  int record_length;
  unsigned char *hlr;
  int hlr_offset;
  
  int var_id;
  int var_instance;
  unsigned char *value;
  int value_len;

  int entry_offset;
};

/* Array of variables that can be placed in an MPHLR */
#define VAR_EOR 0x00
#define VAR_CREATETIME 0x01
#define VAR_CREATOR 0x02
#define VAR_REVISION 0x03
#define VAR_REVISOR 0x04
#define VAR_PIN 0x05
#define VAR_VOICESIG 0x08
#define VAR_HLRMASTER 0x0f
#define VAR_DIDS 0x80
#define VAR_LOCATIONS 0x81
#define VAR_IEMIS 0x82
#define VAR_TEMIS 0x83
#define VAR_CALLS_IN 0x90
#define VAR_CALLS_MISSED 0x91
#define VAR_CALLS_OUT 0x92
#define VAR_SMESSAGES 0xa0
#define VAR_DID2SUBSCRIBER 0xb0
#define VAR_HLRBACKUPS 0xf0
#define VAR_NOTE 0xff
extern struct mphlr_variable vars[];

#define ACTION_GET 0x00
#define ACTION_SET 0x01
#define ACTION_DEL 0x02
#define ACTION_INSERT 0x03
#define ACTION_DIGITALTELEGRAM 0x04
#define ACTION_CREATEHLR 0x0f

#define ACTION_STATS 0x40

#define ACTION_DONE 0x7e
#define ACTION_ERROR 0x7f

#define ACTION_DECLINED 0x80
#define ACTION_OKAY 0x81
#define ACTION_DATA 0x82
#define ACTION_WROTE 0x83

#define ACTION_XFER 0xf0
#define ACTION_PAD 0xfe
#define ACTION_EOT 0xff

extern int hexdigit[16];

/* Make sure we have space to put bytes of the packet as we go along */
#define CHECK_PACKET_LEN(B) {if (((*packet_len)+(B))>=packet_maxlen) { setReason("Packet composition ran out of space."); return -1; } }

extern int sock;

int stowSid(unsigned char *packet,int ofs,char *sid);
int stowDid(unsigned char *packet,int *ofs,char *did);
int isFieldZeroP(unsigned char *packet,int start,int count);
void srandomdev();
int respondSimple(char *sid,int action,unsigned char *action_text,int action_len,
		  unsigned char *transaction_id,struct sockaddr *recvaddr,int cryptoFlags);
int requestItem(char *did,char *sid,char *item,int instance,unsigned char *buffer,int buffer_length,int *len,
		unsigned char *transaction_id);
int requestNewHLR(char *did,char *pin,char *sid,struct sockaddr *recvaddr);
int server(char *backing_file,int size,int foregroundMode);

int setReason(char *fmt, ...);
int hexvalue(unsigned char c);
int dump(char *name,unsigned char *addr,int len);
int packetOk(int interface,unsigned char *packet,int len,unsigned char *transaction_id,
	     struct sockaddr *recvaddr,int recvaddrlen,int parseP);
int process_packet(unsigned char *packet,int len,struct sockaddr *sender,int sender_len);
int packetMakeHeader(unsigned char *packet,int packet_maxlen,int *packet_len,unsigned char *transaction_id,int cryptoflags);
int packetSetDid(unsigned char *packet,int packet_maxlen,int *packet_len,char *did);
int packetSetSid(unsigned char *packet,int packet_maxlen,int *packet_len,char *sid);
int packetFinalise(unsigned char *packet,int packet_maxlen,int *packet_len,int cryptoflags);
int packetAddHLRCreateRequest(unsigned char *packet,int packet_maxlen,int *packet_len);
int extractResponses(struct in_addr sender,unsigned char *buffer,int len,struct response_set *responses);
int packetAddVariableRequest(unsigned char *packet,int packet_maxlen,int *packet_len,
                             char *item,int instance,int start_offset,int max_offset);
int packetGetID(unsigned char *packet,int len,char *did,char *sid);
int getPeerList();
int sendToPeers(unsigned char *packet,int packet_len,int method,int peerId,struct response_set *responses);
int getReplyPackets(int method,int peer,int batchP,struct response_set *responses,
		    unsigned char *transaction_id,struct sockaddr *recvaddr,int timeout);
int clearResponse(struct response **response);
int nextHlr(unsigned char *hlr,int *ofs);
int seedHlr();
int findHlr(unsigned char *hlr,int *ofs,char *sid,char *did);
int createHlr(char *did,char *sid);
struct hlrentry_handle *openhlrentry(unsigned char *hlr,int hofs);
struct hlrentry_handle *hlrentrygetent(struct hlrentry_handle *h);
int hlrStowValue(unsigned char *hlr,int hofs,int hlr_offset,
		 int varid,int varinstance,unsigned char *value,int len);
int hlrMakeSpace(unsigned char *hlr,int hofs,int hlr_offset,int bytes);
int packageVariableSegment(unsigned char *data,int *dlen,struct hlrentry_handle *h,
			   int offset,int buffer_size);
int packetDecipher(unsigned char *packet,int len,int cipher);
int safeZeroField(unsigned char *packet,int start,int count);
int unpackageVariableSegment(unsigned char *data,int dlen,int flags,struct response *r);
int extractSid(unsigned char *packet,int *ofs,char *sid);
int hlrSetVariable(unsigned char *hlr,int hofs,int varid,int varinstance,
		   unsigned char *value,int len);
int extractDid(unsigned char *packet,int *ofs,char *did);
char *hlrSid(unsigned char *hlr,int ofs);
int parseAssignment(unsigned char *text,int *var_id,unsigned char *value,int *value_len);
int writeItem(char *sid,int var_id,int instance,unsigned char *value,
	      int value_start,int value_length,int flags, struct sockaddr *recvaddr);
int packetAddVariableWrite(unsigned char *packet,int packet_maxlen,int *packet_len,
			   int itemId,int instance,unsigned char *value,int start_offset,int value_len,int flags);
int processRequest(unsigned char *packet,int len,struct sockaddr *sender,int sender_len,
		   unsigned char *transaction_id,char *did,char *sid);

int extractRequest(unsigned char *packet,int *packet_ofs,int packet_len,
		   int *itemId,int *instance,unsigned char *value,
		   int *start_offset,int *max_offset,int *flags);
int hlrGetVariable(unsigned char *hlr,int hofs,int varid,int varinstance,
		   unsigned char *value,int *len);
int dumpResponses(struct response_set *responses);
int eraseLastResponse(struct response_set *responses);
int dropPacketP(int packet_len);
int clearResponses(struct response_set *responses);
int responseFromPeerP(struct response_set *responses,int peerId);
int responseFromPeer(struct response_set *responses,int peerId);
int additionalPeer(char *peer);
int readRoutingTable(struct in_addr peers[],int *peer_count,int peer_max);
int readBatmanPeerFile(char *file_path,struct in_addr peers[],int *peer_count,int peer_max);
int getBatmanPeerList(char *socket_path,struct in_addr peers[],int *peer_count,int peer_max);
int hlrDump(unsigned char *hlr,int hofs);
int peerAddress(char *did,char *sid,int flags);
int fixResponses(struct response_set *responses);
int importHlr(char *textfile);
int exportHlr(unsigned char *hlr,char *text);
int openHlrFile(char *backing_file,int size);
int runCommand(char *cmd);
int asteriskObtainGateway(char *requestor_sid,char *did,char *uri_out);
int packetOkDNA(unsigned char *packet,int len,unsigned char *transaction_id,
		struct sockaddr *recvaddr,int recvaddrlen,int parseP);
int packetOkOverlay(int interface,unsigned char *packet,int len,unsigned char *transaction_id,
		    struct sockaddr *recvaddr,int recvaddrlen,int parseP);
int prepareGateway(char *gatewayspec);
int packetSendRequest(int method,unsigned char *packet,int packet_len,int batchP,
		      unsigned char *transaction_id,struct sockaddr *recvaddr,
		      struct response_set *responses);
int readArpTable(struct in_addr peers[],int *peer_count,int peer_max);


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

  unsigned char nexthop[32];
  int nexthop_address_status;
  int nexthop_interface; /* which interface the next hop should be attempted on */

  unsigned char destination[32];
  int destination_address_status;

  unsigned char source[32];
  int source_address_status;

  /* Frame content from destination address onwards */
  int bytecount;
  unsigned char *bytes;

  /* Actual payload */
  struct overlay_buffer *payload;

  int rfs; /* remainder of frame size */
  
  long long enqueued_at;

} overlay_frame;

int overlay_frame_process(int interface,overlay_frame *f);
int overlay_frame_resolve_addresses(int interface,overlay_frame *f);


#define CRYPT_CIPHERED 1
#define CRYPT_SIGNED 2
#define CRYPT_PUBLIC 4

extern int overlayMode;
#define OVERLAY_INTERFACE_UNKNOWN 0
#define OVERLAY_INTERFACE_ETHERNET 1
#define OVERLAY_INTERFACE_WIFI 2
#define OVERLAY_INTERFACE_PACKETRADIO 3
typedef struct overlay_interface {
  char name[80];
  int fd;
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

  /* Sequence number of last tick.  Sent with announcments to help keep track of the reliability of
     getting traffic to/from us. */
  int sequence_number;

  /* Broadcast address and netmask, if known */
  struct sockaddr_in local_address;
  struct sockaddr_in broadcast_address;
  struct sockaddr_in netmask;

  /* Not necessarily the real MTU, but the largest frame size we are willing to TX on this interface.
     For radio links the actual maximum and the maximum that is likely to be delivered reliably are
     potentially two quite different values. */
  int mtu;

  /* If the interface still exists on the local machine.
     If not, it we keep track of it for a few seconds before purging it, incase of flapping, e.g.,
     due to DHCP renewal */
  int observed;
} overlay_interface;

/* Maximum interface count is rather arbitrary.
   Memory consumption is O(n) with respect to this parameter, so let's not make it too big for now.
*/
#define OVERLAY_MAX_INTERFACES 16
extern overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
extern int overlay_last_interface_number; // used to remember where a packet came from
extern unsigned int overlay_sequence_number;
extern time_t overlay_sequence_start_time;

/* Has someone sent us an abbreviation of an unknown type recently? If so remind them
   that we don't accept these.
   XXX - This method assumes bidirectional links.  We should consider sending direct
   to the perpetuator. We will deal with that in time, the main thing is that we have
   a message type that can be used for the purpose.
*/
extern int overlay_interface_repeat_abbreviation_policy[OVERLAY_MAX_INTERFACES];

/*
  For each peer we need to keep track of the routes that we know to reach it.

  We want to use static sized data structures as much as we can to keep things efficient by
  allowing computed memory address lookups instead of following linked lists and other 
  non-deterministic means.

  The tricky part of doing all this is that each interface may have a different maximum number
  of peers based on the bandwidth of the link, as we do not want mesh traffic to consume all
  available bandwidth.  In particular, we need to reserve at least enough bandwidth for one
  call.

  Related to this, if we are in a mesh larger than the per-interface limit allows, then we need to
  only track the highest-scoring peers.  This sounds simple, but how to we tell when to replace a
  low-scoring peer with another one which has a better reachability score, if we are not tracking 
  the reachability score of that node?

  The answer to this is that we track as many nodes as we can, but only announce the highest
  scoring nodes on each interface as bandwidth allows.

  This also keeps our memory usage fixed.

  XXX - At present we are setting OVERLAY_MAX_PEERS at compile time.
  With a bit of work we can change this to be a run-time option.

  Memory consumption of OVERLAY_MAX_PEERS=n is O(n^2).
  XXX We could and should improve this down the track by only monitoring the top k routes, and replacing the worst route
  option when a better one comes along.  This would get the memory usage down to O(n).

 */
#define OVERLAY_MAX_PEERS 500

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
  int length;
  int allocSize;
  int checkpointLength;
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


#define OQ_ISOCHRONOUS_VOICE 0
#define OQ_MESH_MANAGEMENT 1
#define OQ_ISOCHRONOUS_VIDEO 2
#define OQ_ORDINARY 3
#define OQ_OPPORTUNISTIC 4
#define OQ_MAX 5
extern overlay_txqueue overlay_tx[OQ_MAX];

int setReason(char *fmt, ...);
#define WHY(X) setReason("%s:%d:%s()  %s",__FILE__,__LINE__,__FUNCTION__,X)

overlay_buffer *ob_new(int size);
int ob_free(overlay_buffer *b);
int ob_checkpoint(overlay_buffer *b);
int ob_rewind(overlay_buffer *b);
int ob_limitsize(overlay_buffer *b,int bytes);
int ob_unlimitsize(overlay_buffer *b);
int ob_makespace(overlay_buffer *b,int bytes);
int ob_append_byte(overlay_buffer *b,unsigned char byte);
int ob_append_bytes(overlay_buffer *b,unsigned char *bytes,int count);
int ob_append_short(overlay_buffer *b,unsigned short v);
int ob_append_int(overlay_buffer *b,unsigned int v);
int ob_patch_rfs(overlay_buffer *b,int l);
int ob_indel_space(overlay_buffer *b,int offset,int shift);
int ob_append_rfs(overlay_buffer *b,int l);

int op_free(overlay_frame *p);

long long parse_quantity(char *q);

int overlay_interface_init(char *name,struct sockaddr_in src_addr,struct sockaddr_in broadcast,
			   struct sockaddr_in netmask,int speed_in_bits,int port,int type);
int overlay_interface_init_socket(int i,struct sockaddr_in src_addr,struct sockaddr_in broadcast,
				  struct sockaddr_in netmask);
int overlay_interface_discover();
int overlay_interface_discover();
long long overlay_time_until_next_tick();
int overlay_rx_messages();
int overlay_check_ticks();
int overlay_add_selfannouncement();
int overlay_frame_package_fmt1(overlay_frame *p,overlay_buffer *b);
int overlay_interface_args(char *arg);
int overlay_get_nexthop(unsigned char *d,unsigned char *nexthop,int *nexthoplen,
			int *interface);
int overlay_sendto(struct sockaddr_in *recipientaddr,unsigned char *bytes,int len);
int overlay_rhizome_add_advertisements(int interface_number,overlay_buffer *e);
int overlay_add_local_identity(unsigned char *s);
int overlay_address_is_local(unsigned char *s);

extern int overlay_interface_count;

#define OVERLAY_MAX_LOCAL_IDENTITIES 256
extern int overlay_local_identity_count;
extern unsigned char *overlay_local_identities[OVERLAY_MAX_LOCAL_IDENTITIES];

/* Overlay mesh packet codes */
#define OF_TYPE_BITS 0xf0
#define OF_TYPE_SELFANNOUNCE 0x10 /* BATMAN style announcement frames */
#define OF_TYPE_SELFANNOUNCE_ACK 0x20 /* BATMAN style "I saw your announcment" frames */
#define OF_TYPE_DATA 0x30 /* Ordinary data frame.
		        Upto MTU bytes of payload.
			16 bit channel/port indicator for each end. 
		        */
#define OF_TYPE_DATA_VOICE 0x40 /* Voice data frame. 
			      Limited to 255 bytes of payload. 
			      1 byte channel/port indicator for each end */
#define OF_TYPE_RHIZOME_ADVERT 0x50 /* Advertisment of file availability via Rhizome */
#define OF_TYPE_PLEASEEXPLAIN 0x60 /* Request for resolution of an abbreviated address */
#define OF_TYPE_NODEANNOUNCE 0x70
#define OF_TYPE_RESERVED_08 0x80
#define OF_TYPE_RESERVED_09 0x90
#define OF_TYPE_RESERVED_0a 0xa0
#define OF_TYPE_RESERVED_0b 0xb0
#define OF_TYPE_RESERVED_0c 0xc0
#define OF_TYPE_RESERVED_0d 0xd0
#define OF_TYPE_EXTENDED12 0xe0 /* modifier bits and next byte provide 12 bits extended format
				   (for future expansion, just allows us to skip the frame) */
#define OF_TYPE_EXTENDED20 0xf0 /* modifier bits and next 2 bytes provide 20 bits extended format
				 (for future expansion, just allows us to skip the frame) */
/* Flags used to control the interpretation of the resolved type field */
#define OF_TYPE_FLAG_BITS 0xf0000000
#define OF_TYPE_FLAG_NORMAL 0x0
#define OF_TYPE_FLAG_E12 0x10000000
#define OF_TYPE_FLAG_E20 0x20000000

/* Modifiers that indicate the disposition of the frame */
#define OF_MODIFIER_BITS 0x0f

/* Crypto/security options */
#define OF_CRYPTO_BITS 0x0c
#define OF_CRYPTO_NONE 0x00
#define OF_CRYPTO_CIPHERED 0x04 /* Encrypted frame */
#define OF_CRYPTO_SIGNED 0x08   /* Encrypted and Digitally signed frame */
#define OF_CRYPTO_PARANOID 0x0c /* Encrypted and digitally signed frame, with final destination address also encrypted. */

/* Data compression */
#define OF_COMPRESS_BITS 0x03
#define OF_COMPRESS_NONE 0x00
#define OF_COMPRESS_GZIP 0x01     /* Frame compressed with gzip */
#define OF_COMPRESS_BZIP2 0x02    /* bzip2 */
#define OF_COMPRESS_RESERVED 0x03 /* Reserved for another compression system */

#define OVERLAY_ADDRESS_CACHE_SIZE 1024
int overlay_abbreviate_address(unsigned char *in,unsigned char *out,int *ofs);
int overlay_abbreviate_append_address(overlay_buffer *b,unsigned char *a);

int overlay_abbreviate_expand_address(int interface,unsigned char *in,int *inofs,unsigned char *out,int *ofs);
int overlay_abbreviate_cache_address(unsigned char *sid);
int overlay_abbreviate_cache_lookup(unsigned char *in,unsigned char *out,int *ofs,
				    int prefix_bytes,int index_bytes);
int overlay_abbreviate_remember_index(int index_byte_count,unsigned char *in,unsigned char *index_bytes);
extern int overlay_abbreviate_repeat_policy;
int overlay_abbreviate_set_most_recent_address(unsigned char *in);

/* Return codes for resolution of abbreviated addressses */
#define OA_UNINITIALISED 0 /* Nothing has been written into the field */
#define OA_RESOLVED 1      /* We expanded the abbreviation successfully */
#define OA_PLEASEEXPLAIN 2 /* We need the sender to explain their abbreviation */
#define OA_UNSUPPORTED 3   /* We cannot expand the abbreviation as we do not understand this code */

/* Codes used to describe abbreviated addresses.
   Values 0x10 - 0xff are the first byte of, and implicit indicators of addresses written in full */
#define OA_CODE_SELF 0x00
#define OA_CODE_INDEX 0x01
#define OA_CODE_02 0x02
#define OA_CODE_PREVIOUS 0x03
#define OA_CODE_04 0x04
#define OA_CODE_PREFIX3 0x05
#define OA_CODE_PREFIX7 0x06
#define OA_CODE_PREFIX11 0x07
#define OA_CODE_FULL_INDEX1 0x08
#define OA_CODE_PREFIX3_INDEX1 0x09
#define OA_CODE_PREFIX7_INDEX1 0x0a
#define OA_CODE_PREFIX11_INDEX1 0x0b
#define OA_CODE_0C 0x0c
#define OA_CODE_PREFIX11_INDEX2 0x0d
#define OA_CODE_FULL_INDEX2 0x0e
/* The TTL field in a frame is used to differentiate between link-local and wide-area broadcasts */
#define OA_CODE_BROADCAST 0x0f

#define RFS_PLUS250 0xfa
#define RFS_PLUS456 0xfb
#define RFS_PLUS762 0xfc
#define RFS_PLUS1018 0xfd
#define RFS_PLUS1274 0xfe
#define RFS_3BYTE 0xff
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
  unsigned char receiver_interface;
  unsigned char valid;
} overlay_neighbour_observation;

#define OVERLAY_SENDER_PREFIX_LENGTH 12
typedef struct overlay_node_observation {
  unsigned char observed_score; /* serves as validty check also */
  unsigned char corrected_score;
  unsigned char gateways_en_route;
  unsigned char RESERVED; /* for alignment */
  long long rx_time;
  unsigned char sender_prefix[OVERLAY_SENDER_PREFIX_LENGTH];
} overlay_node_observation;

/* Keep track of last 32 observations of a node.
   Hopefully this is enough, if not, we will increase.
   To keep the requirement down we will collate contigious neighbour observations on each interface.
   For node observations we can just replace old observations with new ones. 
*/
#define OVERLAY_MAX_OBSERVATIONS 32

typedef struct overlay_node {
  unsigned char sid[SID_SIZE];
  int neighbour_id; /* 0=not a neighbour */
  int most_recent_observation_id;
  int best_link_score;
  int best_observation;
  unsigned int last_first_hand_observation_time_sec;
  long long last_observation_time_ms;
  /* When did we last advertise this node on each interface, and what score
     did we advertise? */
  long long most_recent_advertisment[OVERLAY_MAX_INTERFACES];
  unsigned char most_recent_advertised_score[OVERLAY_MAX_INTERFACES];
  overlay_node_observation observations[OVERLAY_MAX_OBSERVATIONS];
} overlay_node;

typedef struct overlay_neighbour {
  long long last_observation_time_ms;
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
int overlay_route_saw_selfannounce_ack(int interface,overlay_frame *f,long long now);
int overlay_route_recalc_node_metrics(overlay_node *n,long long now);
int overlay_route_recalc_neighbour_metrics(overlay_neighbour *n,long long now);
int overlay_route_saw_selfannounce(int interface,overlay_frame *f,long long now);
overlay_node *overlay_route_find_node(unsigned char *sid,int createP);
unsigned int overlay_route_hash_sid(unsigned char *sid);
int overlay_route_init(int mb_ram);
overlay_neighbour *overlay_route_get_neighbour_structure(unsigned char *packed_sid, 
							 int createP);
unsigned char *overlay_get_my_sid();
int overlay_frame_set_me_as_source(overlay_frame *f);
int overlay_frame_set_neighbour_as_source(overlay_frame *f,overlay_neighbour *n);
int overlay_frame_set_neighbour_as_destination(overlay_frame *f,overlay_neighbour *n);
int overlay_update_sequence_number();
int packetEncipher(unsigned char *packet,int maxlen,int *len,int cryptoflags);
int overlayServerMode();
int overlay_payload_enqueue(int q,overlay_frame *p);
long long overlay_time_in_ms();
int overlay_abbreviate_lookup_sender_id();
int ob_dump(overlay_buffer *b,char *desc);
unsigned int ob_get_int(overlay_buffer *b,int offset);
char *overlay_render_sid(unsigned char *sid);
int overlay_route_record_link(long long now,unsigned char *to,unsigned char *via,unsigned int timestamp,int score,int gateways_en_route);
int overlay_route_dump();
int overlay_route_tick();
int overlay_route_tick_neighbour(int neighbour_id,long long now);
int overlay_route_tick_node(int bin,int slot,long long now);
int overlay_route_add_advertisements(int interface,overlay_buffer *e);
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
int rhizome_server_poll();

#include "nacl.h"


#define DEBUG_OVERLAYINTERFACES 2
#define DEBUG_PACKETXFER 1
#define DEBUG_VERBOSE 4
#define DEBUG_VERBOSE_IO 8
#define DEBUG_PEERS 16
#define DEBUG_DNARESPONSES 32
#define DEBUG_DNAREQUESTS 64
#define DEBUG_SIMULATION 128
#define DEBUG_DNAVARS 256
#define DEBUG_PACKETFORMATS 512
#define DEBUG_GATEWAY 1024
#define DEBUG_HLR 2048
#define DEBUG_IO 4096
#define DEBUG_OVERLAYFRAMES 8192
#define DEBUG_OVERLAYABBREVIATIONS 16384
#define DEBUG_OVERLAYROUTING 32768
#define DEBUG_SECURITY 65536
#define DEBUG_RHIZOME 131072
#define DEBUG_OVERLAYROUTEMONITOR 262144
#define DEBUG_QUEUES 524288
#define DEBUG_BROADCASTS 1048576

int serval_packetvisualise(FILE *f,char *message,unsigned char *packet,int plen);

int overlay_broadcast_drop_check(unsigned char *a);
int overlay_address_is_broadcast(unsigned char *a);
int overlay_broadcast_generate_address(unsigned char *a);
int overlay_abbreviate_unset_current_sender();

