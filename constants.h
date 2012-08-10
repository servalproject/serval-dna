/*
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

#ifndef __SERVALD_CONSTANTS_H
#define __SERVALD_CONSTANTS_H

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
#define DID_MINSIZE 5
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

#define SID_STRLEN (SID_SIZE*2)

/* Array of variables that can be placed in an MPHLR */
#define VAR_EOR 0x00
#define VAR_CREATETIME 0x01
#define VAR_CREATOR 0x02
#define VAR_REVISION 0x03
#define VAR_REVISOR 0x04
#define VAR_PIN 0x05
#define VAR_VOICESIG 0x08
#define VAR_HLRMASTER 0x0f
#define VAR_NAME 0x10
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
#define ACTION_RECVTTL 0xfd
#define ACTION_PAD 0xfe
#define ACTION_EOT 0xff

#define OVERLAY_MAX_INTERFACES 16

#define CRYPT_CIPHERED 1
#define CRYPT_SIGNED 2
#define CRYPT_PUBLIC 4

#define OVERLAY_INTERFACE_UNKNOWN 0
#define OVERLAY_INTERFACE_ETHERNET 1
#define OVERLAY_INTERFACE_WIFI 2
#define OVERLAY_INTERFACE_PACKETRADIO 3

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

#define OQ_ISOCHRONOUS_VOICE 0
#define OQ_MESH_MANAGEMENT 1
#define OQ_ISOCHRONOUS_VIDEO 2
#define OQ_ORDINARY 3
#define OQ_OPPORTUNISTIC 4
#define OQ_MAX 5

#define OVERLAY_MAX_LOCAL_IDENTITIES 256

/* Overlay mesh packet codes */
#define OF_TYPE_BITS 0xf0
#define OF_TYPE_SELFANNOUNCE 0x10 /* BATMAN style announcement frames */
#define OF_TYPE_SELFANNOUNCE_ACK 0x20 /* BATMAN style "I saw your announcment" frames */
#define OF_TYPE_DATA 0x30 /* Ordinary data frame.
		        Upto MTU bytes of payload.
			32 bit channel/port indicator for each end. 
		        */
#define OF_TYPE_DATA_VOICE 0x40 /* Voice data frame. 
			      Limited to 255 bytes of payload. 
			      1 byte channel/port indicator for each end */
#define OF_TYPE_RHIZOME_ADVERT 0x50 /* Advertisment of file availability via Rhizome */
#define OF_TYPE_PLEASEEXPLAIN 0x60 /* Request for resolution of an abbreviated address */
#define OF_TYPE_NODEANNOUNCE 0x70
#define OF_TYPE_IDENTITYENQUIRY 0x80
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
#define OF_CRYPTO_SIGNED 0x08   /* signed frame */
/* The following was previously considered, but is not being implemented at this
   time.
   #define OF_CRYPTO_PARANOID 0x0c Encrypted and digitally signed frame, with final destination address also encrypted. */

/* Data compression */
#define OF_COMPRESS_BITS 0x03
#define OF_COMPRESS_NONE 0x00
#define OF_COMPRESS_GZIP 0x01     /* Frame compressed with gzip */
#define OF_COMPRESS_BZIP2 0x02    /* bzip2 */
#define OF_COMPRESS_RESERVED 0x03 /* Reserved for another compression system */

#define OVERLAY_ADDRESS_CACHE_SIZE 1024

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

#define COMPUTE_RFS_LENGTH -1

#define OVERLAY_SENDER_PREFIX_LENGTH 12

/* Keep track of last 32 observations of a node.
   Hopefully this is enough, if not, we will increase.
   To keep the requirement down we will collate contigious neighbour observations on each interface.
   For node observations we can just replace old observations with new ones. 
*/
#define OVERLAY_MAX_OBSERVATIONS 32

/* bitmask values for monitor_tell_clients */
#define MONITOR_VOMP (1<<0)
#define MONITOR_RHIZOME (1<<1)
#define MONITOR_PEERS (1<<2)
#define MONITOR_DNAHELPER (1<<3)

#define MAX_SIGNATURES 16

#define IDENTITY_VERIFIED (1<<0)
#define IDENTITY_VERIFIEDBYME (1<<1)
#define IDENTITY_NOTVERIFIED (1<<2)
  /* The value below is for caching negative results */
#define IDENTITY_UNKNOWN (1<<3)

#define MDP_PORT_ECHO 0x00000007
#define MDP_PORT_KEYMAPREQUEST 0x10000001
#define MDP_PORT_VOMP 0x10000002
#define MDP_PORT_DNALOOKUP 0x10000003

#define MDP_TYPE_MASK 0xff
#define MDP_FLAG_MASK 0xff00
#define MDP_FORCE 0x0100
#define MDP_NOCRYPT 0x0200
#define MDP_NOSIGN 0x0400
#define MDP_MTU 2000

#define MDP_TX 1
#define MDP_BIND 3
#define MDP_ERROR 4
#define MDP_GETADDRS 5
#define MDP_ADDRLIST 6

// These are back-compatible with the old values of 'mode' when it was 'selfP'
#define MDP_ADDRLIST_MODE_ROUTABLE_PEERS 0
#define MDP_ADDRLIST_MODE_SELF 1
#define MDP_ADDRLIST_MODE_ALL_PEERS 2

/* 59*32 < (MDP_MTU-100), so up to 59 SIDs in a single reply.
   Multiple replies can be used to respond with more. */
#define MDP_MAX_SID_REQUEST 59

#define MDP_VOMPEVENT 7
#define VOMP_MAX_CALLS 16
/* Maximum amount of audio to cram into a VoMP audio packet.
   More lets us include preemptive retransmissions.
   Less reduces the chance of packets getting lost, and reduces
   the bandwidth used. */
#define VOMP_STUFF_BYTES 800

/* For  overlay_mdp_vompevent->flags */
#define VOMPEVENT_RINGING (1<<0)
#define VOMPEVENT_CALLENDED (1<<1)
#define VOMPEVENT_CALLREJECT (1<<2)
#define VOMPEVENT_HANGUP VOMPEVENT_CALLREJECT
#define VOMPEVENT_TIMEOUT (1<<3)
#define VOMPEVENT_ERROR (1<<4)
#define VOMPEVENT_AUDIOSTREAMING (1<<5)
#define VOMPEVENT_DIAL (1<<6)
#define VOMPEVENT_REGISTERINTEREST (1<<7)
#define VOMPEVENT_WITHDRAWINTEREST (1<<8)
#define VOMPEVENT_CALLCREATED (1<<9)
#define VOMPEVENT_PICKUP (1<<10)
#define VOMPEVENT_CALLINFO (1<<11)
#define VOMPEVENT_AUDIOPACKET (1<<12)

#define MAX_AUDIO_BYTES 1024
#define MDP_NODEINFO 8
#define MDP_GOODBYE 9
#define MDP_AWAITREPLY 9999

#define VOMP_SESSION_MASK 0xffffff
/* max number of recent samples to cram into a VoMP frame as well as the current
   frame of audio (preemptive audio retransmission) */
#define VOMP_MAX_RECENT_SAMPLES 2

#define VOMP_CODEC_NONE 0x00
#define VOMP_CODEC_CODEC2_2400 0x01
#define VOMP_CODEC_CODEC2_1400 0x02
#define VOMP_CODEC_GSMHALF 0x03
#define VOMP_CODEC_GSMFULL 0x04
#define VOMP_CODEC_16SIGNED 0x05
#define VOMP_CODEC_8ULAW 0x06
#define VOMP_CODEC_8ALAW 0x07
#define VOMP_CODEC_PCM 0x08
#define VOMP_CODEC_DTMF 0x80
#define VOMP_CODEC_ENGAGED 0x81
#define VOMP_CODEC_ONHOLD 0x82
#define VOMP_CODEC_CALLERID 0x83
#define VOMP_CODEC_CODECSISUPPORT 0xfe
#define VOMP_CODEC_CHANGEYOURCODECTO 0xff

/* in milliseconds of inactivity */
// 20 seconds to start ringing
#define VOMP_CALL_DIAL_TIMEOUT 5000
// 60 seconds to answer
#define VOMP_CALL_RING_TIMEOUT 60000
// 2 minutes of zero network traffic
#define VOMP_CALL_NETWORK_TIMEOUT 120000
// force state packet interval
#define VOMP_CALL_STATUS_INTERVAL 1000

#define DEFAULT_MONITOR_SOCKET_NAME "org.servalproject.servald.monitor.socket"
#define DEFAULT_MDP_SOCKET_NAME "org.servalproject.servald.mdp.socket"

#endif // __SERVALD_CONSTANTS_H
