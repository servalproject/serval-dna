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

#define NELS(a) (sizeof (a) / sizeof *(a))

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
#define SID_SIZE 32 // == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES
#define SAS_SIZE 32 // == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES
#define DID_MINSIZE 5
#define DID_MAXSIZE 32

#define SID_STRLEN (SID_SIZE*2)

#define OVERLAY_MAX_INTERFACES 16

#define CRYPT_CIPHERED 1
#define CRYPT_SIGNED 2
#define CRYPT_PUBLIC 4

#define OVERLAY_INTERFACE_UNKNOWN 0
#define OVERLAY_INTERFACE_ETHERNET 1
#define OVERLAY_INTERFACE_WIFI 2
#define OVERLAY_INTERFACE_PACKETRADIO 3

#define OQ_ISOCHRONOUS_VOICE 0
#define OQ_MESH_MANAGEMENT 1
#define OQ_ISOCHRONOUS_VIDEO 2
#define OQ_ORDINARY 3
#define OQ_OPPORTUNISTIC 4
#define OQ_MAX 5

#define OVERLAY_MAX_LOCAL_IDENTITIES 256

/* All of these types should be considered deprecated. Processing code should migrate to well known MDP port numbers */
/* Overlay mesh packet codes */
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

#define PAYLOAD_FLAG_SENDER_SAME (1<<0)
#define PAYLOAD_FLAG_TO_BROADCAST (1<<1)
#define PAYLOAD_FLAG_ONE_HOP (1<<2)
#define PAYLOAD_FLAG_LONG_PAYLOAD (1<<3)
#define PAYLOAD_FLAG_CIPHERED (1<<4)
#define PAYLOAD_FLAG_SIGNED (1<<5)

/* Time-to-live is a 'uint5_t'.
 */
#define PAYLOAD_TTL_MAX (31)
#define PAYLOAD_TTL_DEFAULT (31)

// return codes for parsing mdp packet headers
#define HEADER_PROCESS 1
#define HEADER_FORWARD 2

// this can be removed once all overlay messages have been turned into mdp payloads
#define PAYLOAD_FLAG_LEGACY_TYPE (1<<7)

/* Crypto/security options */
#define OF_CRYPTO_NONE 0x00
#define OF_CRYPTO_CIPHERED PAYLOAD_FLAG_CIPHERED /* Encrypted frame */
#define OF_CRYPTO_SIGNED PAYLOAD_FLAG_SIGNED   /* signed frame */

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

#define MDP_PORT_KEYMAPREQUEST 1
#define MDP_PORT_STUNREQ 4
#define MDP_PORT_STUN 5
#define MDP_PORT_PROBE 6
#define MDP_PORT_ECHO 7
#define MDP_PORT_TRACE 8
#define MDP_PORT_DNALOOKUP 10
#define MDP_PORT_VOMP 12
#define MDP_PORT_RHIZOME_REQUEST 13
#define MDP_PORT_RHIZOME_RESPONSE 14
#define MDP_PORT_DIRECTORY 15
#define MDP_PORT_RHIZOME_MANIFEST_REQUEST 16
#define MDP_PORT_NOREPLY 0x3f

#define MDP_TYPE_MASK 0xff
#define MDP_FLAG_MASK 0xff00
#define MDP_FORCE 0x0100
#define MDP_NOCRYPT 0x0200
#define MDP_NOSIGN 0x0400
#define MDP_MTU 1200

#define MDP_TX 1
#define MDP_BIND 3
#define MDP_ERROR 4
#define MDP_GETADDRS 5
#define MDP_ADDRLIST 6
#define MDP_ROUTING_TABLE 7
#define MDP_NODEINFO 8
#define MDP_GOODBYE 9
#define MDP_SCAN 10

// These are back-compatible with the old values of 'mode' when it was 'selfP'
#define MDP_ADDRLIST_MODE_ROUTABLE_PEERS 0
#define MDP_ADDRLIST_MODE_SELF 1
#define MDP_ADDRLIST_MODE_ALL_PEERS 2

/* 59*32 < (MDP_MTU-100), so up to 59 SIDs in a single reply.
   Multiple replies can be used to respond with more. */
#define MDP_MAX_SID_REQUEST 59

/* Maximum amount of audio to cram into a VoMP audio packet.
   More lets us include preemptive retransmissions.
   Less reduces the chance of packets getting lost, and reduces
   the bandwidth used. */
#define VOMP_STUFF_BYTES 800

#define MAX_AUDIO_BYTES 1024
#define MDP_AWAITREPLY 9999

/* max number of recent samples to cram into a VoMP frame as well as the current
   frame of audio (preemptive audio retransmission) */
#define VOMP_MAX_RECENT_SAMPLES 2

// codec's with well defined parameters
#define VOMP_CODEC_16SIGNED 0x01
#define VOMP_CODEC_ULAW 0x02
#define VOMP_CODEC_ALAW 0x03
#define VOMP_CODEC_GSM 0x04

// other out of band signals, probably shouldn't be codecs
#define VOMP_CODEC_DTMF 0x20
#define VOMP_CODEC_TEXT 0x21

// Note, Don't add codec's we aren't using yet

#define CODEC_FLAGS_LENGTH 32

/* in milliseconds of inactivity */
// 20 seconds to start ringing
#define VOMP_CALL_DIAL_TIMEOUT 15000
// 60 seconds to answer
#define VOMP_CALL_RING_TIMEOUT 60000
// 2 minutes of zero network traffic
#define VOMP_CALL_NETWORK_TIMEOUT 120000
// force state packet interval
#define VOMP_CALL_STATUS_INTERVAL 1000

#define DEFAULT_MONITOR_SOCKET_NAME "org.servalproject.servald.monitor.socket"
#define DEFAULT_MDP_SOCKET_NAME "org.servalproject.servald.mdp.socket"

#define SOCK_FILE 0xFF
#define SOCK_UNSPECIFIED 0

#define ENCAP_OVERLAY 1
#define ENCAP_SINGLE 2

#endif // __SERVALD_CONSTANTS_H
