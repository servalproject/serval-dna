/*
Copyright (C) 2012-2015 Serval Project Inc.

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

#ifndef __SERVAL_DNA__CONSTANTS_H
#define __SERVAL_DNA__CONSTANTS_H

// UDP port numbers for various Serval services
#define PORT_DNA 4110

// TCP port numbers for various Serval services
#define HTTPD_PORT_DEFAULT 4110
#define HTTPD_PORT_RANGE 100

#define OVERLAY_MAX_INTERFACES 16

#define CRYPT_CIPHERED 1
#define CRYPT_SIGNED 2
#define CRYPT_PUBLIC 4

// Interface types for matching or default config
// Note that the numeric value is also used to choose the best link
#define OVERLAY_INTERFACE_ETHERNET 1
#define OVERLAY_INTERFACE_WIFI 2
#define OVERLAY_INTERFACE_OTHER 3
#define OVERLAY_INTERFACE_UNKNOWN 4
#define OVERLAY_INTERFACE_ANY 5
#define OVERLAY_INTERFACE_PACKETRADIO 6

#define RADIO_TYPE_RFD900 0
#define RADIO_TYPE_RFM69 1

#define OQ_ISOCHRONOUS_VOICE 0
#define OQ_MESH_MANAGEMENT 1
#define OQ_ISOCHRONOUS_VIDEO 2
#define OQ_ORDINARY 3
#define OQ_OPPORTUNISTIC 4
#define OQ_MAX 5

#define OVERLAY_MAX_LOCAL_IDENTITIES 256

/* All of these types should be considered deprecated. Processing code should migrate to well known MDP port numbers */
/* Overlay mesh packet codes */
#define OF_TYPE_SELFANNOUNCE_ACK 0x20
#define OF_TYPE_DATA 0x30 /* Ordinary data frame.
		        Upto MTU bytes of payload.
			32 bit channel/port indicator for each end. 
		        */
#define OF_TYPE_RHIZOME_ADVERT 0x50 /* Advertisment of file availability via Rhizome */
#define OF_TYPE_PLEASEEXPLAIN 0x60 /* Request for resolution of an abbreviated address */

#define PAYLOAD_FLAG_SENDER_SAME (1<<0)
#define PAYLOAD_FLAG_TO_BROADCAST (1<<1)
#define PAYLOAD_FLAG_ONE_HOP (1<<2)
#define PAYLOAD_FLAG_CIPHERED (1<<4)
#define PAYLOAD_FLAG_SIGNED (1<<5)
#define PAYLOAD_FLAG_ACK_SOON (1<<6)

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
#define MONITOR_LINKS (1<<4)
#define MONITOR_QUIT_ON_DISCONNECT (1<<5)
#define MONITOR_INTERFACE (1<<6)

#define MAX_SIGNATURES 16

#define MDP_PORT_KEYMAPREQUEST 1
#define MDP_PORT_LINKSTATE 2
#define MDP_PORT_STUNREQ 4
#define MDP_PORT_STUN 5
#define MDP_PORT_PROBE 6
#define MDP_PORT_ECHO 7
#define MDP_PORT_TRACE 8
#define MDP_PORT_DNALOOKUP 10
#define MDP_PORT_SERVICE_DISCOVERY 11
#define MDP_PORT_VOMP 12
#define MDP_PORT_RHIZOME_REQUEST 13
#define MDP_PORT_RHIZOME_RESPONSE 14
#define MDP_PORT_DIRECTORY 15
#define MDP_PORT_RHIZOME_MANIFEST_REQUEST 16
#define MDP_PORT_RHIZOME_SYNC 17
#define MDP_PORT_RHIZOME_SYNC_KEYS 18
#define MDP_PORT_NOREPLY 0x3f

#define MDP_TYPE_MASK 0xff
#define MDP_FLAG_MASK 0xff00
#define MDP_FORCE 0x0100
#define MDP_NOCRYPT 0x0200
#define MDP_NOSIGN 0x0400
#define MDP_OVERLAY_MTU 1200
// worst case packet header overheads for port encoding and crypto envelopes (approx);
#define MDP_MTU (MDP_OVERLAY_MTU - 40)

#define MDP_TX 1
#define MDP_BIND 3
#define MDP_ERROR 4
#define MDP_GETADDRS 5
#define MDP_ADDRLIST 6
#define MDP_ROUTING_TABLE 7
#define MDP_GOODBYE 9
#define MDP_SCAN 10

// These are back-compatible with the old values of 'mode' when it was 'selfP'
#define MDP_ADDRLIST_MODE_ROUTABLE_PEERS 0
#define MDP_ADDRLIST_MODE_SELF 1
#define MDP_ADDRLIST_MODE_ALL_PEERS 2

/* 59*32 < (MDP_MTU-100), so up to 59 SIDs in a single reply.
   Multiple replies can be used to respond with more. */
#define MDP_MAX_SID_REQUEST 59


#define MSP_PAYLOAD_PREAMBLE_SIZE  5
#define MSP_MESSAGE_SIZE           1024
//should be something like this...; (MDP_MTU - MSP_PAYLOAD_PREAMBLE_SIZE)

#define MSP_STATE_UNINITIALISED     (0)
#define MSP_STATE_LISTENING         (1<<0)
#define MSP_STATE_RECEIVED_DATA     (1<<1)
#define MSP_STATE_RECEIVED_PACKET   (1<<2)
#define MSP_STATE_SHUTDOWN_LOCAL    (1<<3)
#define MSP_STATE_SHUTDOWN_REMOTE   (1<<4)
// this connection is about to be free'd, release any other resources or references to the state
#define MSP_STATE_CLOSED            (1<<5)
// something has gone wrong somewhere
#define MSP_STATE_ERROR             (1<<6)
// is there space for sending more data?
#define MSP_STATE_DATAOUT           (1<<7)
#define MSP_STATE_STOPPED           (1<<8)

// stream timeout
#define MSP_TIMEOUT 10000


/* Maximum amount of audio to cram into a VoMP audio packet.
   More lets us include preemptive retransmissions.
   Less reduces the chance of packets getting lost, and reduces
   the bandwidth used. */
#define VOMP_STUFF_BYTES 800

#define MAX_AUDIO_BYTES 1024
#define MDP_AWAITREPLY 9999

// codec's with well defined parameters
#define VOMP_CODEC_16SIGNED 0x01
#define VOMP_CODEC_ULAW 0x02
#define VOMP_CODEC_ALAW 0x03
#define VOMP_CODEC_GSM 0x04
#define VOMP_CODEC_CODEC2_1200 0x05
#define VOMP_CODEC_CODEC2_3200 0x06
#define VOMP_CODEC_OPUS 0x07

// other out of band signals, probably shouldn't be codecs
#define VOMP_CODEC_DTMF 0x20
#define VOMP_CODEC_TEXT 0x21

// Note, Don't add codec's we aren't using yet

#define CODEC_FLAGS_LENGTH 32

// force state packet interval
#define VOMP_CALL_STATUS_INTERVAL 1000

// mdp client interface
#define SOCK_EXT 0xFE
// dummy file interface
#define SOCK_FILE 0xFF
#define SOCK_UNSPECIFIED 0

#define ENCAP_OVERLAY 1
#define ENCAP_SINGLE 2

// numbers chosen to not conflict with KEYTYPE flags
#define UNLOCK_REQUEST (0xF0)
#define UNLOCK_CHALLENGE (0xF1)
#define UNLOCK_RESPONSE (0xF2)

#endif // __SERVAL_DNA__CONSTANTS_H
