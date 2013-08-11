/*
 Copyright (C) 2012 Serval Project.

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
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 02110-1301, USA.
 */

#ifndef __SERVALD_PARALLEL_H
#define __SERVALD_PARALLEL_H

#include <pthread.h>
#include "serval.h"
#include "rhizome.h"

extern int multithread;

extern pthread_t main_thread;
extern pthread_t rhizome_thread;

#define ASSERT_THREAD(P)\
  if (multithread && pthread_self() != (P)) {\
    FATAL("Not called from the expected thread");\
  }

/* rhizome thread function */
void *rhizome_run(void *arg);

/* schedule a function call with the specified arguments on fdq */
void post_runnable(ALARM_FUNCP function, void *arg, fdqueue *fdq);

/* following structs are used for passing args from one thread to another */

/* *alarm->context is an overlay_mdp_frame */
void overlay_mdp_dispatch_alarm(struct sched_ent *alarm);

/* overlay_rhizome_saw_advertisements argument */
struct orsa_arg {
  int id;
  struct overlay_buffer *payload;
  unsigned char src_sid[SID_SIZE];
  int src_reachable;
  int use_new_sync_protocol;
  struct sockaddr_in recvaddr;
  time_ms_t now;
};

/* *alarm->context is a struct orsa_arg */
void overlay_rhizome_saw_advertisements_alarm(struct sched_ent *alarm);

/* *alarm->context is a struct overlay_buffer (payload) */
void overlay_payload_enqueue_alarm(struct sched_ent *alarm);

/* rhizome_received_content argument */
struct rrc_arg {
  int type;
  unsigned char bidprefix[16];
  uint64_t version;
  uint64_t offset;
  int count;
  unsigned char* bytes;
};

/* *alarm->context is a struct rrc_arg */
void rhizome_received_content_alarm(struct sched_ent *alarm);

/* rhizome_mdp_send_block argument */
struct rmsb_arg {
  int unicast;
  unsigned char unicast_dest_sid[SID_SIZE];
  unsigned char bid[RHIZOME_MANIFEST_ID_BYTES];
  uint64_t version;
  uint64_t file_offset;
  uint32_t bitmap;
  uint16_t block_length;
};

/* *alarm->context is a struct rmsb_arg */
void rhizome_mdp_send_block_alarm(struct sched_ent *alarm);

/* rhizome_advertise_manifest_alarm argument */
struct ram_arg {
  int manifest_all_bytes;
  unsigned char manifestdata[MAX_MANIFEST_BYTES];
};

/* *alarm->context is a struct ram_arg */
void rhizome_advertise_manifest_alarm(struct sched_ent *alarm);

/* *alarm->context is a char * (id_hex) */
void rhizome_retrieve_and_advertise_manifest_alarm(struct sched_ent *alarm);

#endif
