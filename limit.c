/*
Copyright (C) 2014 Serval Project Inc.
 
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

#include <unistd.h>
#include "os.h"
#include "limit.h"

#define MIN_BURST_LENGTH 5000

static void update_limit_state(struct limit_state *state, time_ms_t now){
  if (state->next_interval > now || state->burst_size==0){
    return;
  }
  
  if (state->next_interval + state->burst_length>now)
    state->next_interval+=state->burst_length;
  else
    state->next_interval=now + state->burst_length;
  
  state->sent = 0;
}

/* When should we next allow this thing to occur? */
time_ms_t limit_next_allowed(struct limit_state *state){
  time_ms_t now = gettime_ms();
  if (!state->burst_size)
    return now;
  update_limit_state(state, now);
  
  if (state->sent < state->burst_size)
    return now;
  return state->next_interval;
}

/* Can we do this now? if so, track it */
int limit_is_allowed(struct limit_state *state){
  time_ms_t now = gettime_ms();
  if (!state->burst_size)
    return 0;
  update_limit_state(state, now);
  if (state->sent >= state->burst_size){
    return -1;
  }
  state->sent ++;
  return 0;
}

/* Initialise burst size and length based on the number we can do in one MIN_BURST */
int limit_init(struct limit_state *state, uint32_t rate_micro_seconds){
  state->rate_micro_seconds = rate_micro_seconds;
  if (rate_micro_seconds==0){
    state->burst_size=0;
    state->burst_length=0;
  }else{
    state->burst_size = (MIN_BURST_LENGTH / rate_micro_seconds)+1;
    state->burst_length = (state->burst_size * rate_micro_seconds) / 1000.0;
  }
  return 0;
}

