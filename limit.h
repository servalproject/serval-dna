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

#ifndef __SERVAL_DNA__LIMIT_H
#define __SERVAL_DNA__LIMIT_H

struct limit_state{
  uint32_t rate_micro_seconds;
  // length of time for a burst
  time_ms_t burst_length;
  // how many in a burst
  int burst_size;
  // how many have we sent in this burst so far
  int sent;
  // when can we allow another burst
  time_ms_t next_interval;
};

time_ms_t limit_next_allowed(struct limit_state *state);
int limit_is_allowed(struct limit_state *state);
int limit_init(struct limit_state *state, uint32_t rate_micro_seconds);

#endif