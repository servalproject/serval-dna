/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2012 Paul Gardner-Stephen 

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

#include <string.h>
#include "serval.h"
#include "assert.h"
#include "log.h"
#include "os.h"

/*
  Generate a nonce that is "asymptotically almost surely" never reused, according
  to the mathematical meaning of that phrase.  Basically, we want the chance of
  nonce reuse to be 1 in 2^(8*length), and length to be sufficiently large.
  The NaCl primitives that require a nonce use 24 bytes, so the probability of
  nonce reuse becomes 1 in 2^(8*24) = 1 in 2^192 < 1 in 10^57.  There are about
  10^57 atoms in the solar system.  The easiest way to acheive this is to pick
  a random initial nonce, and then monotonically increase it each time we need
  a new nonce.  The random starting point gives us safety for the first nonce
  after the process begins, and monotonic increase makes sure we never reuse a
  value, and will never reuse a previous value for a VERY long time. The only 
  downside is that it lets an attacker know how many packets we have sent in
  some interval.  We could mix in the current time or similar to mitigate that.
*/

int nonce_initialised=0;
long long nonce_counter=0;
long long nonce_lasttime=0;
long long nonce_lasttimedelta=0;
unsigned char nonce_value[24];
  
void nonce_add(long long v)
{
  int i;
  unsigned char new_nonce[24];

  assert(v>0);
  for(i=0;i<24;i++) new_nonce[i]=0;

  for(i=0;i<24;i++) {
    int nv=nonce_value[23-i]+new_nonce[23-i]+(v&0xff);
    new_nonce[23-i]=nv&0xff;
    if (i<(24-1)) new_nonce[23-(i+1)]=nv>>8;
    v=v>>8;
  }
  
  assert(memcmp(new_nonce,nonce_value,24)>0);
  bcopy(new_nonce,nonce_value,24);
  return;
}

int getuniquenonce(unsigned char *nonce,int length)
{
  IN();
  assert(length==24);
  long long now=gettime_ms();

  if (!nonce_initialised) {
    if (urandombytes(nonce_value,24)) {
      WHYF("Could not obtain initial nonce: urandombytes() failed.");
      RETURN(-1);
    }
    nonce_initialised=1;
    nonce_lasttime=now;
  }

  long long delta=now-nonce_lasttime;
  if (delta<nonce_lasttimedelta) {
    // time has gone backwards, so make sure that our delta keeps increasing
    // so that we never reuse a nonce
    nonce_lasttime-=(nonce_lasttimedelta-delta+1);
  }

  delta=now-nonce_lasttime;
  assert(delta>=nonce_lasttimedelta);
  nonce_counter++;
  assert(nonce_counter>0);

  nonce_lasttime=now;
  nonce_lasttimedelta=delta;

  nonce_add(1+delta);

  bcopy(&nonce_value,nonce,24);
  //  dump("nonce",nonce,24);
  RETURN(0);
}
