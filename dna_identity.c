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

/*
  This module is responsible for managing the known list of DID:SID:name mappings,
  and any signatures that vouch for those mappings.  Similarly, we wish to be able
  to advertise our mapping and any signatures that vouch for us.

  We have the choice of using the rhizome database, some other persistent storage
  or an in-memory structure.  It would be nice to have a fall-back for when we don't 
  have the means to run sqlite.  A small in-memory cache will likely be used, 
  regardless. This initial implementation assumes that we have sqlite and the rhizome
  database instance available.

  So what data do we actually need to tell whether we have verified an identity or not?
  We need a DID:SID[:name] tuple.
  We also need the scope for us to mark a given tuple as verified by ourselves, e.g., 
  using a Diffie-Hellman type exchange between handsets.
  Finally, we want the ability to store any signatures that vouch for the identity of
  a given party.
*/

#include "mphlr.h"
#include "rhizome.h"

int dnacache_lookup(char *did,char *name,char *sid)
{
  
}
