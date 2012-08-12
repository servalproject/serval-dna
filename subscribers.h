//
//  subscribers.h
//  
//
//  Created by Jeremy Lakeman on 11/08/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#ifndef _subscribers_h
#define _subscribers_h
#include "constants.h"

struct subscriber{
  unsigned char sid[SID_SIZE];
  // minimum abbreviation length, in 4bit nibbles.
  int abbreviate_len;
};

struct subscriber *find(const unsigned char *sid, int len, int create);
void dump_subscribers();


#endif
