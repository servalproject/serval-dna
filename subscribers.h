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
  overlay_node *node;
};


struct subscriber *find_subscriber(const unsigned char *sid, int len, int create);
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context);

#endif
