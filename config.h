/* 
Serval DNA configuration
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

#ifndef __SERVALDNA_CONFIG_H
#define __SERVALDNA_CONFIG_H

#include <stdint.h>
#include "constants.h"

typedef unsigned long debugflags_t;

#define RHIZOME_HTTP_PORT 4110

typedef struct binarysid { unsigned char binary[SID_SIZE]; } sid_t;
#define SID_NONE        ((sid_t){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
#define SID_BROADCAST   ((sid_t){0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff})

struct pattern_list {
    unsigned patc;
    char patv[16][41];
};
#define PATTERN_LIST_EMPTY ((struct pattern_list){.patc = 0})


// Generate value structs, struct config_SECTION.
#define STRUCT(__sect) struct config_##__sect {
#define NODE(__type, __name, __default, __parser, __flags, __comment) __type __name;
#define ATOM(__type, __name, __default, __parser, __flags, __comment) __type __name;
#define STRING(__size, __name, __default, __parser, __flags, __comment) char __name[__size + 1];
#define SUB_STRUCT(__sect, __name, __flags) struct config_##__sect __name;
#define NODE_STRUCT(__sect, __name, __parser, __flags) struct config_##__sect __name;
#define END_STRUCT };
#define ARRAY(__sect, __type, __size, __parser, __comment) struct config_##__sect { unsigned ac; struct { char label[41]; __type value; } av[(__size)]; };
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY

// Generate default functions, dfl_config_SECTION()
#define STRUCT(__sect) \
    int dfl_config_##__sect(struct config_##__sect *s) {
#define NODE(__type, __name, __default, __parser, __flags, __comment) \
        s->__name = (__default);
#define ATOM(__type, __name, __default, __parser, __flags, __comment) \
        s->__name = (__default);
#define STRING(__size, __name, __default, __parser, __flags, __comment) \
        strncpy(s->__name, (__default), (__size))[(__size)] = '\0';
#define SUB_STRUCT(__sect, __name, __flags) \
        dfl_config_##__sect(&s->__name);
#define NODE_STRUCT(__sect, __name, __parser, __flags) \
        dfl_config_##__sect(&s->__name);
#define END_STRUCT \
        return 0; \
    }
#define ARRAY(__sect, __type, __size, __parser, __comment) \
    int dfl_config_##__sect(struct config_##__sect *s) { \
        s->ac = 0; \
        return 0; \
    }
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY

struct config_node {
    const char *source; // = parse_config() 'source' arg
    unsigned int line_number;
    const char *fullkey; // malloc()
    const char *key; // points inside fullkey, do not free()
    const char *text; // malloc()
    size_t nodc;
    struct config_node *nodv[10]; // malloc()
};

/* Return values for parsing functions */
#define CFERROR     (-1)
#define CFOK        0
#define CFOVERFLOW  1
#define CFMISSING   2
#define CFINVALID   3

// Generate parser function prototypes.
#define STRUCT(__sect) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *);
#define NODE(__type, __name, __default, __parser, __flags, __comment) \
    int __parser(__type *, const struct config_node *);
#define ATOM(__type, __name, __default, __parser, __flags, __comment) \
    int __parser(__type *, const char *);
#define STRING(__size, __name, __default, __parser, __flags, __comment) \
    int __parser(char *, size_t, const char *);
#define SUB_STRUCT(__sect, __name, __flags) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *);
#define NODE_STRUCT(__sect, __name, __parser, __flags) \
    int __parser(struct config_##__sect *, const struct config_node *);
#define END_STRUCT
#define ARRAY(__sect, __type, __size, __parser, __comment) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *); \
    int __parser(__type *, const struct config_node *);
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY

#endif //__SERVALDNA_CONFIG_H
