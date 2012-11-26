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
#include "strbuf.h"

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

#define ARRAY_ATOM(__name, __size, __type, __parser, __comment) \
    __ARRAY(__name, __size, __type, __type value, __parser, char *, __comment)
#define ARRAY_STRING(__name, __size, __strsize, __parser, __comment) \
    __ARRAY(__name, __size, char *, char value[__strsize], __parser, char *, __comment)
#define ARRAY_NODE(__name, __size, __type, __parser, __comment) \
    __ARRAY(__name, __size, __type, __type value, __parser, struct cf_om_node *, __comment)
#define ARRAY_STRUCT(__name, __size, __structname, __comment) \
    ARRAY_NODE(__name, __size, struct config_##__structname, opt_config_##__structname, __comment)

// Generate value structs, struct config_SECTION.
#define STRUCT(__name) struct config_##__name {
#define NODE(__type, __element, __default, __parser, __flags, __comment) __type __element;
#define ATOM(__type, __element, __default, __parser, __flags, __comment) __type __element;
#define STRING(__size, __element, __default, __parser, __flags, __comment) char __element[__size + 1];
#define SUB_STRUCT(__name, __element, __flags) struct config_##__name __element;
#define NODE_STRUCT(__name, __element, __parser, __flags) struct config_##__name __element;
#define END_STRUCT };
#define __ARRAY(__name, __size, __type, __decl, __parser, __parsearg, __comment) \
    struct config_##__name { unsigned ac; struct { char label[41]; __decl; } av[(__size)]; };
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY

/* Return bit flags for schema default dfl_ and parsing opt_ functions. */

#define CFERROR             (~0) // all set
#define CFOK                0
#define CFEMPTY             (1<<0)
#define CFARRAYOVERFLOW     (1<<1)
#define CFSTRINGOVERFLOW    (1<<2)
#define CFINCOMPLETE        (1<<3)
#define CFINVALID           (1<<4)
#define CF__SUB_SHIFT       16
#define CFSUB(f)            ((f) << CF__SUB_SHIFT)
#define CF__SUBFLAGS        CFSUB(~0)
#define CF__FLAGS           (~0 & ~CF__SUBFLAGS)

strbuf strbuf_cf_flags(strbuf, int);

// Generate default functions, dfl_config_SECTION().

#define STRUCT(__name) \
    int dfl_config_##__name(struct config_##__name *s) {
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
        s->__element = (__default);
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
        s->__element = (__default);
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
        strncpy(s->__element, (__default), (__size))[(__size)] = '\0';
#define SUB_STRUCT(__name, __element, __flags) \
        dfl_config_##__name(&s->__element);
#define NODE_STRUCT(__name, __element, __parser, __flags) \
        dfl_config_##__name(&s->__element);
#define END_STRUCT \
        return CFOK; \
    }
#define __ARRAY(__name, __size, __type, __decl, __parser, __parsearg, __comment) \
    int dfl_config_##__name(struct config_##__name *a) { \
        a->ac = 0; \
        return CFOK; \
    }
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY

/* The Configuration Object Model (COM).  The config file is parsed into a tree of these structures
 * first, then those structures are passed as arguments to the schema parsing functions.
 */

struct cf_om_node {
    const char *source; // = parse_config() 'source' arg
    unsigned int line_number;
    const char *fullkey; // malloc()
    const char *key; // points inside fullkey, do not free()
    const char *text; // malloc()
    size_t nodc;
    struct cf_om_node *nodv[10]; // malloc()
};

// Generate parser function prototypes.
#define STRUCT(__name) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *);
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
    int __parser(__type *, const struct cf_om_node *);
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
    int __parser(__type *, const char *);
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
    int __parser(char *, size_t, const char *);
#define SUB_STRUCT(__name, __element, __flags) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *);
#define NODE_STRUCT(__name, __element, __parser, __flags) \
    int __parser(struct config_##__name *, const struct cf_om_node *);
#define END_STRUCT
#define __ARRAY(__name, __size, __type, __decl, __parser, __parsearg, __comment) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *); \
    int __parser(__type *, const __parsearg);
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY

#endif //__SERVALDNA_CONFIG_H
