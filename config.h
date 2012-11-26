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

/* This file defines the internal API to the configuration file.  See "config_schema.h" for the
 * definition of the configuration schema, which is used to generate these API components.
 *
 * Each STRUCT(foo) schema declaration produces the following data declaration:
 *
 *      struct config_foo {
 *          TYPE NAME;
 *          ...
 *      };
 *
 *      A C struct definition containing exactly one element per schema declaration inside the
 *      STRUCT..END_STRUCT block, in the defined order.  The TYPE and NAME of each element depends
 *      on the schema declaration that produces it:
 *
 *      ATOM(TYPE, bar, ...)
 *      NODE(TYPE, bar, ...)
 *
 *          TYPE bar;
 *
 *      STRING(SIZE, bar, ...)
 *
 *          char bar[SIZE+1];
 *
 *      SUB_STRUCT(NAME, bar, ...)
 *      NODE_STRUCT(NAME, bar, ...)
 *      
 *          struct config_NAME bar;
 *
 * Each ARRAY_*(SIZE, bar, ...) schema declaration produces the following data declaration:
 *
 *      struct config_bar {
 *          unsigned ac;
 *          struct {
 *              char label[N]; // please discover N using sizeof()
 *              TYPE value;
 *          } av[SIZE];
 *      };
 *
 *      A C struct definition containing a count 'ac' of the number of array elements [0..SIZE-1]
 *      and 'av' an array of element values, each one consisting of a label and the value itself,
 *      whose TYPE depends on the ARRAY_* declaration itself:
 *      
 *      ARRAY_ATOM(NAME, SIZE, TYPE, ...)
 *      ARRAY_NODE(NAME, SIZE, TYPE, ...)
 *
 *              TYPE value;
 *
 *      ARRAY_STRING(NAME, SIZE, STRINGSIZE, ...)
 *
 *              char value[STRINGSIZE];
 *
 *      ARRAY_STRUCT(NAME, SIZE, STRUCTNAME, ...)
 *
 *              struct config_STRUCTNAME value;
 *
 * Each STRUCT(foo) and ARRAY_*(SIZE, foo, ...) schema declaration produces the following API
 * functions:
 *
 *  - int dfl_config_foo(struct config_foo *dest);
 *
 *      A C function which sets the entire contents of the given C structure to its default values
 *      as defined in the schema.  This will only return CFOK or CFERROR; see below.
 *
 *  - int opt_config_foo(struct config_foo *dest, const struct cf_om_node *node);
 *
 *      A C function which parses the given COM (configuration object model) and assigns the parsed
 *      result into the given C structure.  See below for the return value.
 *
 * All parse functions assign the result of their parsing into the struct given in their 'dest'
 * argument, and return a bitmask of the following flags:
 *
 *  - CFERROR (all bits set, == -1) if an unrecoverable error occurrs (eg, malloc() fails); the
 *    result in *dest is undefined and may be malformed or inconsistent;
 *
 *  - CFEMPTY if no items were encountered in the COM (ie, no array elements or no struct elements);
 *    the memory at *dest is unchanged;
 *
 *  - CFARRAYOVERFLOW if the size of any array was exceeded; a valid result is produced and the
 *    overflowed array(s) are fully populated, arbitrarily omitting some elements that were found in
 *    the COM;
 *
 *  - CFSTRINGFOVERFLOW if the size of any string element was exceeded, a valid result is produced
 *    but the overflowed string elements are unchanged -- those parts of *dest are not overwritten;
 *
 *  - CFINCOMPLETE if any MANDATORY element was missing; a valid result is produced but the missing
 *    mandatory element(s) are unchanged -- those parts of *dest are not overwritten;
 *
 *  - CFINVALID if any invalid configuration value was encountered, ie, any parse function returned
 *    CFINVALID in its return flags; a valid result is produced but the invalid elements are
 *    unchanged -- those parts of *dest are not overwritten;
 *
 *  - CFSUB(CFxxx) if the STRUCT parser function encountered the error CFxxx when parsing a struct
 *    element, ie, a parse function returned CFxxx; a valid result is produced but some parts of
 *    *dest will not be overwritten;
 *
 * The special value CFOK is zero (no bits set); in this case a valid result is produced and all of
 * *dest is overwritten (except unused array elements).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

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

// Generate value structs, struct config_SECTION.
#define STRUCT(__name) \
    struct config_##__name {
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
        __type __element;
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
        __type __element;
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
        char __element[__size + 1];
#define SUB_STRUCT(__name, __element, __flags) \
        struct config_##__name __element;
#define NODE_STRUCT(__name, __element, __parser, __flags) \
        struct config_##__name __element;
#define END_STRUCT \
    };
#define __ARRAY(__name, __size, __decl) \
    struct config_##__name { \
        unsigned ac; \
        struct { \
            char label[41]; \
            __decl; \
        } av[(__size)]; \
    };
#define ARRAY_ATOM(__name, __size, __type, __parser, __comment) __ARRAY(__name, __size, __type value)
#define ARRAY_STRING(__name, __size, __strsize, __parser, __comment) __ARRAY(__name, __size, char value[(__strsize) + 1])
#define ARRAY_NODE(__name, __size, __type, __parser, __comment) __ARRAY(__name, __size, __type value)
#define ARRAY_STRUCT(__name, __size, __structname, __comment) __ARRAY(__name, __size, struct config_##__structname value)
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY
#undef ARRAY_ATOM
#undef ARRAY_STRING
#undef ARRAY_NODE
#undef ARRAY_STRUCT

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
#define __ARRAY(__name) \
    int dfl_config_##__name(struct config_##__name *a) { \
        a->ac = 0; \
        return CFOK; \
    }
#define ARRAY_ATOM(__name, __size, __type, __parser, __comment) __ARRAY(__name)
#define ARRAY_STRING(__name, __size, __strsize, __parser, __comment) __ARRAY(__name)
#define ARRAY_NODE(__name, __size, __type, __parser, __comment) __ARRAY(__name)
#define ARRAY_STRUCT(__name, __size, __structname, __comment) __ARRAY(__name)
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY
#undef ARRAY_ATOM
#undef ARRAY_STRING
#undef ARRAY_NODE
#undef ARRAY_STRUCT

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
#define __ARRAY(__name) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *);
#define ARRAY_ATOM(__name, __size, __type, __parser, __comment) \
    __ARRAY(__name) \
    int __parser(__type *, const struct cf_om_node *);
#define ARRAY_STRING(__name, __size, __strsize, __parser, __comment) \
    __ARRAY(__name) \
    int __parser(char *, size_t, const char *);
#define ARRAY_NODE(__name, __size, __type, __parser, __comment) \
    __ARRAY(__name) \
    int __parser(__type *, const struct cf_om_node *);
#define ARRAY_STRUCT(__name, __size, __structname, __comment) \
    __ARRAY(__name) \
    int opt_config_##__structname(struct config_##__structname *, const struct cf_om_node *);
#include "config_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY
#undef ARRAY_ATOM
#undef ARRAY_STRING
#undef ARRAY_NODE
#undef ARRAY_STRUCT

#endif //__SERVALDNA_CONFIG_H
