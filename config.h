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
 * Each STRUCT(foo, ...) schema declaration produces the following data declaration:
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
 * Each STRUCT(foo, ...) and ARRAY_*(SIZE, foo, ...) schema declaration produces the following API
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
 *      result into the given C structure.  See below for the return value.  For arrays, this
 *      function is used to parse each individual array element, and the parsed result is only
 *      appended to the array if it returns CFOK.
 *
 * If a STRUCT(foo, validator) or ARRAY(foo, ..., validator) schema declaration is given a validator
 * function, then the function must have the following signature:
 *
 *  - int validator(struct config_foo *dest, int orig_result);
 *
 *      A C function which validates the contents of the given C structure (struct or array) as
 *      defined in the schema.  This function is invoked by the opt_config_foo() parser function
 *      just before it returns, so all the parse functions have already been called and the result
 *      is assembled.  The validator function is passed a pointer to the (non-const) structure,
 *      which it may modify if desired, and the original CFxxx flags result code (not CFERROR) that
 *      would be returned by the opt_config_foo() parser function.  It returns a new CFxxx flags
 *      result (which may simply be the same as was passed).
 *
 *      In the case arrays, validator() is passed a *dest containing elements that were successfully
 *      parsed from the COM, omitting any that did not parse successfully (in which case the
 *      relevant CFxxx result flags will be set) and arbitrarily omitting others that did not fit
 *      (in which case the CFOVERFLOW flag is set).  It is up to validator() to decide whether to
 *      return some, all or none of these elements (ie, alter dest->ac and/or dest->av), and whether
 *      to set or clear the CFARRAYOVERFLOW bit, or set other bits (like CFINVALID for example).  If
 *      there is no validator function, then opt_config_foo() will return an empty array (dest->ac
 *      == 0) in the case of CFARRAYOVERFLOW.
 *
 * All parse functions assign the result of their parsing into the struct given in their 'dest'
 * argument, and return a bitmask of the following flags:
 *
 *  - CFERROR (all bits set, == -1) if an unrecoverable error occurs (eg, malloc() fails).  The
 *    result in *dest is undefined and may be malformed or inconsistent.
 *
 *  - CFEMPTY if no items were parsed from the COM.  In the case of a struct, this means that no
 *    child nodes were found for any elements; if any child nodes were present but failed parsing
 *    then CFEMPTY is not set but other flags will be set.  In the case of arrays, CFEMPTY means
 *    that the returned array has zero length for _any_ reason (overflow, element parsing failures,
 *    or no elements present in the COM).
 *
 *  - CFUNSUPPORTED if the config item (array or struct) is not supported.  This flag is not
 *    produced by the normal opt_config_foo() parse functions, but a validation function could
 *    set it as a way of indicating, for example, that a given option is not yet implemented or
 *    has been deprecated.  In that case, the validation function should also log a message to that
 *    effect.  The CFUNSUPPORTED flag is mainly used in its CFSUB(CFUNSUPPORTED) form (see below)
 *    to indicate that the COM contains elements that are not defined in the STRUCT.
 *
 *  - CFARRAYOVERFLOW if the size of any array was exceeded.  The result in *dest may be empty (in
 *    which case CFEMPTY is also set), or may contain elements parsed successfully from the COM (ie,
 *    returned CFOK), omitting any that did not parse successfully (in which case other bits will be
 *    set) and arbitrarily omitting others that did not fit (it is not defined which will be
 *    omitted).  Normal array parsing without a validator function will return an empty result in
 *    the case of overflow, but a validator function may change this behaviour.
 *
 *  - CFSTRINGFOVERFLOW if the size of any string element was exceeded.  The result in *dest may be
 *    unchanged or may contain a truncated string, depending on the parser that detected and
 *    reported the string overflow.
 *
 *  - CFINCOMPLETE if any MANDATORY element is missing (no node in the COM) or empty (as indicated
 *    by the CFEMPTY bit in its parse result).  The result in *dest is valid but the missing
 *    mandatory element(s) are unchanged (in the case of a struct) or zero-length (in the case of an
 *    array).
 *
 *  - CFINVALID if any invalid configuration value was encountered, ie, any parse function returned
 *    CFINVALID in its return flags.  The result in *dest is valid and the elements that failed
 *    to parse are unchanged.
 *
 *  - CFSUB(CFxxx) if any element of a STRUCT or ARRAY produced a CFxxx result when being parsed, ie
 *    any element's parse function returned CFxxx.  In the case of a STRUCT, the failed elements are
 *    usually left with their prior (default) values, but this depends on the parse functions'
 *    behaviours.  In the case of an ARRAY, failed elements are omitted from the array
 *
 * The difference between CFSUB(CFxxx) and CFxxx needs explaining.  To illustrate, CFSUB(CFINVALID)
 * is different from CFINVALID because an element of a struct or array may have failed to parse, yet
 * the whole struct or array itself may still be valid (in the case of a struct, the element's prior
 * value may be retained, and in the case of an array, the failed element is simply omitted from the
 * result).  A validator function may wish to reflect any CFSUB() bit as a CFINVALID result, but the
 * normal behaviour of opt_config_foo() is to not return CFINVALID unless the validator function
 * sets it.
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
#define STRUCT(__name, __validator...) \
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
#define ARRAY_ATOM(__name, __size, __type, __eltparser, __validator...) __ARRAY(__name, __size, __type value)
#define ARRAY_STRING(__name, __size, __strsize, __eltparser, __validator...) __ARRAY(__name, __size, char value[(__strsize) + 1])
#define ARRAY_NODE(__name, __size, __type, __eltparser, __validator...) __ARRAY(__name, __size, __type value)
#define ARRAY_STRUCT(__name, __size, __structname, __validator...) __ARRAY(__name, __size, struct config_##__structname value)
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
#define CFUNSUPPORTED       (1<<5)
#define CF__SUB_SHIFT       16
#define CFSUB(f)            ((f) << CF__SUB_SHIFT)
#define CF__SUBFLAGS        CFSUB(~0)
#define CF__FLAGS           (~0 & ~CF__SUBFLAGS)

strbuf strbuf_cf_flags(strbuf, int);

// Generate default functions, dfl_config_SECTION().

#define STRUCT(__name, __validator...) \
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
#define ARRAY_ATOM(__name, __size, __type, __eltparser, __validator...) __ARRAY(__name)
#define ARRAY_STRING(__name, __size, __strsize, __eltparser, __validator...) __ARRAY(__name)
#define ARRAY_NODE(__name, __size, __type, __eltparser, __validator...) __ARRAY(__name)
#define ARRAY_STRUCT(__name, __size, __structname, __validator...) __ARRAY(__name)
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
#define __VALIDATOR(__name, __validator...) \
    typedef int __validator_func__config_##__name##__t(struct config_##__name *, int); \
    __validator_func__config_##__name##__t __dummy__validator_func__config_##__name, ##__validator;
#define STRUCT(__name, __validator...) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *); \
    __VALIDATOR(__name, ##__validator)
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
#define __ARRAY(__name, __validator...) \
    int opt_config_##__name(struct config_##__name *, const struct cf_om_node *); \
    __VALIDATOR(__name, ##__validator)
#define ARRAY_ATOM(__name, __size, __type, __eltparser, __validator...) \
    __ARRAY(__name, ##__validator) \
    int __eltparser(__type *, const struct cf_om_node *);
#define ARRAY_STRING(__name, __size, __strsize, __eltparser, __validator...) \
    __ARRAY(__name, ##__validator) \
    int __eltparser(char *, size_t, const char *);
#define ARRAY_NODE(__name, __size, __type, __eltparser, __validator...) \
    __ARRAY(__name, ##__validator) \
    int __eltparser(__type *, const struct cf_om_node *);
#define ARRAY_STRUCT(__name, __size, __structname, __validator...) \
    __ARRAY(__name, ##__validator) \
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
