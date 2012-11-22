#include <stdint.h>
#include "constants.h"

typedef unsigned long debugflags_t;

#define RHIZOME_HTTP_PORT 4110

typedef struct binarysid { unsigned char binary[SID_SIZE]; } sid_t;

struct pattern_list {
    unsigned patc;
    char patv[16][41];
};

#define PATTERN_LIST_EMPTY ((struct pattern_list){.patc = 0})

#define SID_NONE        ((sid_t){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0})
#define SID_BROADCAST   ((sid_t){0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff})

// Generate value structs, struct config_SECTION.
#define SECTION(__sect) struct config_##__sect {
#define ATOM(__type, __name, __default, __parser, __flags, __comment) __type __name;
#define STRING(__size, __name, __default, __parser, __flags, __comment) char __name[__size + 1];
#define SUB(__sect, __name, __flags) struct config_##__sect __name;
#define SUBP(__sect, __name, __parser, __flags) struct config_##__sect __name;
#define SECTION_END };
#define LIST(__sect, __type, __size, __parser, __comment) struct config_##__sect { unsigned listc; struct { char label[41]; __type value; } listv[(__size)]; };
#include "config_schema.h"
#undef SECTION
#undef ATOM
#undef STRING
#undef SUB
#undef SUBP
#undef SECTION_END
#undef LIST
