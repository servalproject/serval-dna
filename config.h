typedef unsigned long debugflags_t;

struct config_node {
    const char *source; // = parse_config() 'source' arg
    unsigned int line_number;
    const char *fullkey; // malloc()
    const char *key; // points inside fullkey, do not free()
    const char *text; // malloc()
    size_t nodc;
    struct config_node *nodv[10]; // malloc()
};

struct config_node *parse_config(const char *source, const char *buf, size_t len);
int get_child(const struct config_node *parent, const char *key);
void unsupported_node(const struct config_node *node);
void unsupported_tree(const struct config_node *node);

int opt_boolean(int *booleanp, const struct config_node *node);
int opt_absolute_path(const char **pathp, const struct config_node *node);
void opt_debugflags(debugflags_t *flagsp, const struct config_node *node);

// Generate value structs, struct config_SECTION
#define CONFIG_SECTION(__sect) struct config_##__sect {
#define CONFIG_ITEM(__name, __type, __default, __parser, __comment) __type __name;
#define CONFIG_STRUCT(__name, __sect) struct config_##__sect __name;
#define CONFIG_SECTION_END };
#include "config_schema.h"
#undef CONFIG_SECTION
#undef CONFIG_ITEM
#undef CONFIG_STRUCT
#undef CONFIG_SECTION_END

// Generate default functions, dfl_config_SECTION()
#define CONFIG_SECTION(__sect) \
    void dfl_config_##__sect(struct config_##__sect *s) {
#define CONFIG_ITEM(__name, __type, __default, __parser, __comment) s->__name = __default;
#define CONFIG_STRUCT(__name, __sect) dfl_config_##__sect(&s->__name);
#define CONFIG_SECTION_END }
#include "config_schema.h"
#undef CONFIG_SECTION
#undef CONFIG_ITEM
#undef CONFIG_STRUCT
#undef CONFIG_SECTION_END

// Generate parsing functions, opt_config_SECTION()
#define CONFIG_SECTION(__sect) \
    void opt_config_##__sect(struct config_##__sect *s, const struct config_node *node) { \
    int i; \
    char used[node->nodc]; \
    for (i = 0; i < node->nodc; ++i) used[i] = 0;
#define CONFIG_ITEM(__name, __type, __default, __parser, __comment) \
        if ((i = get_child(node, #__name)) != -1) { used[i] = 1; __parser(&s->__name, node->nodv[i]); }
#define CONFIG_STRUCT(__name, __sect) \
        if ((i = get_child(node, #__name)) != -1) { used[i] = 1; opt_config_##__sect(&s->__name, node->nodv[i]); }
#define CONFIG_SECTION_END \
        for (i = 0; i < node->nodc; ++i) { if (!used[i]) unsupported_tree(node->nodv[i]); } \
    }
#include "config_schema.h"
#undef CONFIG_SECTION
#undef CONFIG_ITEM
#undef CONFIG_STRUCT
#undef CONFIG_SECTION_END

