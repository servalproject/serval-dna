#include <netinet/in.h>

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

void *emalloc(size_t len);
char *strn_emalloc(const char *str, size_t len);
char *str_emalloc(const char *str);

struct config_node *parse_config(const char *source, const char *buf, size_t len);
int get_child(const struct config_node *parent, const char *key);
void unsupported_node(const struct config_node *node);
void unsupported_tree(const struct config_node *node);

// Generate value structs, struct config_SECTION.
#define SECTION(__sect) struct config_##__sect {
#define ITEM(__name, __type, __default, __parser, __comment) __type __name;
#define SUB(__name, __sect) struct config_##__sect __name;
#define LIST(__name, __type, __parser, __comment) struct { unsigned listc; struct { const char *label; __type value; } *listv; } __name;
#define SECTION_END };
#include "config_schema.h"
#undef SECTION
#undef ITEM
#undef SUB
#undef LIST
#undef SECTION_END

// Generate parser function prototypes.
#define SECTION(__sect) int opt_config_##__sect(struct config_##__sect *s, const struct config_node *node);
#define ITEM(__name, __type, __default, __parser, __comment) int __parser(__type *, const struct config_node *);
#define SUB(__name, __sect)
#define LIST(__name, __type, __parser, __comment) int __parser(__type *, const struct config_node *);
#define SECTION_END
#include "config_schema.h"
#undef SECTION
#undef ITEM
#undef SUB
#undef LIST
#undef SECTION_END

int opt_boolean(int *booleanp, const struct config_node *node);
int opt_absolute_path(const char **pathp, const struct config_node *node);
int opt_debugflags(debugflags_t *flagsp, const struct config_node *node);
int opt_rhizome_peer(struct config_rhizomepeer *, const struct config_node *node);
int opt_host(const char **hostp, const struct config_node *node);
int opt_port(unsigned short *portp, const struct config_node *node);

// Generate default functions, dfl_config_SECTION()
#define SECTION(__sect) \
    void dfl_config_##__sect(struct config_##__sect *s) {
#define ITEM(__name, __type, __default, __parser, __comment) s->__name = __default;
#define SUB(__name, __sect) dfl_config_##__sect(&s->__name);
#define LIST(__name, __type, __parser, __comment) s->__name.listc = 0; s->__name.listv = NULL;
#define SECTION_END }
#include "config_schema.h"
#undef SECTION
#undef ITEM
#undef SUB
#undef LIST
#undef SECTION_END

// Generate parsing functions, opt_config_SECTION()
#define SECTION(__sect) \
    int opt_config_##__sect(struct config_##__sect *s, const struct config_node *node) { \
        if (node->text) unsupported_node(node); \
        int i; \
        char used[node->nodc]; \
        for (i = 0; i < node->nodc; ++i) \
            used[i] = 0;
#define ITEM(__name, __type, __default, __parser, __comment) \
        if ((i = get_child(node, #__name)) != -1) { \
            used[i] = 1; \
            __parser(&s->__name, node->nodv[i]); \
        }
#define SUB(__name, __sect) \
        if ((i = get_child(node, #__name)) != -1) { \
            used[i] = 1; \
            opt_config_##__sect(&s->__name, node->nodv[i]); \
        }
#define LIST(__name, __type, __parser, __comment) \
        if ((i = get_child(node, #__name)) != -1) { \
            used[i] = 1; \
            const struct config_node *child = node->nodv[i]; \
            if (child->text) \
                unsupported_node(child); \
            char *labels[child->nodc]; \
            __type values[child->nodc]; \
            int n = 0; \
            int j; \
            for (j = 0; j < child->nodc; ++j) { \
                const struct config_node *elt = child->nodv[j]; \
                switch (__parser(&values[n], elt)) { \
                case -1: \
                    return -1; \
                case 0: \
                    if (!(labels[n++] = str_emalloc(elt->key))) { \
                        while (n) \
                            free(labels[--n]); \
                        return -1; \
                    } \
                    break; \
                } \
            } \
            if (n) { \
                if (s->__name.listv = emalloc(n * sizeof(s->__name.listv[0]))) { \
                    for (j = 0; j < n; ++j) { \
                        s->__name.listv[j].label = labels[j]; \
                        s->__name.listv[j].value = values[j]; \
                    } \
                    s->__name.listc = n; \
                } else { \
                    while (n) \
                        free(labels[--n]); \
                    return -1; \
                } \
            } \
        }
#define SECTION_END \
        for (i = 0; i < node->nodc; ++i) \
            if (!used[i]) \
                unsupported_tree(node->nodv[i]); \
        return 0; \
    }
#include "config_schema.h"
#undef SECTION
#undef ITEM
#undef SUB
#undef LIST
#undef SECTION_END

