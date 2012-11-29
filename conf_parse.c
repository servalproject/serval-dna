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

#include <assert.h>
#include "log.h"
#include "config.h"

// Generate config set-default function definitions, cf_dfl_config_NAME().
#define STRUCT(__name, __validator...) \
    int cf_dfl_config_##__name(struct config_##__name *s) {
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
        s->__element = (__default);
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
        s->__element = (__default);
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
        strncpy(s->__element, (__default), (__size))[(__size)] = '\0';
#define SUB_STRUCT(__name, __element, __flags) \
        cf_dfl_config_##__name(&s->__element);
#define NODE_STRUCT(__name, __element, __parser, __flags) \
        cf_dfl_config_##__name(&s->__element);
#define END_STRUCT \
        return CFOK; \
    }
#define ARRAY(__name, __validator...) \
    int cf_dfl_config_##__name(struct config_##__name *a) { \
        a->ac = 0; \
        return CFOK; \
    }
#define KEY_ATOM(__type, __eltparser, __cmpfunc...)
#define KEY_STRING(__strsize, __eltparser, __cmpfunc...)
#define VALUE_ATOM(__type, __eltparser)
#define VALUE_STRING(__strsize, __eltparser)
#define VALUE_NODE(__type, __eltparser)
#define VALUE_SUB_STRUCT(__structname)
#define VALUE_NODE_STRUCT(__structname, __eltparser)
#define END_ARRAY(__size)
#include "conf_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY
#undef KEY_ATOM
#undef KEY_STRING
#undef VALUE_ATOM
#undef VALUE_STRING
#undef VALUE_NODE
#undef VALUE_SUB_STRUCT
#undef VALUE_NODE_STRUCT
#undef END_ARRAY

// Generate array element comparison functions.
#define STRUCT(__name, __validator...)
#define NODE(__type, __element, __default, __parser, __flags, __comment)
#define ATOM(__type, __element, __default, __parser, __flags, __comment)
#define STRING(__size, __element, __default, __parser, __flags, __comment)
#define SUB_STRUCT(__name, __element, __flags)
#define NODE_STRUCT(__name, __element, __parser, __flags)
#define END_STRUCT
#define ARRAY(__name, __validator...) \
    static int __cmp_config_##__name(const struct config_##__name##__element *a, const struct config_##__name##__element *b) { \
      __compare_func__config_##__name##__t *cmp = (NULL
#define KEY_ATOM(__type, __eltparser, __cmpfunc...) \
	,##__cmpfunc); \
      return cmp ? (*cmp)(&a->key, &b->key) : 0;
#define KEY_STRING(__strsize, __eltparser, __cmpfunc...) \
	,##__cmpfunc); \
      return cmp ? (*cmp)(a->key, b->key) : 0;
#define VALUE_ATOM(__type, __eltparser)
#define VALUE_STRING(__strsize, __eltparser)
#define VALUE_NODE(__type, __eltparser)
#define VALUE_SUB_STRUCT(__structname)
#define VALUE_NODE_STRUCT(__structname, __eltparser)
#define END_ARRAY(__size) \
    }
#include "conf_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY
#undef KEY_ATOM
#undef KEY_STRING
#undef VALUE_ATOM
#undef VALUE_STRING
#undef VALUE_NODE
#undef VALUE_SUB_STRUCT
#undef VALUE_NODE_STRUCT
#undef END_ARRAY

// Schema item flags.
#define __MANDATORY     (1<<0)
#define __TEXT		(1<<1)
#define __CHILDREN	(1<<2)

// Schema flag symbols, to be used in the '__flags' macro arguments.
#define MANDATORY	|__MANDATORY
#define USES_TEXT	|__TEXT
#define USES_CHILDREN	|__CHILDREN

// Generate parsing functions, cf_opt_config_SECTION()
#define STRUCT(__name, __validator...) \
    int cf_opt_config_##__name(struct config_##__name *strct, const struct cf_om_node *node) { \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFEMPTY; \
      char used[node->nodc]; \
      memset(used, 0, node->nodc * sizeof used[0]);
#define __ITEM(__element, __flags, __parseexpr) \
      { \
	int i = cf_get_child(node, #__element); \
	const struct cf_om_node *child = (i != -1) ? node->nodv[i] : NULL; \
	int ret = CFEMPTY; \
	if (child) { \
	  used[i] |= (__flags); \
	  ret = (__parseexpr); \
	  if (ret == CFERROR) \
	    return CFERROR; \
	} \
	result |= ret & CF__SUBFLAGS; \
	ret &= CF__FLAGS; \
	if (!(ret & CFEMPTY)) \
	  result &= ~CFEMPTY; \
	else if ((__flags) & __MANDATORY) { \
	  cf_warn_missing_node(node, #__element); \
	  result |= CFINCOMPLETE; \
	} \
	if (ret & ~CFEMPTY) { \
	  assert(child != NULL); \
	  if (child->text) \
	    cf_warn_node_value(child, ret); \
	  result |= CFSUB(ret); \
	} \
      }
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, 0 __flags, __parser(&strct->__element, child))
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? __parser(&strct->__element, child->text) : CFEMPTY)
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? __parser(strct->__element, (__size) + 1, child->text) : CFEMPTY)
#define SUB_STRUCT(__name, __element, __flags) \
        __ITEM(__element, (0 __flags)|__CHILDREN, cf_opt_config_##__name(&strct->__element, child))
#define NODE_STRUCT(__name, __element, __parser, __flags) \
        __ITEM(__element, (0 __flags)|__TEXT|__CHILDREN, __parser(&strct->__element, child))
#define END_STRUCT \
      { \
	int i; \
	for (i = 0; i < node->nodc; ++i) { \
	  if (node->nodv[i]->text && !(used[i] & __TEXT)) { \
	    cf_warn_unsupported_node(node->nodv[i]); \
	    result |= CFSUB(CFUNSUPPORTED); \
	  } \
	  if (node->nodv[i]->nodc && !(used[i] & __CHILDREN)) { \
	    cf_warn_unsupported_children(node->nodv[i]); \
	    result |= CFSUB(CFUNSUPPORTED); \
	  } \
	} \
      } \
      if (validator) \
	result = (*validator)(node, strct, result); \
      return result; \
    }

#define ARRAY(__name, __validator...) \
    int cf_opt_config_##__name(struct config_##__name *array, const struct cf_om_node *node) { \
      __compare_func__config_##__name##__t *cmp = NULL; \
      int (*eltcmp)(const struct config_##__name##__element *, const struct config_##__name##__element *) = __cmp_config_##__name; \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFOK; \
      int i, n; \
      for (n = 0, i = 0; i < node->nodc && n < NELS(array->av); ++i) { \
	const struct cf_om_node *child = node->nodv[i]; \
	int ret = CFEMPTY;
#define __ARRAY_KEY(__parseexpr) \
	ret = (__parseexpr); \
	if (ret == CFERROR) \
	  return CFERROR; \
	result |= ret & CF__SUBFLAGS; \
	ret &= CF__FLAGS; \
	result |= CFSUB(ret); \
	if (ret != CFOK) \
	  cf_warn_array_key(child, ret);
#define __ARRAY_VALUE(__parseexpr) \
	if (ret == CFOK) { \
	  ret = (__parseexpr); \
	  if (ret == CFERROR) \
	    return CFERROR; \
	  result |= ret & CF__SUBFLAGS; \
	  ret &= CF__FLAGS; \
	  result |= CFSUB(ret); \
	  if (ret == CFOK) \
	    ++n; \
	  else \
	    cf_warn_array_value(child, ret); \
	}
#define END_ARRAY(__size) \
      } \
      if (i < node->nodc) { \
	assert(n == NELS(array->av)); \
	result |= CFARRAYOVERFLOW; \
	for (; i < node->nodc; ++i) \
	  cf_warn_list_overflow(node->nodv[i]); \
      } \
      array->ac = n; \
      if (cmp) \
	qsort(array->av, array->ac, sizeof array->av[0], (int (*)(const void *, const void *)) eltcmp); \
      if (validator) \
	result = (*validator)(node, array, result); \
      if (result & ~CFEMPTY) { \
	cf_warn_no_array(node, result); \
	array->ac = 0; \
      } \
      if (array->ac == 0) \
	result |= CFEMPTY; \
      return result; \
    }
#define KEY_ATOM(__type, __eltparser, __cmpfunc...) \
      __ARRAY_KEY(__eltparser(&array->av[n].key, child->key)) \
      cmp = (NULL, ##__cmpfunc);
#define KEY_STRING(__strsize, __eltparser, __cmpfunc...) \
      __ARRAY_KEY(__eltparser(array->av[n].key, sizeof array->av[n].key, child->key)) \
      cmp = (NULL, ##__cmpfunc);
#define VALUE_ATOM(__type, __eltparser) \
      __ARRAY_VALUE(child->text ? __eltparser(&array->av[n].value, child->text) : CFEMPTY)
#define VALUE_STRING(__strsize, __eltparser) \
      __ARRAY_VALUE(child->text ? __eltparser(array->av[n].value, sizeof array->av[n].value, child->text) : CFEMPTY)
#define VALUE_NODE(__type, __eltparser) \
      __ARRAY_VALUE(__eltparser(&array->av[n].value, child))
#define VALUE_SUB_STRUCT(__structname) \
      __ARRAY_VALUE(cf_opt_config_##__structname(&array->av[n].value, child))
#define VALUE_NODE_STRUCT(__structname, __eltparser) \
      __ARRAY_VALUE(__eltparser(&array->av[n].value, child))

#include "conf_schema.h"

#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef ARRAY
#undef KEY_ATOM
#undef KEY_STRING
#undef VALUE_ATOM
#undef VALUE_STRING
#undef VALUE_NODE
#undef VALUE_SUB_STRUCT
#undef VALUE_NODE_STRUCT
#undef END_ARRAY
