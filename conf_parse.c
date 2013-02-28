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
#include "conf.h"

// Generate config set-default function definitions, cf_dfl_config_NAME().
#define STRUCT(__name, __validator...) \
    int cf_dfl_config_##__name(struct config_##__name *s) {
#define NODE(__type, __element, __default, __repr, __flags, __comment) \
        s->__element = (__default);
#define ATOM(__type, __element, __default, __repr, __flags, __comment) \
        s->__element = (__default);
#define STRING(__size, __element, __default, __repr, __flags, __comment) \
        strncpy(s->__element, (__default), (__size))[(__size)] = '\0';
#define SUB_STRUCT(__name, __element, __flags) \
        cf_dfl_config_##__name(&s->__element);
#define NODE_STRUCT(__name, __element, __repr, __flags) \
        cf_dfl_config_##__name(&s->__element);
#define END_STRUCT \
        return CFOK; \
    }
#define ARRAY(__name, __flags, __validator...) \
    int cf_dfl_config_##__name(struct config_##__name *a) { \
        a->ac = 0; \
        return CFOK; \
    }
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...)
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...)
#define VALUE_ATOM(__type, __eltrepr)
#define VALUE_STRING(__strsize, __eltrepr)
#define VALUE_NODE(__type, __eltrepr)
#define VALUE_SUB_STRUCT(__structname)
#define VALUE_NODE_STRUCT(__structname, __eltrepr)
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
#define NODE(__type, __element, __default, __repr, __flags, __comment)
#define ATOM(__type, __element, __default, __repr, __flags, __comment)
#define STRING(__size, __element, __default, __repr, __flags, __comment)
#define SUB_STRUCT(__name, __element, __flags)
#define NODE_STRUCT(__name, __element, __repr, __flags)
#define END_STRUCT
#define ARRAY(__name, __flags, __validator...) \
    static int __cmp_config_##__name(const struct config_##__name##__element *a, const struct config_##__name##__element *b) { \
      __compare_func__config_##__name##__t *cmp = (NULL
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
	,##__cmpfunc); \
      return cmp ? (*cmp)(&a->key, &b->key) : memcmp(&a->key, &b->key, sizeof a->key);
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
	,##__cmpfunc); \
      return cmp ? (*cmp)(a->key, b->key) : strcmp(a->key, b->key);
#define VALUE_ATOM(__type, __eltrepr)
#define VALUE_STRING(__strsize, __eltrepr)
#define VALUE_NODE(__type, __eltrepr)
#define VALUE_SUB_STRUCT(__structname)
#define VALUE_NODE_STRUCT(__structname, __eltrepr)
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
#define __SORTED	(1<<3)
#define __NO_DUPLICATES	(1<<4)

// Schema flag symbols, to be used in the '__flags' macro arguments.
#define MANDATORY	|__MANDATORY
#define USES_TEXT	|__TEXT
#define USES_CHILDREN	|__CHILDREN
#define SORTED		|__SORTED
#define NO_DUPLICATES	|__NO_DUPLICATES

// Generate parsing functions, cf_opt_config_SECTION()
#define STRUCT(__name, __validator...) \
    int cf_opt_config_##__name(struct config_##__name *strct, const struct cf_om_node *node) { \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFEMPTY; \
      char used[node->nodc]; \
      memset(used, 0, node->nodc * sizeof used[0]);
#define __ITEM(__element, __flags, __parseexpr) \
      { \
	int i = cf_om_get_child(node, #__element, NULL); \
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
#define NODE(__type, __element, __default, __repr, __flags, __comment) \
        __ITEM(__element, 0 __flags, cf_opt_##__repr(&strct->__element, child))
#define ATOM(__type, __element, __default, __repr, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? cf_opt_##__repr(&strct->__element, child->text) : CFEMPTY)
#define STRING(__size, __element, __default, __repr, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? cf_opt_##__repr(strct->__element, (__size) + 1, child->text) : CFEMPTY)
#define SUB_STRUCT(__name, __element, __flags) \
        __ITEM(__element, (0 __flags)|__CHILDREN, cf_opt_config_##__name(&strct->__element, child))
#define NODE_STRUCT(__name, __element, __repr, __flags) \
        __ITEM(__element, (0 __flags)|__TEXT|__CHILDREN, cf_opt_##__repr(&strct->__element, child))
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
#define ARRAY(__name, __flags, __validator...) \
    int cf_opt_config_##__name(struct config_##__name *array, const struct cf_om_node *node) { \
      int flags = (0 __flags); \
      int (*eltcmp)(const struct config_##__name##__element *, const struct config_##__name##__element *) = __cmp_config_##__name; \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFOK; \
      int i, n; \
      for (n = 0, i = 0; i < node->nodc && n < NELS(array->av); ++i) { \
	const struct cf_om_node *child = node->nodv[i]; \
	int ret = CFEMPTY;
#define __ARRAY_KEY(__parseexpr, __cmpfunc...) \
	ret = (__parseexpr); \
	if (ret == CFERROR) \
	  return CFERROR; \
	result |= ret & CF__SUBFLAGS; \
	ret &= CF__FLAGS; \
	result |= CFSUB(ret); \
	if (ret == CFOK && (flags & __NO_DUPLICATES)) { \
	  int j; \
	  for (j = 0; j < n; ++j) { \
	    if ((*eltcmp)(&array->av[j], &array->av[n]) == 0) { \
	      cf_warn_duplicate_node(child, NULL); \
	      ret |= CFDUPLICATE; \
	    } \
	  } \
	} \
	if (ret != CFOK) \
	  cf_warn_array_key(child, ret);
#define __ARRAY_VALUE(__dflexpr, __parseexpr) \
	if (ret == CFOK) { \
	  ret = (__dflexpr); \
	  if (ret == CFOK) \
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
      if (flags & __SORTED) \
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
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
      __ARRAY_KEY(cf_opt_##__keyrepr(&array->av[n].key, child->key), ##__cmpfunc)
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
      __ARRAY_KEY(cf_opt_##__keyrepr(array->av[n].key, sizeof array->av[n].key, child->key), ##__cmpfunc)
#define VALUE_ATOM(__type, __eltrepr) \
      __ARRAY_VALUE(CFOK, child->text ? cf_opt_##__eltrepr(&array->av[n].value, child->text) : CFEMPTY)
#define VALUE_STRING(__strsize, __eltrepr) \
      __ARRAY_VALUE(CFOK, child->text ? cf_opt_##__eltrepr(array->av[n].value, sizeof array->av[n].value, child->text) : CFEMPTY)
#define VALUE_NODE(__type, __eltrepr) \
      __ARRAY_VALUE(CFOK, cf_opt_##__eltrepr(&array->av[n].value, child))
#define VALUE_SUB_STRUCT(__structname) \
      __ARRAY_VALUE(cf_dfl_config_##__structname(&array->av[n].value), cf_opt_config_##__structname(&array->av[n].value, child))
#define VALUE_NODE_STRUCT(__structname, __eltrepr) \
      __ARRAY_VALUE(cf_dfl_config_##__structname(&array->av[n].value), cf_opt_##__eltrepr(&array->av[n].value, child))
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
#undef __ARRAY_KEY
#undef __ARRAY_VALUE
#undef END_ARRAY

// Generate config array search-by-key functions.
#define STRUCT(__name, __validator...)
#define NODE(__type, __element, __default, __repr, __flags, __comment)
#define ATOM(__type, __element, __default, __repr, __flags, __comment)
#define STRING(__size, __element, __default, __repr, __flags, __comment)
#define SUB_STRUCT(__name, __element, __flags)
#define NODE_STRUCT(__name, __element, __repr, __flags)
#define END_STRUCT
#define ARRAY(__name, __flags, __validator...) \
    int config_##__name##__get(const struct config_##__name *array,
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
	  const __type *key) { \
      int (*cmp)(const __type *, const __type *) = (NULL, ##__cmpfunc); \
      int i; \
      for (i = 0; i < array->ac; ++i) \
	if ((cmp ? (*cmp)(key, &array->av[i].key) : memcmp(key, &array->av[i].key, sizeof *key)) == 0) \
	  return i; \
      return -1; \
    }
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
	  const char *key) { \
      int (*cmp)(const char *, const char *) = (NULL, ##__cmpfunc); \
      int i; \
      for (i = 0; i < array->ac; ++i) \
	if ((cmp ? (*cmp)(key, array->av[i].key) : strcmp(key, array->av[i].key)) == 0) \
	  return i; \
      return -1; \
    }
#define VALUE_ATOM(__type, __eltrepr)
#define VALUE_STRING(__strsize, __eltrepr)
#define VALUE_NODE(__type, __eltrepr)
#define VALUE_SUB_STRUCT(__structname)
#define VALUE_NODE_STRUCT(__structname, __eltrepr)
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

// Generate config schema dump functions, cf_sch_config_NAME().
#define STRUCT(__name, __validator...) \
    int cf_sch_config_##__name(struct cf_om_node **rootp) { \
      int i; \
      struct cf_om_node **childp;
#define __ADD_CHILD(nodep, __elementstr) \
	if ((i = cf_om_add_child(nodep, __elementstr)) == -1) \
	  return -1; \
	childp = &(*nodep)->nodv[i];
#define __ATOM(nodep, __text) \
	if (((*nodep)->text = str_edup(__text)) == NULL) \
	  return -1;
#define __STRUCT(nodep, __structname) \
	if (cf_sch_config_##__structname(nodep) == -1) \
	  return -1;
#define NODE(__type, __element, __default, __repr, __flags, __comment) \
	__ADD_CHILD(rootp, #__element) \
	__ATOM(childp, "(" #__repr ")") \
	__ADD_CHILD(childp, "(" #__repr ")") \
	__ATOM(childp, "(" #__repr ")")
#define ATOM(__type, __element, __default, __repr, __flags, __comment) \
	__ADD_CHILD(rootp, #__element) \
	__ATOM(childp, "(" #__repr ")")
#define STRING(__size, __element, __default, __repr, __flags, __comment) \
	__ADD_CHILD(rootp, #__element) \
	__ATOM(childp, "(" #__repr ")")
#define SUB_STRUCT(__structname, __element, __flags) \
	__ADD_CHILD(rootp, #__element) \
	__STRUCT(childp, __structname)
#define NODE_STRUCT(__structname, __element, __repr, __flags) \
	__ADD_CHILD(rootp, #__element) \
	__ATOM(childp, "(" #__repr ")") \
	__STRUCT(childp, __structname)
#define END_STRUCT \
        return 0; \
    }
#define ARRAY(__name, __flags, __validator...) \
    int cf_sch_config_##__name(struct cf_om_node **rootp) { \
      int i; \
      struct cf_om_node **childp;
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
	__ADD_CHILD(rootp, "[" #__keyrepr "]")
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
	__ADD_CHILD(rootp, "[" #__keyrepr "]")
#define VALUE_ATOM(__type, __eltrepr) \
	__ATOM(childp, "(" #__eltrepr ")")
#define VALUE_STRING(__strsize, __eltrepr) \
	__ATOM(childp, "(" #__eltrepr ")")
#define VALUE_NODE(__type, __eltrepr) \
	__ATOM(childp, "(" #__eltrepr ")") \
	__ADD_CHILD(childp, "(" #__eltrepr ")") \
	__ATOM(childp, "(" #__eltrepr ")")
#define VALUE_SUB_STRUCT(__structname) \
	__STRUCT(childp, __structname)
#define VALUE_NODE_STRUCT(__structname, __eltrepr) \
	__ATOM(childp, "(" #__eltrepr ")") \
	__STRUCT(childp, __structname)

#define END_ARRAY(__size) \
        return 0; \
    }
#include "conf_schema.h"
#undef __ADD_CHILD
#undef __ATOM
#undef __STRUCT
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

// Generate formatting functions, cf_fmt_config_SECTION()
#define STRUCT(__name, __validator...) \
    int cf_fmt_config_##__name(struct cf_om_node **parentp, const struct config_##__name *strct) { \
      int result = CFOK; \
      int ret;
#define __FMT_TEXT(__repr, __eltname, __eltexpr, __defaultvar) \
	const char *text = NULL; \
	ret = cf_fmt_##__repr(&text, __eltexpr); \
	if (ret == CFOK) { \
	  int n; \
	  if (text == NULL) { \
	    WHY("cf_fmt_" #__repr "() returned CFOK but text=NULL"); \
	    ret = CFERROR; \
	  } else if ((n = cf_om_add_child(parentp, __eltname)) == -1) { \
	    ret = CFERROR; \
	  } else { \
	    (*parentp)->nodv[n]->text = text; \
	    (*parentp)->nodv[n]->line_number = is_default ? 0 : 1; \
	    text = NULL; \
	  } \
	} else if (ret == CFERROR || !is_default) \
	  WARNF("cf_fmt_" #__repr "() returned %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(300), ret))); \
	if (text) { \
	  free((char *)text); \
	  text = NULL; \
	} \
	if (ret == CFERROR) \
	  return CFERROR; \
	else if (ret != CFOK && !is_default) \
	  result |= (ret & CF__SUBFLAGS) | CFSUB(ret & CF__FLAGS);
#define __FMT_NODE(__fmtfunc, __element) \
      { \
	int n = cf_om_add_child(parentp, #__element); \
	if (n == -1) \
	  ret = CFERROR; \
	else { \
	  ret = __fmtfunc(&(*parentp)->nodv[n], &strct->__element); \
	  cf_om_remove_null_child(parentp, n); \
	  if (ret != CFOK) \
	    WARNF(#__fmtfunc "() returned %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(300), ret))); \
	  if (n < (*parentp)->nodc && cf_om_remove_empty_child(parentp, n)) { \
	    WHYF(#__fmtfunc "() returned empty node at n=%d", n); \
	    ret = CFERROR; \
	  } \
	} \
	if (ret == CFERROR) \
	  return CFERROR; \
	else if (ret != CFOK) \
	  result |= (ret & CF__SUBFLAGS) | CFSUB(ret & CF__FLAGS); \
      }
#define NODE(__type, __element, __default, __repr, __flags, __comment) \
      __FMT_NODE(cf_fmt_##__repr, __element)
#define ATOM(__type, __element, __default, __repr, __flags, __comment) \
      { \
	__type dfl = __default; \
	int is_default = cf_cmp_##__repr(&strct->__element, &dfl) == 0; \
	__FMT_TEXT(__repr, #__element, &strct->__element, __default) \
      }
#define STRING(__size, __element, __default, __repr, __flags, __comment) \
      { \
        int is_default = cf_cmp_##__repr(&strct->__element[0], __default) == 0; \
	__FMT_TEXT(__repr, #__element, &strct->__element[0], __default) \
      }
#define SUB_STRUCT(__structname, __element, __flags) \
      __FMT_NODE(cf_fmt_config_##__structname, __element)
#define NODE_STRUCT(__structname, __element, __repr, __flags) \
      __FMT_NODE(cf_fmt_##__repr, __element)
#define END_STRUCT \
      if ((*parentp)->nodc == 0) \
	cf_om_free_node(parentp); \
      return result; \
    }
#define ARRAY(__name, __flags, __validator...) \
    int cf_fmt_config_##__name(struct cf_om_node **parentp, const struct config_##__name *array) { \
      int result = CFOK; \
      int i; \
      for (i = 0; i < array->ac; ++i) {
#define __ARRAY_KEY(__keyfunc, __keyexpr) \
	const char *key = NULL; \
	int ret = __keyfunc(&key, __keyexpr); \
	int n = -1; \
	if (ret != CFOK) { \
	  WARNF(#__keyfunc "() returned %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(300), ret))); \
	} else if (key == NULL) { \
	  WHY(#__keyfunc "() returned CFOK but key=NULL"); \
	  ret = CFERROR; \
	} else { \
	  n = cf_om_add_child(parentp, key); \
	  if (n == -1) \
	    ret = CFERROR; \
	} \
	if (key) { \
	  free((char *)key); \
	  key = NULL; \
	} \
	if (ret == CFOK) {
#define __ARRAY_VALUE(__valuefunc) \
	  cf_om_remove_null_child(parentp, n); \
	  if (ret != CFOK) \
	    WARNF(#__valuefunc "() returned %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(300), ret))); \
	  if (n < (*parentp)->nodc && cf_om_remove_empty_child(parentp, n)) { \
	    WHYF(#__valuefunc "() returned empty node at n=%d", n); \
	    ret = CFERROR; \
	  }
#define __ARRAY_TEXT(__valuefunc, __eltexpr) \
	  ret = __valuefunc(&(*parentp)->nodv[n]->text, __eltexpr); \
	  __ARRAY_VALUE(__valuefunc)
#define __ARRAY_NODE(__valuefunc, __eltexpr) \
	  ret = __valuefunc(&(*parentp)->nodv[n], __eltexpr); \
	  __ARRAY_VALUE(__valuefunc)
#define END_ARRAY(__size) \
	} \
	if (ret == CFERROR) \
	  return CFERROR; \
	else if (ret != CFOK) \
	  result |= (ret & CF__SUBFLAGS) | CFSUB(ret & CF__FLAGS); \
      } \
      if ((*parentp)->nodc == 0) \
	cf_om_free_node(parentp); \
      return result; \
    }
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
	__ARRAY_KEY(cf_fmt_##__keyrepr, &array->av[i].key);
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
	__ARRAY_KEY(cf_fmt_##__keyrepr, &array->av[i].key[0]);
#define VALUE_ATOM(__type, __eltrepr) \
	__ARRAY_TEXT(cf_fmt_##__eltrepr, &array->av[i].value)
#define VALUE_STRING(__strsize, __eltrepr) \
	__ARRAY_TEXT(cf_fmt_##__eltrepr, &array->av[i].value[0])
#define VALUE_NODE(__type, __eltrepr) \
	__ARRAY_NODE(cf_fmt_##__eltrepr, &array->av[i].value)
#define VALUE_SUB_STRUCT(__structname) \
	__ARRAY_NODE(cf_fmt_config_##__structname, &array->av[i].value)
#define VALUE_NODE_STRUCT(__structname, __eltrepr) \
	__ARRAY_NODE(cf_fmt_##__eltrepr, &array->av[i].value)
#include "conf_schema.h"
#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __FMT_TEXT
#undef __FMT_NODE
#undef ARRAY
#undef KEY_ATOM
#undef KEY_STRING
#undef VALUE_ATOM
#undef VALUE_STRING
#undef VALUE_NODE
#undef VALUE_SUB_STRUCT
#undef VALUE_NODE_STRUCT
#undef __ARRAY_KEY
#undef __ARRAY_TEXT
#undef __ARRAY_NODE
#undef __ARRAY_VALUE
#undef END_ARRAY

// Generate comparison functions, cf_cmp_config_SECTION()
#define STRUCT(__name, __validator...) \
    int cf_cmp_config_##__name(const struct config_##__name *a, const struct config_##__name *b) { \
      int c;
#define NODE(__type, __element, __default, __repr, __flags, __comment) \
      if ((c = cf_cmp_##__repr(&a->__element, &b->__element))) \
	  return c;
#define ATOM(__type, __element, __default, __repr, __flags, __comment) \
      if ((c = cf_cmp_##__repr(&a->__element, &b->__element))) \
	  return c;
#define STRING(__size, __element, __default, __repr, __flags, __comment) \
      if ((c = cf_cmp_##__repr(&a->__element[0], &b->__element[0]))) \
	  return c;
#define SUB_STRUCT(__structname, __element, __flags) \
      if ((c = cf_cmp_config_##__structname(&a->__element, &b->__element))) \
	  return c;
#define NODE_STRUCT(__structname, __element, __repr, __flags) \
      if ((c = cf_cmp_##__repr(&a->__element, &b->__element))) \
	  return c;
#define END_STRUCT \
      return 0; \
    }
#define ARRAY(__name, __flags, __validator...) \
    int cf_cmp_config_##__name(const struct config_##__name *a, const struct config_##__name *b) { \
      int c; \
      int i; \
      for (i = 0; i < a->ac && i < b->ac; ++i) {
#define KEY_ATOM(__type, __keyrepr, __cmpfunc...) \
      if ((c = cf_cmp_##__keyrepr(&a->av[i].key, &b->av[i].key))) \
	  return c;
#define KEY_STRING(__strsize, __keyrepr, __cmpfunc...) \
      if ((c = cf_cmp_##__keyrepr(&a->av[i].key[0], &b->av[i].key[0]))) \
	  return c;
#define VALUE_ATOM(__type, __eltrepr) \
      if ((c = cf_cmp_##__eltrepr(&a->av[i].value, &b->av[i].value))) \
	  return c;
#define VALUE_STRING(__strsize, __eltrepr) \
      if ((c = cf_cmp_##__eltrepr(&a->av[i].value[0], &b->av[i].value[0]))) \
	  return c;
#define VALUE_NODE(__type, __eltrepr) \
      if ((c = cf_cmp_##__eltrepr(&a->av[i].value, &b->av[i].value))) \
	  return c;
#define VALUE_SUB_STRUCT(__structname) \
      if ((c = cf_cmp_config_##__structname(&a->av[i].value, &b->av[i].value))) \
	  return c;
#define VALUE_NODE_STRUCT(__structname, __eltrepr) \
      if ((c = cf_cmp_##__eltrepr(&a->av[i].value, &b->av[i].value))) \
	  return c;
#define END_ARRAY(__size) \
      } \
      return (a->ac < b->ac) ? -1 : (a->ac > b->ac) ? 1 : 0; \
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
