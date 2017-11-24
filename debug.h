/*
Copyright (C) 2015 Serval Project Inc.
Copyright (C) 2017 Flinders University
 
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

#ifndef __SERVAL_DNA__DEBUG_H
#define __SERVAL_DNA__DEBUG_H

/* This header file must not be included by other header files (.h), only by
 * source files (.c), because it defines macros (DEBUG being the primary
 * offender) that can interfere with other projects that include Serval DNA
 * header files, such as the iOS ServalDNA.framework.
 */

#include "log.h" // for _DEBUGF_TAG
#include "idebug.h" // for struct idebug

/* These DEBUG macros use the IF_DEBUG(FLAG) macro as the conditional.
 *
 * The compilation environment may define IF_DEBUG(FLAG) to be constant (0) to
 * disable all debug statements, which should omit them from the compilation
 * altogether if the compiler is optimising properly.
 *
 * Alternatively, the compilation environment may define IF_DEBUG(FLAG) to be
 * constant (1) to enable all debug statements unconditionally, which will
 * produce a large and verbose executable.
 *
 * The common definition of IF_DEBUG(FLAG) will use FLAG to index into a local
 * struct of debug flags; see "conf.h".
 */

#define DEBUGF(FLAG,F,...)           do { if (IF_DEBUG(FLAG)) _DEBUGF_TAG(#FLAG, F, ##__VA_ARGS__); } while (0)
#define DEBUGF2(FLAG1,FLAG2,F,...)   do { if (IF_DEBUG(FLAG1) || IF_DEBUG(FLAG2)) _DEBUGF_TAG((IF_DEBUG(FLAG1) ? #FLAG1 : #FLAG2), F, ##__VA_ARGS__); } while (0)
#define DEBUG(FLAG,X)                DEBUGF(FLAG, "%s", (X))
#define DEBUGF_perror(FLAG,F,...)    do { if (IF_DEBUG(FLAG)) _DEBUGF_TAG_perror(#FLAG, F, ##__VA_ARGS__); } while (0)
#define DEBUG_perror(FLAG,X)         DEBUGF_perror(FLAG, "%s", (X))
#define DEBUG_argv(FLAG,X,ARGC,ARGV) do { if (IF_DEBUG(FLAG)) _DEBUG_TAG_argv(#FLAG, X, (ARGC), (ARGV)); } while (0)
#define DEBUG_dump(FLAG,X,ADDR,LEN)  do { if (IF_DEBUG(FLAG)) _DEBUG_TAG_dump(#FLAG, X, (ADDR), (LEN)); } while (0)

#define D(FLAG)                   DEBUG(FLAG, "D")
#define T                         DEBUG(trace, "T")

/* These IDEBUG macros use the IF_IDEBUG(IND) macro as the conditional.
 *
 * An "indirect debug flag" is a struct that contains a pointer to a flag and a
 * string constant with the name of the flag.
 */

#define INDIRECT_CONFIG_DEBUG(FLAG) ((struct idebug){.flagp=&(config.debug.FLAG), .flagname=#FLAG})

#define IF_IDEBUG(IND)              ((IND).flagp && *(IND).flagp)
#define IDEBUG_TAG(IND)             ((IND).flagname ? (IND).flagname : "")

#define IDEBUGF(IND,F,...)          do { if (IF_IDEBUG(IND)) _DEBUGF_TAG(IDEBUG_TAG(IND), F, ##__VA_ARGS__); } while (0)
#define IDEBUG(IND,X)               IDEBUGF(IND, "%s", (X))
#define IDEBUGF_perror(IND,F,...)   do { if (IF_IDEBUG(IND)) _DEBUGF_TAG_perror(IDEBUG_TAG(IND), F, ##__VA_ARGS__); } while (0)
#define IDEBUG_perror(IND,X)        IDEBUGF_perror(IND, "%s", (X))

#endif // __SERVAL_DNA__DEBUG_H
