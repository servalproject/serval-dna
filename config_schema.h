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

/* This file contains definitions for the schema of the Serval DNA configuration file.  See comments
 * in "config.h" for a description of the internal configuration API.
 *
 * A configuration schema is set of nested structures and arrays.  By convention, the top level, or
 * root of the schema is called "main", but every structure and array has its own complete API which
 * can be used by itself.  So if there were two independent configuration files, both could be
 * defined in this file, each with a conventional name for its own root element.
 *
 * To describe a configuration file that looks like this:
 *
 *      some.thing.element1=integer
 *      some.thing.element2=string
 *      some.list.foo.element1=integer
 *      some.list.foo.element2=string
 *      some.list.bar.element1=integer
 *      some.list.bar.element2=string
 *      another_thing=http://my.host.com:1234/path/to/nowhere
 *
 * the following schema would do:
 *
 *      STRUCT(happy)
 *          ATOM(int32_t, element1, 0, opt_int32_nonnegative,, "An integer >= 0")
 *          STRING(80, element2, "boo!", opt_str_nonempty, MANDATORY, "A non-empty string")
 *      END_STRUCT
 *
 *      ARRAY_STRUCT(joy, 16, happy, "An array of integer-string pairs")
 *
 *      STRUCT(love)
 *          SUB_STRUCT(happy, thing,)
 *          SUB_STRUCT(joy, list,)
 *      END_STRUCT
 *
 *      STRUCT(main)
 *          SUB_STRUCT(love, some,)
 *          STRING(128, another_thing, "", opt_uri,, "URL; protocol://hostname[:port][/path]")
 *      END_STRUCT
 *
 * which would produce an API based on the following definitions (see "config.h" for more
 * information):
 *
 *      struct config_happy {
 *          int32_t element1;
 *          char element2[81];
 *      };
 *      struct config_joy {
 *          unsigned ac;
 *          struct {
 *              char label[N]; // please discover N using sizeof()
 *              struct config_happy value;
 *          } av[16];
 *      };
 *      struct config_love {
 *          struct config_happy thing;
 *          struct config_joy list;
 *      };
 *      struct config_main {
 *          struct config_love some;
 *          char another_thing[129];
 *      };
 *
 * A schema definition is composed from the following STRUCT and ARRAY definitions:
 *
 *      STRUCT(name)
 *          ATOM(type, element, default, parsefunc, flags, comment)
 *          NODE(type, element, default, parsefunc, flags, comment)
 *          STRING(size, element, default, parsefunc, flags, comment)
 *          SUB_STRUCT(structname, element, flags)
 *          NODE_STRUCT(structname, element, parsefunc, flags)
 *      END_STRUCT
 *
 *      ARRAY_ATOM(name, size, type, parsefunc, comment)
 *      ARRAY_STRING(name, size, strsize, parsefunc, comment)
 *      ARRAY_NODE(name, size, type, parsefunc, comment)
 *      ARRAY_STRUCT(name, size, structname, comment)
 *
 * The meanings of the parameters are:
 *
 * 'name'
 *      A label used to qualify this struct/array's API from the API components of other structs and
 *      arrays.  This label does not appear anywhere in the config file itself; it is purely for
 *      internal code-related purposes.
 * 'type'
 *      Only used for ATOM, NODE, ARRAY_ATOM and ARRAY_NODE declarations.  Gives the C type of the
 *      element.  For STRING and ARRAY_STRING, this is implicitly (const char *).
 * 'structname'
 *      Only used for SUB_STRUCT, NODE_STRUCT and ARRAY_STRUCT declarations.  Identifies a sub-
 *      structure by 'name' to nest in the enclosing struct or array.
 * 'element'
 *      The name of the struct element and the key in the configuration file.  This name does appear
 *      in the config file and also in the API, so that an option mamed "some.thing.element1" in the
 *      file is referred to as some.thing.element1 in the C code.  Arrays are more complicated:
 *      "some.list.foo.element1" in the config file is referred to as some.list.av[n].value.element1
 *      in the C code, and some.list.ac gives the size of the some.list.av array.
 * 'default'
 *      Only used for ATOM and NODE struct elements.  Gives the default value for the element if
 *      absent from the config file.
 * 'parsefunc'
 *      The function used to parse the value from the config file.  The ATOM, STRING, ARRAY_ATOM and
 *      ARRAY_STRING parse functions take a string argument (const char *).  The NODE, NODE_STRUCT
 *      and ARRAY_NODE parse functions take a pointer to a COM node (const struct cf_om_node).
 * 'flags'
 *      A space-separated list of flags.  At present only the MANDATORY flag is supported, which
 *      will cause parsing to fail if the given STRUCT element is not set in the config file.  In
 *      the case of struct elements that are arrays, the config file must set at least one element
 *      of the array, or parsing fails.
 * 'comment'
 *      A human-readable string describing the value of the configuration option.  Must be
 *      informative enough to help users diagnose parse errors.  Eg, "An integer" is not enough;
 *      better would be "Integer >= 0, number of seconds since Unix epoch".
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

STRUCT(log)
STRING(256,                 file,       "", opt_absolute_path,, "Absolute path of log file")
ATOM(int,                   show_pid,   1, opt_boolean,, "If true, all log lines contain PID of logging process")
ATOM(int,                   show_time,  1, opt_boolean,, "If true, all log lines contain time stamp")
END_STRUCT

STRUCT(server)
STRING(256,                 chdir,      "/", opt_absolute_path,, "Absolute path of chdir(2) for server process")
END_STRUCT

ARRAY_STRING(argv, 8, 128, opt_str, "Array of arguments to pass to command")

STRUCT(dnahelper)
STRING(256,                 executable, "", opt_absolute_path,, "Absolute path of dna helper executable")
SUB_STRUCT(argv,            argv,)
END_STRUCT

STRUCT(dna)
SUB_STRUCT(dnahelper,       helper,)
END_STRUCT

STRUCT(rhizomepeer)
STRING(25,                  protocol,   "http", opt_protocol,, "Protocol name")
STRING(256,                 host,       "", opt_str_nonempty, MANDATORY, "Host name or IP address")
ATOM(uint16_t,              port,       RHIZOME_HTTP_PORT, opt_port,, "Port number")
END_STRUCT

ARRAY_NODE(peerlist, 10, struct config_rhizomepeer, opt_rhizome_peer, "Rhizome peers")

STRUCT(rhizomedirect)
SUB_STRUCT(peerlist,        peer,)
END_STRUCT

STRUCT(rhizome)
STRING(256,                 path,       "", opt_absolute_path,, "Absolute path of rhizome directory")
ATOM(int,                   enabled,    1, opt_boolean,, "If true, Rhizome HTTP server is started")
SUB_STRUCT(rhizomedirect,   direct,)
END_STRUCT

STRUCT(directory)
ATOM(sid_t,                 service,     SID_NONE, opt_sid,, "Subscriber ID of Serval Directory Service")
END_STRUCT

STRUCT(network_interface)
ATOM(int,                   exclude,    0, opt_boolean,, "If true, do not use matching interfaces")
ATOM(struct pattern_list,   match,      PATTERN_LIST_EMPTY, opt_pattern_list, MANDATORY, "Names that match network interface")
ATOM(short,                 type,       OVERLAY_INTERFACE_WIFI, opt_interface_type,, "Type of network interface")
ATOM(uint16_t,              port,       RHIZOME_HTTP_PORT, opt_port,, "Port number for network interface")
ATOM(uint64_t,              speed,      1000000, opt_uint64_scaled,, "Speed in bits per second")
END_STRUCT

ARRAY_STRUCT(interface_list, 10, network_interface, "Network interfaces")

STRUCT(main)
NODE_STRUCT(interface_list, interfaces, opt_interface_list, MANDATORY)
SUB_STRUCT(log,             log,)
SUB_STRUCT(server,          server,)
SUB_STRUCT(dna,             dna,)
NODE(debugflags_t,          debug,      0, opt_debugflags, USES_CHILDREN, "Debug flags")
SUB_STRUCT(rhizome,         rhizome,)
SUB_STRUCT(directory,       directory,)
END_STRUCT
