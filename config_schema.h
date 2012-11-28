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
 * A configuration file consists of lines of the form:
 *
 *      FULLKEY "=" VALUE "\n"
 *
 * where FULLKEY has the form KEY [ "." KEY [ "." KEY [ ... ] ] ] and VALUE is any string not
 * containing newline.  Lines ending with "\r\n" have the "\r" stripped from the end of VALUE.
 * Otherwise VALUE is preserved exactly, with all leading and trailing spaces intact.
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
 *      ARRAY(joy)
 *          KEY_STRING(3, happy, opt_str)
 *          VALUE_SUB_STRUCT(happy)
 *      END_ARRAY(16)
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
 *          struct config_joy__element {
 *              char key[4];
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
 *      STRUCT(name[, validatorfunc])
 *          element-declaration
 *          element-declaration
 *          ...
 *      END_STRUCT
 *
 *          where each element-declaration is one of:
 *
 *          ATOM(type, element, default, parsefunc, flags, comment)
 *          NODE(type, element, default, parsefunc, flags, comment)
 *          STRING(strlen, element, default, parsefunc, flags, comment)
 *          SUB_STRUCT(structname, element, flags)
 *          NODE_STRUCT(structname, element, parsefunc, flags)
 *
 *      ARRAY(name[, validatorfunc])
 *          key-declaration
 *          value-declaration
 *      END_ARRAY(size)
 *  
 *          where key-declaration is one of:
 *
 *          KEY_ATOM(type, parsefunc)
 *          KEY_STRING(strlen, parsefunc)
 *
 *          and value-declaration is one of:
 *
 *          VALUE_ATOM(type, parsefunc)
 *          VALUE_STRING(strlen, parsefunc)
 *          VALUE_NODE(type, parsefunc)
 *          VALUE_SUB_STRUCT(structname)
 *          VALUE_NODE_STRUCT(structname, parsefunc)
 *
 * The meanings of the parameters are:
 *
 * 'name'
 *      A label used to qualify this struct/array's API from the API components of other structs and
 *      arrays.  This label does not appear anywhere in the config file itself; it is purely for
 *      internal code-related purposes.
 * 'strlen'
 *      For STRING, LABEL_STRING and VALUE_STRING, gives the maximum length of the string.  The
 *      string is declared as an array of char[strlen+1] to leave room for a terminating nul.
 * 'size'
 *      For all ARRAYs, gives the maximum size of the array.
 * 'type'
 *      Used for ATOM, NODE, LABEL_ATOM, VALUE_ATOM and VALUE_NODE declarations.  Gives the C type
 *      of the element.  For STRING, KEY_STRING and VALUE_STRING this is implicitly a char[].
 * 'structname'
 *      Only used for SUB_STRUCT, NODE_STRUCT, VALUE_SUB_STRUCT and VALUE_NODE_STRUCT declarations.
 *      Identifies a sub- structure by 'name' to nest in the enclosing struct or array.
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
 *      The function used to parse a VALUE from the config file for a STRUCT element, or a KEY or
 *      VALUE for an array element.  Parse functions for ATOM, STRING, KEY_ATOM, KEY_STRING,
 *      VALUE_ATOM and VALUE_STRING all take a string argument (const char *) which is a
 *      nul-terminated text.  The parse functions for NODE, NODE_STRUCT, VALUE_NODE and
 *      VALUE_NODE_STRUCT take a pointer to a COM node (const struct cf_om_node *), and are
 *      responsible for parsing the node's text and all of its descendents (children).
 * 'validatorfunc'
 *      A function that is called after the struct/array is fully parsed and populated.  This
 *      function can perform validation checks on the whole struct/array that cannot be performed by
 *      the parse functions of each element in isolation, and can even alter the contents of the
 *      struct/array, eg, sort an array or fill in default values in structs that depend on other
 *      elements.  Takes as its second argument the CFxxx code produced by the parser, and returns
 *      an updated CFxxx result code (which could be the same) as documented in "config.h".
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

STRUCT(monitor)
STRING(256,                 socket,     DEFAULT_MONITOR_SOCKET_NAME, opt_str_nonempty,, "Name of socket for monitor interface")
ATOM(int,                   uid,        -1, opt_int,, "Allowed UID for monitor socket client")
END_STRUCT

STRUCT(mdp_iftype)
ATOM(uint32_t,              tick_ms,    0, opt_uint32_nonzero,, "Tick interval for this interface type")
END_STRUCT

ARRAY(mdp_iftypelist)
KEY_ATOM(short, opt_interface_type)
VALUE_SUB_STRUCT(mdp_iftype)
END_ARRAY(5)

STRUCT(mdp)
ATOM(uint32_t,              ticks_per_full_address, 4, opt_uint32_nonzero,, "Ticks to elapse between announcing full SID")
SUB_STRUCT(mdp_iftypelist,  iftype,)
END_STRUCT

ARRAY(argv, vld_argv)
KEY_ATOM(unsigned short, opt_ushort_nonzero)
VALUE_STRING(128, opt_str)
END_ARRAY(16)

STRUCT(executable)
STRING(256,                 executable, "", opt_absolute_path, MANDATORY, "Absolute path of dna helper executable")
SUB_STRUCT(argv,            argv,)
END_STRUCT

STRUCT(dna)
SUB_STRUCT(executable,      helper,)
END_STRUCT

STRUCT(rhizomepeer)
STRING(25,                  protocol,   "http", opt_protocol,, "Protocol name")
STRING(256,                 host,       "", opt_str_nonempty, MANDATORY, "Host name or IP address")
ATOM(uint16_t,              port,       RHIZOME_HTTP_PORT, opt_port,, "Port number")
END_STRUCT

ARRAY(peerlist)
KEY_STRING(15, opt_str)
VALUE_NODE(struct config_rhizomepeer, opt_rhizome_peer)
END_ARRAY(10)

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

STRUCT(host)
STRING(INTERFACE_NAME_STRLEN, interface, "", opt_str_nonempty, MANDATORY, "Interface name")
ATOM(struct in_addr,        address,    (struct in_addr){0}, opt_in_addr, MANDATORY, "Host IP address")
ATOM(uint16_t,              port,       PORT_DNA, opt_port,, "Port number")
END_STRUCT

ARRAY(host_list)
KEY_ATOM(sid_t, opt_sid)
VALUE_SUB_STRUCT(host)
END_ARRAY(32)

STRUCT(network_interface)
ATOM(int,                   exclude,    0, opt_boolean,, "If true, do not use matching interfaces")
ATOM(struct pattern_list,   match,      PATTERN_LIST_EMPTY, opt_pattern_list, MANDATORY, "Names that match network interface")
ATOM(short,                 type,       OVERLAY_INTERFACE_WIFI, opt_interface_type,, "Type of network interface")
ATOM(uint16_t,              port,       RHIZOME_HTTP_PORT, opt_port,, "Port number for network interface")
ATOM(uint64_t,              speed,      1000000, opt_uint64_scaled,, "Speed in bits per second")
ATOM(uint32_t,              mdp_tick_ms, 0, opt_uint32_nonzero,, "Override MDP tick interval for this interface")
END_STRUCT

ARRAY(interface_list)
KEY_STRING(15, opt_str)
VALUE_SUB_STRUCT(network_interface)
END_ARRAY(10)

STRUCT(main)
NODE_STRUCT(interface_list, interfaces, opt_interface_list, MANDATORY)
SUB_STRUCT(log,             log,)
SUB_STRUCT(server,          server,)
SUB_STRUCT(monitor,         monitor,)
SUB_STRUCT(mdp,             mdp,)
SUB_STRUCT(dna,             dna,)
NODE(debugflags_t,          debug,      0, opt_debugflags, USES_CHILDREN, "Debug flags")
SUB_STRUCT(rhizome,         rhizome,)
SUB_STRUCT(directory,       directory,)
SUB_STRUCT(host_list,       hosts,)
END_STRUCT
