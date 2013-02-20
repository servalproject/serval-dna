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
 *          ATOM(int32_t, element1, 0, cf_opt_int32_nonnegative,, "An integer >= 0")
 *          STRING(80, element2, "boo!", cf_opt_str_nonempty, MANDATORY, "A non-empty string")
 *      END_STRUCT
 *
 *      ARRAY(joy,)
 *          KEY_STRING(3, happy, cf_opt_str)
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
 *          STRING(128, another_thing, "", cf_opt_uri,, "URL; protocol://hostname[:port][/path]")
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
 *      ARRAY(name, flags[, validatorfunc])
 *          key-declaration
 *          value-declaration
 *      END_ARRAY(size)
 *  
 *          where key-declaration is one of:
 *
 *          KEY_ATOM(type, parsefunc[, comparefunc])
 *          KEY_STRING(strlen, parsefunc[, comparefunc])
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
 * 'comparefunc'
 *      A function used to sort an array after all elements have been parsed, and before being
 *      validated (see below).
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

STRUCT(debug)
ATOM(char, verbose,		        0, cf_opt_char_boolean,, "")
ATOM(char, dnaresponses,		0, cf_opt_char_boolean,, "")
ATOM(char, dnahelper,		        0, cf_opt_char_boolean,, "")
ATOM(char, queues,		        0, cf_opt_char_boolean,, "")
ATOM(char, timing,		        0, cf_opt_char_boolean,, "")
ATOM(char, io,		                0, cf_opt_char_boolean,, "")
ATOM(char, verbose_io,		        0, cf_opt_char_boolean,, "")
ATOM(char, packetformats,		0, cf_opt_char_boolean,, "")
ATOM(char, gateway,		        0, cf_opt_char_boolean,, "")
ATOM(char, keyring,		        0, cf_opt_char_boolean,, "")
ATOM(char, security,		        0, cf_opt_char_boolean,, "")
ATOM(char, mdprequests,		        0, cf_opt_char_boolean,, "")
ATOM(char, peers,		        0, cf_opt_char_boolean,, "")
ATOM(char, overlayframes,		0, cf_opt_char_boolean,, "")
ATOM(char, overlayabbreviations,	0, cf_opt_char_boolean,, "")
ATOM(char, overlayrouting,		0, cf_opt_char_boolean,, "")
ATOM(char, overlayroutemonitor,		0, cf_opt_char_boolean,, "")
ATOM(char, overlayinterfaces,		0, cf_opt_char_boolean,, "")
ATOM(char, broadcasts,		        0, cf_opt_char_boolean,, "")
ATOM(char, packettx,		        0, cf_opt_char_boolean,, "")
ATOM(char, packetrx,		        0, cf_opt_char_boolean,, "")
ATOM(char, packetradio,		        0, cf_opt_char_boolean,, "")
ATOM(char, rejecteddata,		0, cf_opt_char_boolean,, "")
ATOM(char, slip,		        0, cf_opt_char_boolean,, "")
ATOM(char, slipdecode,		        0, cf_opt_char_boolean,, "")
ATOM(char, packetconstruction,		0, cf_opt_char_boolean,, "")
ATOM(char, rhizome,		        0, cf_opt_char_boolean,, "")
ATOM(char, rhizome_tx,		        0, cf_opt_char_boolean,, "")
ATOM(char, rhizome_rx,		        0, cf_opt_char_boolean,, "")
ATOM(char, rhizome_ads,		        0, cf_opt_char_boolean,, "")
ATOM(char, manifests,		        0, cf_opt_char_boolean,, "")
ATOM(char, vomp,		        0, cf_opt_char_boolean,, "")
ATOM(char, trace,		        0, cf_opt_char_boolean,, "")
ATOM(char, profiling,		        0, cf_opt_char_boolean,, "")
ATOM(char, externalblobs,		0, cf_opt_char_boolean,, "")
END_STRUCT

STRUCT(log)
STRING(256,                 file,       "", cf_opt_str_nonempty,, "Path of log file, either absolute or relative to instance directory")
ATOM(int,                   show_pid,   1, cf_opt_int_boolean,, "If true, all log lines contain PID of logging process")
ATOM(int,                   show_time,  1, cf_opt_int_boolean,, "If true, all log lines contain time stamp")
END_STRUCT

STRUCT(server)
STRING(256,                 chdir,      "/", cf_opt_absolute_path,, "Absolute path of chdir(2) for server process")
STRING(256,                 interface_path, "", cf_opt_str_nonempty,, "Path of directory containing interface files, either absolute or relative to instance directory")
ATOM(int,                   respawn_on_crash, 0, cf_opt_int_boolean,, "If true, server will exec(2) itself on fatal signals, eg SEGV")
END_STRUCT

STRUCT(monitor)
STRING(256,                 socket,     DEFAULT_MONITOR_SOCKET_NAME, cf_opt_str_nonempty,, "Name of socket for monitor interface")
ATOM(int,                   uid,        -1, cf_opt_int,, "Allowed UID for monitor socket client")
END_STRUCT

STRUCT(mdp_iftype)
ATOM(uint32_t,              tick_ms,    -1, cf_opt_uint32_nonzero,, "Tick interval for this interface type")
ATOM(int,                   packet_interval,    -1, cf_opt_int,, "Minimum interval between packets in microseconds")
END_STRUCT

ARRAY(mdp_iftypelist, NO_DUPLICATES)
KEY_ATOM(short, cf_opt_interface_type, cmp_short)
VALUE_SUB_STRUCT(mdp_iftype)
END_ARRAY(5)

STRUCT(mdp)
STRING(256,                 socket,     DEFAULT_MDP_SOCKET_NAME, cf_opt_str_nonempty,, "Name of socket for MDP client interface")
SUB_STRUCT(mdp_iftypelist,  iftype,)
END_STRUCT

STRUCT(olsr)
ATOM(int,                   enable,     1, cf_opt_int_boolean,, "If true, OLSR is used for mesh routing")
ATOM(uint16_t,              remote_port,4130, cf_opt_uint16_nonzero,, "Remote port number")
ATOM(uint16_t,              local_port, 4131, cf_opt_uint16_nonzero,, "Local port number")
END_STRUCT

ARRAY(argv, SORTED NO_DUPLICATES, vld_argv)
KEY_ATOM(unsigned short, cf_opt_ushort_nonzero, cmp_ushort)
VALUE_STRING(128, cf_opt_str)
END_ARRAY(16)

STRUCT(executable)
STRING(256,                 executable, "", cf_opt_absolute_path, MANDATORY, "Absolute path of dna helper executable")
SUB_STRUCT(argv,            argv,)
END_STRUCT

STRUCT(dna)
SUB_STRUCT(executable,      helper,)
END_STRUCT

STRUCT(rhizome_peer)
STRING(25,                  protocol,   "http", cf_opt_protocol,, "Protocol name")
STRING(256,                 host,       "", cf_opt_str_nonempty, MANDATORY, "Host name or IP address")
ATOM(uint16_t,              port,       RHIZOME_HTTP_PORT, cf_opt_uint16_nonzero,, "Port number")
END_STRUCT

ARRAY(peerlist,)
KEY_STRING(15, cf_opt_str)
VALUE_NODE_STRUCT(rhizome_peer, cf_opt_rhizome_peer)
END_ARRAY(10)

STRUCT(rhizome_direct)
SUB_STRUCT(peerlist,        peer,)
END_STRUCT

STRUCT(rhizome_api_addfile)
STRING(64,                  uri_path, "", cf_opt_absolute_path,, "URI path for HTTP add-file request")
ATOM(struct in_addr,        allow_host, hton_in_addr(INADDR_LOOPBACK), cf_opt_in_addr,, "IP address of host allowed to make HTTP add-file request")
STRING(256,                 manifest_template_file, "", cf_opt_str_nonempty,, "Path of manifest template file, either absolute or relative to instance directory")
ATOM(sid_t,                 default_author, SID_ANY, cf_opt_sid,, "Author of add-file bundle if sender not given")
ATOM(rhizome_bk_t,          bundle_secret_key, RHIZOME_BK_NONE, cf_opt_rhizome_bk,, "Secret key of add-file bundle to try if sender not given")
END_STRUCT

STRUCT(rhizome_api)
SUB_STRUCT(rhizome_api_addfile, addfile,)
END_STRUCT

STRUCT(rhizome_http)
ATOM(int,                   enable,     1, cf_opt_int_boolean,, "If true, Rhizome HTTP server is started")
END_STRUCT

STRUCT(rhizome_mdp)
ATOM(int,                   enable,     1, cf_opt_int_boolean,, "If true, Rhizome MDP server is started")
END_STRUCT

STRUCT(rhizome_advertise)
ATOM(int,                   enable,     1, cf_opt_int_boolean,, "If true, Rhizome advertisements are sent")
ATOM(uint32_t,              interval,   500, cf_opt_uint32_nonzero,, "Interval between Rhizome advertisements")
END_STRUCT

STRUCT(rhizome)
ATOM(int,                   enable,     1, cf_opt_int_boolean,, "If true, server opens Rhizome database when starting")
ATOM(int,                   clean_on_open, 1, cf_opt_int_boolean,, "If true, Rhizome database is cleaned at start of every command")
STRING(256,                 datastore_path, "", cf_opt_absolute_path,, "Path of rhizome storage directory, absolute or relative to instance directory")
ATOM(uint64_t,              database_size, 1000000, cf_opt_uint64_scaled,, "Size of database in bytes")
ATOM(char,                  external_blobs, 0, cf_opt_char_boolean,, "Store rhizome bundles as separate files.")

ATOM(uint64_t,              rhizome_mdp_block_size, 512, cf_opt_uint64_scaled,, "Rhizome MDP block size.")
ATOM(uint64_t,              idle_timeout, RHIZOME_IDLE_TIMEOUT, cf_opt_uint64_scaled,, "Rhizome transfer timeout if no data received.")
ATOM(uint32_t,              fetch_delay_ms, 50, cf_opt_uint32_nonzero,, "Delay from receiving first bundle advert to initiating fetch")
SUB_STRUCT(rhizome_direct,  direct,)
SUB_STRUCT(rhizome_api,     api,)
SUB_STRUCT(rhizome_http,    http,)
SUB_STRUCT(rhizome_mdp,     mdp,)
SUB_STRUCT(rhizome_advertise, advertise,)
END_STRUCT

STRUCT(directory)
ATOM(sid_t,                 service,     SID_ANY, cf_opt_sid,, "Subscriber ID of Serval Directory Service")
END_STRUCT

STRUCT(host)
STRING(INTERFACE_NAME_STRLEN, interface, "", cf_opt_str_nonempty,, "Interface name")
STRING(256,                 host,       "", cf_opt_str_nonempty,, "Host Name")
ATOM(struct in_addr,        address,    hton_in_addr(INADDR_NONE), cf_opt_in_addr,, "Host IP address")
ATOM(uint16_t,              port,       PORT_DNA, cf_opt_uint16_nonzero,, "Port number")
END_STRUCT

ARRAY(host_list, NO_DUPLICATES)
KEY_ATOM(sid_t, cf_opt_sid, cmp_sid)
VALUE_SUB_STRUCT(host)
END_ARRAY(32)

STRUCT(network_interface, vld_network_interface)
ATOM(int,                   exclude,    0, cf_opt_int_boolean,, "If true, do not use matching interfaces")
ATOM(struct pattern_list,   match,      PATTERN_LIST_EMPTY, cf_opt_pattern_list,, "Names that match network interface")
ATOM(int,                   socket_type,  SOCK_UNSPECIFIED, cf_opt_socket_type,, "Type of network socket")
ATOM(int,                   encapsulation, ENCAP_OVERLAY, cf_opt_encapsulation,, "Type of packet encapsulation")
STRING(256,                 file,      "", cf_opt_str_nonempty,, "Path of interface file, absolute or relative to server.interface_path")
ATOM(struct in_addr,        dummy_address,    hton_in_addr(INADDR_LOOPBACK), cf_opt_in_addr,, "Dummy interface address")
ATOM(struct in_addr,        dummy_netmask,    hton_in_addr(0xFFFFFF00), cf_opt_in_addr,, "Dummy interface netmask")
ATOM(uint16_t,              port,       PORT_DNA, cf_opt_uint16_nonzero,, "Port number for network interface")
ATOM(char,                  drop_broadcasts,     0, cf_opt_char_boolean,, "If true, drop all incoming broadcast packets")
ATOM(char,                  drop_unicasts,     0, cf_opt_char_boolean,, "If true, drop all incoming unicast packets")
ATOM(short,                 type,       OVERLAY_INTERFACE_WIFI, cf_opt_interface_type,, "Type of network interface")
ATOM(int,                   packet_interval,    -1, cf_opt_int,, "Minimum interval between packets in microseconds")
ATOM(int,                   mdp_tick_ms, -1, cf_opt_int32_nonneg,, "Override MDP tick interval for this interface")
ATOM(char,                  send_broadcasts, 1, cf_opt_char_boolean,, "If false, don't send any broadcast packets")
ATOM(char,                  default_route, 0, cf_opt_char_boolean,, "If true, use this interface as a default route")
ATOM(char,                  prefer_unicast, 0, cf_opt_char_boolean,, "If true, send unicast data as unicast IP packets if available")
END_STRUCT

ARRAY(interface_list, SORTED NO_DUPLICATES)
KEY_ATOM(unsigned, cf_opt_uint)
VALUE_NODE_STRUCT(network_interface, cf_opt_network_interface)
END_ARRAY(10)

// The top level.
STRUCT(main)
NODE_STRUCT(interface_list, interfaces, cf_opt_interface_list,)
SUB_STRUCT(log,             log,)
SUB_STRUCT(server,          server,)
SUB_STRUCT(monitor,         monitor,)
SUB_STRUCT(mdp,             mdp,)
SUB_STRUCT(dna,             dna,)
SUB_STRUCT(debug,           debug,)
SUB_STRUCT(rhizome,         rhizome,)
SUB_STRUCT(directory,       directory,)
SUB_STRUCT(olsr,            olsr,)
SUB_STRUCT(host_list,       hosts,)
END_STRUCT
