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
 *          ATOM(int32_t, element1, 0, int32_nonneg,, "An integer >= 0")
 *          STRING(80, element2, "boo!", str_nonempty, MANDATORY, "A non-empty string")
 *      END_STRUCT
 *
 *      ARRAY(joy,)
 *          KEY_STRING(3, happy, str)
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
 *          STRING(128, another_thing, "", uri,, "URL; protocol://hostname[:port][/path]")
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
 *      STRUCT(name [, validatorfunc])
 *          element-declaration
 *          element-declaration
 *          ...
 *      END_STRUCT
 *
 *          where each element-declaration is one of:
 *
 *          ATOM(type, element, default, repr, flags, comment)
 *          NODE(type, element, default, repr, flags, comment)
 *          STRING(strlen, element, default, repr, flags, comment)
 *          SUB_STRUCT(structname, element, flags [, default_label])
 *          NODE_STRUCT(structname, element, repr, flags [, default_label])
 *
 *      ARRAY(name, flags [, validatorfunc])
 *          key-declaration
 *          value-declaration
 *      END_ARRAY(size)
 *
 *          where key-declaration is one of:
 *
 *          KEY_ATOM(type, repr)
 *          KEY_STRING(strlen, repr)
 *
 *          and value-declaration is one of:
 *
 *          VALUE_ATOM(type, repr)
 *          VALUE_STRING(strlen, repr)
 *          VALUE_NODE(type, repr)
 *          VALUE_SUB_STRUCT(structname)
 *          VALUE_NODE_STRUCT(structname, repr)
 *
 * For defining alternative STRUCT default settings:
 *
 *      STRUCT_DEFAULT(name, default_label)
 *          default-declaration
 *          default-declaration
 *          ...
 *      END_STRUCT_DEFAULT
 *
 *          where each default-declaration is one of:
 *
 *          ATOM_DEFAULT(element, default)
 *          STRING_DEFAULT(element, default)
 *          SUB_STRUCT_DEFAULT(structname, element [, default_label])
 *
 *      Every structure defined by STRUCT has its own, native default values as given by
 *      the 'default' parameter in each of its element declarations.  The STRUCT_DEFAULT
 *      declaration defines a variation on the default values that can be used to give the
 *      structure alternative defaults when included as a SUB_STRUCT (or NODE_STRUCT) from
 *      within another structure.  Not all the STRUCT's elements have to be defined within
 *      a STRUCT_DEFAULT definition; any omitted ones take the STRUCT's native default.
 *
 * For defining that one STRUCT can be treated as a subset of another:
 *
 *      STRUCT_ASSIGN(substruct, superstruct)
 *          element-declaration
 *          element-declaration
 *          ...
 *      END_STRUCT_ASSIGN
 *
 *          where element-declaration is exactly as for STRUCT(...) above.
 *
 *      This generates a structure copy function that copies the given elements of 'substruct'
 *      into the equivalent elements of 'superstruct'; ie, both structures must have the same
 *      element names and types.
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
 *      of the element.  For STRING, KEY_STRING and VALUE_STRING this is implicitly char[strlen+1].
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
 * 'repr'
 *      The string representation.  This name specifies a trio of functions, cf_opt_<repr>(),
 *      cf_fmt_<repr>() and cf_cmp_<repr>():
 *       - The cf_opt_<repr>() functions for ATOM, STRING, KEY_ATOM, KEY_STRING, VALUE_ATOM and
 *         VALUE_STRING take a (const char *) argument pointing to nul-terminated text.  The
 *         <repr> functions for NODE and VALUE_NODE take a pointer to a COM node (const
 *         struct cf_om_node *), and are responsible for parsing the node's text and all of its
 *         descendents (children).
 *       - Each cf_fmt_<repr>() function is the inverse of cf_opt_<repr>.  The cf_fmt_<repr>
 *         functions for ATOM, KEY_ATOM, KEY_STRING, VALUE_ATOM and VALUE_STRING all take a pointer
 *         to a const 'type', and produce a malloc()ed nul-terminated string which, if passed to
 *         cf_opt_<repr>(), would produce the same original value.  If the value is invalid (outside
 *         the legal range) then cf_fmt_<repr> returns CFINVALID or CFEMPTY.  The cf_fmt_<repr>
 *         functions for NODE and VALUE_NODE take a pointer to a const 'type' and produce a
 *         malloc()ed COM node (struct cf_om_node *) which, if passed to cf_opt_<repr> would produce
 *         the same original value.
 *       - Each cf_cmp_<repr>() function compares two values of the given 'type' and returns -1, 0
 *         or 1 to indicate the natural ordering of the values.  These functions are used to detect
 *         when config elements have their default values, to avoid calling cf_fmt_<repr>().  They
 *         are also used to sort array keys.
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
 * 'default_label'
 *      A label used to qualify an alternative STRUCT default set.  These labels need only be unique
 *      for each given struct 'name', so different STRUCTs may re-use the same labels.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

STRUCT(debug)
ATOM(bool_t, verbose,                   0, boolean,, "")
ATOM(bool_t, ack,                       0, boolean,, "")
ATOM(bool_t, dnaresponses,              0, boolean,, "")
ATOM(bool_t, dnahelper,                 0, boolean,, "")
ATOM(bool_t, queues,                    0, boolean,, "")
ATOM(bool_t, timing,                    0, boolean,, "")
ATOM(bool_t, http_server,               0, boolean,, "")
ATOM(bool_t, httpd,                     0, boolean,, "")
ATOM(bool_t, nohttptx,                  0, boolean,, "")
ATOM(bool_t, io,                        0, boolean,, "")
ATOM(bool_t, verbose_io,                0, boolean,, "")
ATOM(bool_t, interactive_io,            0, boolean,, "")
ATOM(bool_t, packetformats,             0, boolean,, "")
ATOM(bool_t, gateway,                   0, boolean,, "")
ATOM(bool_t, keyring,                   0, boolean,, "")
ATOM(bool_t, security,                  0, boolean,, "")
ATOM(bool_t, mdprequests,               0, boolean,, "")
ATOM(bool_t, msp,                       0, boolean,, "")
ATOM(bool_t, monitor,                   0, boolean,, "")
ATOM(bool_t, radio_link,                0, boolean,, "")
ATOM(bool_t, peers,                     0, boolean,, "")
ATOM(bool_t, overlaybuffer,             0, boolean,, "")
ATOM(bool_t, overlayframes,             0, boolean,, "")
ATOM(bool_t, overlayabbreviations,      0, boolean,, "")
ATOM(bool_t, overlayrouting,            0, boolean,, "")
ATOM(bool_t, overlayroutemonitor,       0, boolean,, "")
ATOM(bool_t, overlayinterfaces,         0, boolean,, "")
ATOM(bool_t, broadcasts,                0, boolean,, "")
ATOM(bool_t, packettx,                  0, boolean,, "")
ATOM(bool_t, packetrx,                  0, boolean,, "")
ATOM(bool_t, packetradio,               0, boolean,, "")
ATOM(bool_t, rejecteddata,              0, boolean,, "")
ATOM(bool_t, slip,                      0, boolean,, "")
ATOM(bool_t, slipdecode,                0, boolean,, "")
ATOM(bool_t, slipbytestream,            0, boolean,, "")
ATOM(bool_t, packetconstruction,        0, boolean,, "")
ATOM(bool_t, rhizome,                   0, boolean,, "")
ATOM(bool_t, rhizome_manifest,          0, boolean,, "")
ATOM(bool_t, rhizome_sql_bind,          0, boolean,, "")
ATOM(bool_t, rhizome_store,             0, boolean,, "")
ATOM(bool_t, rhizome_tx,                0, boolean,, "")
ATOM(bool_t, rhizome_rx,                0, boolean,, "")
ATOM(bool_t, rhizome_ads,               0, boolean,, "")
ATOM(bool_t, rhizome_mdp_rx,            0, boolean,, "")
ATOM(bool_t, subscriber,                0, boolean,, "")
ATOM(bool_t, throttling,                0, boolean,, "")
ATOM(bool_t, meshms,                    0, boolean,, "")
ATOM(bool_t, manifests,                 0, boolean,, "")
ATOM(bool_t, vomp,                      0, boolean,, "")
ATOM(bool_t, trace,                     0, boolean,, "")
ATOM(bool_t, profiling,                 0, boolean,, "")
ATOM(bool_t, linkstate,                 0, boolean,, "")
END_STRUCT

#define LOG_FORMAT_OPTIONS \
ATOM(bool_t,                show_pid,    1, boolean,, "If true, all log lines contain PID of logging process") \
ATOM(bool_t,                show_time,   1, boolean,, "If true, all log lines contain time stamp") \
ATOM(int,                   level,       LOG_LEVEL_DEBUG, log_level,, "Only log messages at and above this level of severity") \
ATOM(bool_t,                dump_config, 1, boolean,, "If true, current configuration is dumped into start of log")

STRUCT(log_format)
LOG_FORMAT_OPTIONS
END_STRUCT

STRUCT(log_format_file)
STRING(256,                 directory_path, "", str,, "Path of directory for log files, either absolute or relative to instance log directory")
STRING(256,                 path,           "", str_nonempty,, "Path of single log file, either absolute or relative to directory_path")
ATOM(unsigned short,        rotate,         12, ushort,, "Number of log files to rotate, zero means no deletion")
ATOM(uint32_t,              duration,       3600, uint32_time_interval,, "Time duration of each log file, zero means one file per invocation")
LOG_FORMAT_OPTIONS
END_STRUCT

STRUCT_ASSIGN(log_format, log_format_file)
LOG_FORMAT_OPTIONS
END_STRUCT_ASSIGN

STRUCT(log)
SUB_STRUCT(log_format_file, file,,)
SUB_STRUCT(log_format,      console,,       console)
SUB_STRUCT(log_format,      android,,       android)
END_STRUCT

STRUCT_DEFAULT(log_format, console)
ATOM_DEFAULT(show_pid,    0)
ATOM_DEFAULT(show_time,   0)
ATOM_DEFAULT(level,       LOG_LEVEL_HINT)
ATOM_DEFAULT(dump_config, 0)
END_STRUCT_DEFAULT

STRUCT_DEFAULT(log_format, android)
ATOM_DEFAULT(show_pid,    0)
END_STRUCT_DEFAULT

STRUCT(server)
STRING(256,                 chdir,      "/", absolute_path,, "Absolute path of chdir(2) for server process")
STRING(256,                 interface_path, "", str_nonempty,, "Path of directory containing interface files, either absolute or relative to instance directory")
ATOM(bool_t,                respawn_on_crash, 0, boolean,, "If true, server will exec(2) itself on fatal signals, eg SEGV")
END_STRUCT

STRUCT(monitor)
ATOM(uint32_t,              uid,        0, uint32_nonzero,, "Allowed UID for monitor socket client")
END_STRUCT

STRUCT(mdp_iftype)
ATOM(int32_t,               tick_ms,         -1, int32_nonneg,, "Tick interval")
ATOM(int32_t,               packet_interval, -1, int32_nonneg,, "Minimum interval between packets in microseconds")
ATOM(int32_t,               reachable_timeout_ms, -1, int32_nonneg,, "Inactivity timeout after which node considered unreachable")
END_STRUCT

ARRAY(mdp_iftypelist, NO_DUPLICATES)
KEY_ATOM(short, interface_type)
VALUE_SUB_STRUCT(mdp_iftype)
END_ARRAY(5)

STRUCT(mdp)
SUB_STRUCT(mdp_iftypelist,  iftype,)
ATOM(bool_t,                enable_inet, 0, boolean,, "If true, allow mdp clients to connect over loopback UDP")
END_STRUCT

STRUCT(olsr)
ATOM(bool_t,                enable,      0, boolean,, "If true, OLSR is used for mesh routing")
ATOM(uint16_t,              remote_port, 4130, uint16_nonzero,, "Remote port number")
ATOM(uint16_t,              local_port,  4131, uint16_nonzero,, "Local port number")
END_STRUCT

ARRAY(argv, NO_DUPLICATES, vld_argv)
KEY_ATOM(unsigned short, ushort_nonzero)
VALUE_STRING(128, str)
END_ARRAY(16)

STRUCT(executable)
STRING(256,                 executable, "", absolute_path, MANDATORY, "Absolute path of dna helper executable")
SUB_STRUCT(argv,            argv,)
END_STRUCT

STRUCT(dna)
SUB_STRUCT(executable,      helper,)
END_STRUCT

STRUCT(rhizome_peer)
STRING(25,                  protocol,   "http", protocol,, "Protocol name")
STRING(256,                 host,       "", str_nonempty, MANDATORY, "Host name or IP address")
ATOM(uint16_t,              port,       HTTPD_PORT, uint16_nonzero,, "Port number")
END_STRUCT

ARRAY(peerlist,)
KEY_STRING(15, str)
VALUE_NODE_STRUCT(rhizome_peer, rhizome_peer)
END_ARRAY(10)

STRUCT(rhizome_direct)
SUB_STRUCT(peerlist,        peer,)
END_STRUCT

STRUCT(user)
STRING(50,                  password,   "", str,, "Authentication password")
END_STRUCT

ARRAY(userlist,)
KEY_STRING(25, str)
VALUE_SUB_STRUCT(user)
END_ARRAY(10)

STRUCT(rhizome_api_addfile)
STRING(64,                  uri_path,               "", absolute_path,, "URI path for HTTP add-file request")
ATOM(struct in_addr,        allow_host,             hton_in_addr(INADDR_LOOPBACK), in_addr,, "IP address of host allowed to make HTTP add-file request")
STRING(256,                 manifest_template_file, "", str_nonempty,, "Path of manifest template file, either absolute or relative to instance directory")
ATOM(sid_t,                 default_author,         SID_ANY, sid,, "Author of add-file bundle if sender not given")
ATOM(rhizome_bk_t,          bundle_secret_key,      RHIZOME_BK_NONE, rhizome_bk,, "Secret key of add-file bundle to try if sender not given")
END_STRUCT

STRUCT(rhizome_api_restful)
SUB_STRUCT(userlist,        users,)
ATOM(uint32_t,              newsince_timeout,       60, uint32_time_interval,, "Time to block while reporting new bundles")
ATOM(uint32_t,              newsince_poll_ms,       2000, uint32_nonzero,, "Database poll interval while blocked reporting new bundles")
END_STRUCT

STRUCT(rhizome_api)
SUB_STRUCT(rhizome_api_addfile, addfile,)
SUB_STRUCT(rhizome_api_restful, restful,)
END_STRUCT

STRUCT(rhizome_http)
ATOM(bool_t,                enable,     1, boolean,, "If true, Rhizome HTTP server is started")
END_STRUCT

STRUCT(rhizome_mdp)
ATOM(bool_t,                enable,     1, boolean,, "If true, Rhizome MDP server is started")
END_STRUCT

STRUCT(rhizome_advertise)
ATOM(bool_t,                enable,     1, boolean,, "If true, Rhizome advertisements are sent")
ATOM(uint32_t,              interval,   500, uint32_nonzero,, "Interval between Rhizome advertisements")
END_STRUCT

STRUCT(rhizome)
ATOM(bool_t,                enable,         1, boolean,, "If true, server opens Rhizome database when starting")
ATOM(bool_t,                fetch,          1, boolean,, "If false, no new bundles will be fetched from peers")
ATOM(bool_t,                clean_on_open,  0, boolean,, "If true, Rhizome database is cleaned at start of every command")
ATOM(bool_t,                clean_on_start, 1, boolean,, "If true, Rhizome database is cleaned at start of daemon")
STRING(256,                 datastore_path, "", str_nonempty,, "Path of rhizome storage directory, absolute or relative to instance directory")
ATOM(uint64_t,              database_size,  1000000, uint64_scaled,, "Size of database in bytes")
ATOM(uint32_t,              max_blob_size,  128 * 1024, uint32_scaled,, "Store payloads larger than this in files not SQLite blobs")

ATOM(uint64_t,              rhizome_mdp_block_size, 512, uint64_scaled,, "Rhizome MDP block size.")
ATOM(uint64_t,              idle_timeout,           RHIZOME_IDLE_TIMEOUT, uint64_scaled,, "Rhizome transfer timeout if no data received.")
ATOM(uint64_t,              mdp_stall_timeout,      1000, uint64_scaled,, "Timeout to request more data via mdp.")
ATOM(uint32_t,              fetch_delay_ms,         50, uint32_nonzero,, "Delay from receiving first bundle advert to initiating fetch")
SUB_STRUCT(rhizome_direct,  direct,)
SUB_STRUCT(rhizome_api,     api,)
SUB_STRUCT(rhizome_http,    http,)
SUB_STRUCT(rhizome_mdp,     mdp,)
SUB_STRUCT(rhizome_advertise, advertise,)
END_STRUCT

STRUCT(directory)
ATOM(sid_t,                 service,     SID_ANY, sid,, "Subscriber ID of Serval Directory Service")
END_STRUCT

STRUCT(host)
STRING(INTERFACE_NAME_STRLEN, interface, "", str_nonempty,, "Interface name")
STRING(256,                   host,      "", str_nonempty,, "Host Name")
ATOM(struct in_addr,          address,   hton_in_addr(INADDR_NONE), in_addr,, "Host IP address")
ATOM(uint16_t,                port,      PORT_DNA, uint16_nonzero,, "Port number")
END_STRUCT

ARRAY(host_list, NO_DUPLICATES)
KEY_ATOM(sid_t, sid)
VALUE_SUB_STRUCT(host)
END_ARRAY(32)

STRUCT(network_interface, vld_network_interface)
ATOM(bool_t,                exclude,         0, boolean,, "If true, do not use matching interfaces")
ATOM(struct pattern_list,   match,           PATTERN_LIST_EMPTY, pattern_list,, "Names that match network interface")
ATOM(short,                 socket_type,     SOCK_UNSPECIFIED, socket_type,, "Type of network socket; stream, dgram or file")
ATOM(short,                 encapsulation,   ENCAP_OVERLAY, encapsulation,, "Type of packet encapsulation")
STRING(256,                 file,            "", str_nonempty,, "Path of interface file, absolute or relative to server.interface_path")
ATOM(struct in_addr,        dummy_address,   hton_in_addr(INADDR_LOOPBACK), in_addr,, "Dummy interface address")
ATOM(struct in_addr,        dummy_netmask,   hton_in_addr(0xFFFFFF00), in_addr,, "Dummy interface netmask")
ATOM(uint16_t,              port,            PORT_DNA, uint16_nonzero,, "Port number for network interface")
ATOM(bool_t,                drop_broadcasts, 0, boolean,, "If true, drop all incoming broadcast packets")
ATOM(bool_t,                drop_unicasts,   0, boolean,, "If true, drop all incoming unicast packets")
ATOM(uint16_t,              drop_packets,    0, uint16_nonzero,, "Percentage of incoming packets that should be dropped for testing purposes")
ATOM(short,                 type,            OVERLAY_INTERFACE_WIFI, interface_type,, "Type of network interface")
SUB_STRUCT(mdp_iftype,      mdp,)
ATOM(bool_t,                send_broadcasts, 1, boolean,, "If false, don't send any broadcast packets")
ATOM(bool_t,                default_route,   0, boolean,, "If true, use this interface as a default route")
ATOM(bool_t,                prefer_unicast,  0, boolean,, "If true, send unicast data as unicast IP packets if available")
ATOM(bool_t,                debug,           0, boolean,, "If true, log details of every outgoing packet")
ATOM(bool_t,                point_to_point,  0, boolean,, "If true, assume there will only be two devices on this interface")
ATOM(bool_t,                ctsrts,          0, boolean,, "If true, enable CTS/RTS hardware handshaking")
ATOM(int32_t,               uartbps,         57600, int32_rs232baudrate,, "Speed of serial UART link speed (which may be different to serial device link speed)")
END_STRUCT

ARRAY(interface_list, NO_DUPLICATES)
KEY_ATOM(unsigned, uint)
VALUE_NODE_STRUCT(network_interface, network_interface)
END_ARRAY(10)

// The top level.
STRUCT(main)
NODE_STRUCT(interface_list, interfaces, interface_list,)
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
