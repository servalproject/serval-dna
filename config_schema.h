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

STRUCT(log)
STRING(256,                 file,       "", opt_absolute_path,, "Absolute path of log file")
ATOM(int,                   show_pid,   1, opt_boolean,, "If true, all log lines contain PID of logging process")
ATOM(int,                   show_time,  1, opt_boolean,, "If true, all log lines contain time stamp")
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
NODE(debugflags_t,          debug,      0, opt_debugflags, USES_CHILDREN, "Debug flags")
SUB_STRUCT(rhizome,         rhizome,)
SUB_STRUCT(directory,       directory,)
END_STRUCT
