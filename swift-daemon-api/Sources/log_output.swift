/*
Serval DNA support - log outputter for iOS (unified logging)
Copyright 2018 Flinders University

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

import Foundation
import servald.log

#if os(iOS)

import os

// A Serval log outputter that uses Apple's unified logging system (introduced
// in iOS 10.0 and macOS 10.12 "Sierra")

private func logPrint(_ level: CInt, _ message: UnsafePointer<CChar>?, _ overrun: Int8) {
    let level_text = String(cString: serval_log_level_prefix_string(level)!)
    let message_text = String(cString: message!)
    let log_type : OSLogType
    switch level {
    case LOG_LEVEL_DEBUG:  log_type = OSLogType.debug
    case LOG_LEVEL_INFO:   log_type = OSLogType.info
    case LOG_LEVEL_HINT:   log_type = OSLogType.info
    case LOG_LEVEL_WARN:   log_type = OSLogType.default
    case LOG_LEVEL_ERROR:  log_type = OSLogType.error
    case LOG_LEVEL_FATAL:  log_type = OSLogType.fault
    default:               return
    }
    os_log("%@ %@", type: log_type, level_text, message_text)
}

#elseif os(macOS)

// A Serval log outputter that uses Apple's (legacy) System Log facility.

private func logPrint(_ level: CInt, _ message: UnsafePointer<CChar>?, _ overrun: Int8) {
    let level_text = String(cString: serval_log_level_prefix_string(level)!)
    let message_text = String(cString: message!)
    NSLog("%s %s", level_text, message_text)
}

#else

// A Serval log outputter that writes to standard error and is not
// configurable.  Warning: If you also link log_output_console.o into the
// executable, you will get duplicate log outputs on standard error.

private func logPrint(_ level: CInt, _ message: UnsafePointer<CChar>?, _ overrun: Int8) {
    let level_text = String(cString: serval_log_level_prefix_string(level)!)
    let message_text = String(cString: message!)
    FileHandle.standardError.write("\(level_text) \(message_text)\n".data(using:.utf8)!)
}

#endif

public func logSetup() {
    serval_log_delegate.print = logPrint
    serval_log_delegate.minimum_level = LOG_LEVEL_DEBUG
    serval_log_delegate.show_prolog = 1
#if os(iOS) || os(macOS)
    // Apple's unified logging system (iOS) and syslog (macOS) both record the
    // timestamp and process ID in all log messages, so we don't need to.
    serval_log_delegate.show_pid = 0
    serval_log_delegate.show_time = 0
#else
    // If logging to standard error, do prefix every message with the timestamp
    // and process ID.
    serval_log_delegate.show_pid = 1
    serval_log_delegate.show_time = 1
#endif
}
