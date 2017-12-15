/*
Serval DNA daemon in Swift
Copyright 2017 Flinders University

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
import ServalDNA
import servald.log

// Logging
//
// A simplistic console log outputter that writes to standard error and is not
// configurable.  Note that log_output_console.o is not linked into
// servaldswift, in order to avoid duplicate log outputs on standard error.

private func logPrint(_ level: CInt, _ message: UnsafePointer<CChar>?, _ overrun: Int8) {
    let level_text = String(cString: serval_log_level_prefix_string(level)!)
    let message_text = String(cString: message!)
    FileHandle.standardError.write("\(level_text) \(message_text)\n".data(using:.utf8)!)
}

serval_log_delegate.print = logPrint
serval_log_delegate.minimum_level = LOG_LEVEL_WARN
serval_log_delegate.show_prolog = 1
serval_log_delegate.show_pid = 1
serval_log_delegate.show_time = 1

// Output

var contextFile = CliContextFile(FileHandle.standardOutput)

// Invocation

let status = serval_commandline_main(context: contextFile, args: CommandLine.arguments)

// Cleanup

contextFile.flush()

exit(status)
