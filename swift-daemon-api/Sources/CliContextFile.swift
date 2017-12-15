/*
Serval DNA Swift CLI output to stdio stream
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

/* An instance of struct cli_vtable that prints all fields to a stdio stream
 * via a buffer.  This is the Swift equivalent of cli_stdio.c.  It is used by
 * the 'servaldswift' daemon to produce its output.
 */

open class CliContextFile: CliContext {
    private var fileHandle: FileHandle
    private var buffer: Data
    private let bufsize: Int? = nil

    public init(_ file: FileHandle) {
        self.fileHandle = file
        self.buffer = Data()
    }

    public override func delim(_ opt: String?) {
        self.puts(ProcessInfo.processInfo.environment["SERVALD_OUTPUT_DELIMITER"] ?? opt ?? "\n")
    }

    public override func write(_ data: Data) {
        self.buffer.append(data)
        if self.bufsize != nil && self.buffer.count >= self.bufsize! {
            self.flush()
        }
    }

    public override func flush() {
        if !self.buffer.isEmpty {
            self.fileHandle.write(self.buffer)
            self.buffer.removeAll()
        }
    }
}
