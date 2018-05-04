/*
Serval DNA Swift CLI output to in-memory array
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

/* An instance of struct cli_vtable that appends all fields to an array.
 */

open class CliContextArray: CliContext {
    public var array: [Any]

    override public init() {
        self.array = []
    }

    override func write(_ data: Data) {
        self.array.append(data)
    }

    override func puts(_ str: String) {
        self.array.append(str)
    }

    override func putString(_ str: String, _ delim: String? = nil) {
        self.array.append(str)
    }

    override func putLong(_ value: Int64, _ delim: String? = nil) {
        self.array.append(value)
    }

    override func putHexData(_ data: Data, _ delim: String? = nil) {
        self.array.append(data)
    }

    override func putBlob(_ data: Data, _ delim: String? = nil) {
        self.array.append(data)
    }

    override func startTable(column_names: [String]) {
        self.array.append(column_names.count)
        for i in 0 ..< column_names.count {
            self.array.append(column_names[i])
        }
    }

    override func endTable(row_count: Int) {
        self.array.append(row_count)
    }

    override func fieldName(_ name: String, _ delim: String? = nil) {
        self.array.append(name)
    }

}
