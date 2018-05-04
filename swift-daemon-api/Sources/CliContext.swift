/*
Serval DNA Swift CLI output
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
import serval_dna.lib

internal extension Data {
    var hexUpper: String {
        return map { String(format: "%02hhX", $0) }.joined()
    }
}

open class CliContext {
    public var cContext: cli_context = cli_context(context: nil, vtable: nil)

    public init() {
        cContext.context = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
        cContext.vtable = UnsafeMutablePointer<cli_vtable>(&cliVtable)
    }

    // Subclasses override these as needed:

    func delim(_ opt: String? = nil) {}

    func write(_ data: Data) {}

    func puts(_ str: String) {
        self.write(str.data(using:.utf8)!)
    }

    func flush() {}

    func putString(_ str: String, _ delim: String? = nil) {
        self.puts(str)
        self.delim(delim)
    }

    func putLong(_ value: Int64, _ delim: String? = nil) {
        self.puts("\(value)")
        self.delim(delim)
    }

    func putHexData(_ data: Data, _ delim: String? = nil) {
        self.puts(data.hexUpper)
        self.delim(delim)
    }

    func putBlob(_ data: Data, _ delim: String? = nil) {
        self.write(data)
        self.delim(delim)
    }

    func startTable(column_names: [String]) {
        self.putLong(Int64(column_names.count))
        for i in 0 ..< column_names.count {
            self.putString(column_names[i], i == column_names.count - 1 ? nil : ":")
        }
    }

    func endTable(row_count: Int) {}

    func fieldName(_ name: String, _ delim: String? = nil) {
        self.putString(name)
        self.delim(delim)
    }
}

private func _self(_ context: UnsafeMutablePointer<cli_context>?) -> CliContext {
    return Unmanaged<CliContext>.fromOpaque(context!.pointee.context).takeUnretainedValue()
}

private func cliDelim(_ context: UnsafeMutablePointer<cli_context>?, _ opt: UnsafePointer<CChar>?) -> Void {
    _self(context).delim(opt != nil ? String(cString: opt!) : nil)
}

private func cliWrite(_ context: UnsafeMutablePointer<cli_context>?, _ buf: UnsafePointer<CChar>?, _ len: Int) -> Void {
    if buf != nil {
        _self(context).write(Data(bytes: buf!, count: len))
    }
}

private func cliPuts(_ context: UnsafeMutablePointer<cli_context>?, _ str: UnsafePointer<CChar>?) -> Void {
    if str != nil {
        _self(context).putString(String(cString: str!))
    }
}

// The va_list C type on i386, armv7 and i86_64 is CVaListPointer, whereas on
// arm64 it is Optional<CVaListPointer>.
#if arch(arm64)

private func cliVprintf(_ context: UnsafeMutablePointer<cli_context>?, _ fmt: UnsafePointer<CChar>?, _ ap: CVaListPointer?) -> Void {
    let str = NSString(format: String(cString: fmt!), arguments: ap!)
    _self(context).putString(String(data: str.data(using: String.Encoding.utf16.rawValue)!, encoding:.utf16)!)
}

#else

private func cliVprintf(_ context: UnsafeMutablePointer<cli_context>?, _ fmt: UnsafePointer<CChar>?, _ ap: CVaListPointer) -> Void {
    let str = NSString(format: String(cString: fmt!), arguments: ap)
    _self(context).putString(String(data: str.data(using: String.Encoding.utf16.rawValue)!, encoding:.utf16)!)
}

#endif

private func cliPutLong(_ context: UnsafeMutablePointer<cli_context>?, _ value: Int64, _ delim: UnsafePointer<CChar>?) -> Void {
    _self(context).putLong(value, delim != nil ? String(cString: delim!) : nil)
}

private func cliPutString(_ context: UnsafeMutablePointer<cli_context>?, _ value: UnsafePointer<CChar>?, _ delim: UnsafePointer<CChar>?) -> Void {
    _self(context).putString(value != nil ? String(cString: value!) : "",
                             delim != nil ? String(cString: delim!) : nil)
}

private func cliPutHexvalue(_ context: UnsafeMutablePointer<cli_context>?, _ buf: UnsafePointer<CUnsignedChar>?, _ len: Int, _ delim: UnsafePointer<CChar>?) -> Void {
    _self(context).putHexData(buf != nil ? Data(bytes: buf!, count: len) : Data(),
                              delim != nil ? String(cString: delim!) : nil)
}

private func cliPutBlob(_ context: UnsafeMutablePointer<cli_context>?, _ blob: UnsafePointer<CUnsignedChar>?, _ len: Int, _ delim: UnsafePointer<CChar>?) -> Void {
    _self(context).putBlob(blob != nil ? Data(bytes: UnsafeRawPointer(blob!).bindMemory(to: CChar.self, capacity: len), count: len) : Data(),
                           delim != nil ? String(cString: delim!) : nil)
}

private func cliStartTable(_ context: UnsafeMutablePointer<cli_context>?, _ column_count: Int, _ column_names: UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> Void {
    let names = (0..<column_count).map { String(cString: column_names![$0]!) }
    _self(context).startTable(column_names: names)
}

private func cliEndTable(_ context: UnsafeMutablePointer<cli_context>?, _ row_count: Int) -> Void {
    _self(context).endTable(row_count: row_count)
}

private func cliFieldName(_ context: UnsafeMutablePointer<cli_context>?, _ name: UnsafePointer<CChar>?, _ delim: UnsafePointer<CChar>?) -> Void {
    _self(context).fieldName(name != nil ? String(cString: name!) : "", delim != nil ? String(cString: delim!) : nil)
}

private func cliFlush(_ context: UnsafeMutablePointer<cli_context>?) -> Void {
    _self(context).flush()
}

private var cliVtable = cli_vtable(
        delim: cliDelim,
        write: cliWrite,
        puts: cliPuts,
        vprintf: cliVprintf,
        put_long: cliPutLong,
        put_string: cliPutString,
        put_hexvalue: cliPutHexvalue,
        put_blob: cliPutBlob,
        start_table: cliStartTable,
        end_table: cliEndTable,
        field_name: cliFieldName,
        flush: cliFlush
    )
