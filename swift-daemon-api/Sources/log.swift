/*
Serval DNA support - Swift entry points to Serval logging operations
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

import serval_dna.lib

public enum LogLevel {
    case debug
    case info
    case hint
    case warn
    case error
    case fatal

    var rawValue : CInt {
        get {
            switch (self) {
            case .debug: return LOG_LEVEL_DEBUG
            case .info: return LOG_LEVEL_INFO
            case .hint: return LOG_LEVEL_HINT
            case .warn: return LOG_LEVEL_WARN
            case .error: return LOG_LEVEL_ERROR
            case .fatal: return LOG_LEVEL_FATAL
            }
        }
    }
}

internal var baseFilePath : String = #file

private func trimpath(_ path: String) -> String {
    var i = path.startIndex
    for (b, p) in zip(baseFilePath.indices, path.indices) {
        if path[p] != baseFilePath[b] {
            break;
        }
        if path[p] == "/" {
            i = path.index(after: p)
        }
    }
    return String(path[i..<path.endIndex])
}

private func servalLog(level: LogLevel, format: String, va_list: CVaListPointer, file: String = #file, line: Int = #line, function: String = #function) {
    trimpath(file).withCString { c_file in
        function.withCString { c_function in
            format.withCString { c_format in
                serval_vlogf(level.rawValue, __sourceloc(file: c_file, line: UInt32(exactly: line) ?? 0, function: c_function), c_format, va_list)
            }
        }
    }
}

public func servalLog(level: LogLevel, text: String, file: String = #file, line: Int = #line, function: String = #function) {
    text.withCString { c_text in
        withVaList([c_text]) { va_list in
            servalLog(level: level, format: "%s", va_list: va_list, file: file, line: line, function: function)
        }
    }
}

public func servalLogFatal(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .fatal, text: text, file: file, line: line, function: function)
}

public func servalLogError(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .error, text: text, file: file, line: line, function: function)
}

public func servalLogWarning(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .warn, text: text, file: file, line: line, function: function)
}

public func servalLogHint(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .hint, text: text, file: file, line: line, function: function)
}

public func servalLogInfo(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .info, text: text, file: file, line: line, function: function)
}

public func servalLogDebug(_ text: String, file: String = #file, line: Int = #line, function: String = #function) {
    servalLog(level: .debug, text: text, file: file, line: line, function: function)
}
