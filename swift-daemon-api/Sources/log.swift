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

private func serval_log(level: CInt, format: String, va_list: CVaListPointer) {
    format.withCString { CString in
        serval_vlogf(level, __whence, CString, va_list)
    }
}

public func serval_log(level: CInt, text: String) {
    text.withCString { CString in
        withVaList([CString]) { va_list in
            serval_log(level: level, format: "%s", va_list: va_list)
        }
    }
}

public func serval_log_fatal(_ text: String) {
    serval_log(level: LOG_LEVEL_FATAL, text: text)
}

public func serval_log_error(_ text: String) {
    serval_log(level: LOG_LEVEL_ERROR, text: text)
}

public func serval_log_warning(_ text: String) {
    serval_log(level: LOG_LEVEL_WARN, text: text)
}

public func serval_log_hint(_ text: String) {
    serval_log(level: LOG_LEVEL_HINT, text: text)
}

public func serval_log_info(_ text: String) {
    serval_log(level: LOG_LEVEL_INFO, text: text)
}

public func serval_log_debug(_ text: String) {
    serval_log(level: LOG_LEVEL_DEBUG, text: text)
}
