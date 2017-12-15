import servald.log

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
