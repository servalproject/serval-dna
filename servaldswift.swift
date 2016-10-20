import Foundation
import servald.main

public func serval_daemon_main(args: [String]) -> CInt {
    // print "args = \(args)"
    var argv = args.map { strdup($0) }
    argv.append(nil)
    defer {
        argv.forEach { free($0) }
    }
    return servald_main(CInt(argv.count - 1), &argv)
}

exit(serval_daemon_main(args: CommandLine.arguments))
