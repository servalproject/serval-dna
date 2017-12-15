/*
Serval DNA Swift command-line entry point
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
import servald.cli

/* A Swift entry point to the Serval DNA daemon command-line entry point, which takes a
 * [String] parameter, converts it into an argv array of C strings, and invokes
 * the C main entry point with argv0, and argc/argv arguments.
 */
public func serval_commandline_main(context: CliContext, args: [String]) -> CInt {
    var margv = args.map { strdup($0) }
    margv.append(nil)
    defer {
        margv.forEach { free($0) }
    }
    let argv0 = margv[0]
    margv.remove(at: 0)
    let argv = margv.map { $0 != nil ? UnsafePointer<CChar>?($0!) : nil }
    return argv.withUnsafeBufferPointer {
        return commandline_main(&context.cContext, argv0, CInt(argv.count - 1), $0.baseAddress!)
    }
}
