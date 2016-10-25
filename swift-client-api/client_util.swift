/*
Serval DNA Client Swift test program
Copyright (C) 2016-2017 Flinders University

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

import ServalClient
import Dispatch
#if os(Linux)
import Glibc
#endif

var arg0 : String = ""

func usage() {
    // Once no longer supporting Swift 3, change this to a multi-line string literal.
    print("Usage: \(arg0) [options] keyring --pin PIN list")
    print("       \(arg0) [options] keyring --pin PIN add [ did DID ] [ name NAME ]")
    print("       \(arg0) [options] keyring --pin PIN remove SID")
    print("       \(arg0) [options] keyring --pin PIN set SID [ did DID ] [ name NAME ]")
    print("Options:")
    print("    --pin PIN")
    print("    --user USER")
    print("    --password PASSWORD")
}

func main() {
    var args = CommandLine.arguments
    arg0 = args.remove(at: 0)
    var port : Int16?
    var username : String?
    var password : String?
    parseOptions(&args, [
        ("--port", { port = Int16($0) }),
        ("--user", { username = $0 }),
        ("--password", { password = $0 })
    ])
    let restful_config = ServalRestfulClient.Configuration.default.with(port: port, username: username, password: password)
    let cmd = args.isEmpty ? "" : args.remove(at: 0)
    switch (cmd) {
    case "keyring":
        exit(keyring(&args, configuration: restful_config))
    default:
        usage()
        exit(1)
    }
}

func parseOptions(_ args: inout [String], _ options: [(String, (String) -> Void)]) -> Void {
    argLoop: while (!args.isEmpty) {
        let arg = args[0]
        var opt : String
        var param : String?
        var optrange : Range<Int>
        if let eq = arg.range(of: "=") {
            opt = arg.substring(to: eq.lowerBound)
            param = arg.substring(from: eq.upperBound)
            optrange = 0 ..< 1
        }
        else {
            opt = arg
            param = args.count > 1 ? args[1] : nil
            optrange = 0 ..< 2
        }
        for (label, closure) in options {
            if opt == label && param != nil {
                closure(param!)
                args.removeSubrange(optrange)
                continue argLoop
            }
        }
        break argLoop
    }
}

func printIdentity(identity: ServalKeyring.Identity) {
    print("sid:" + identity.sid.hexUpper)
    print("identity:" + identity.identity.hexUpper)
    if identity.did != nil {
        print("did:" + identity.did!)
    }
    if identity.name != nil {
        print("name:" + identity.name!)
    }
}

func keyring(_ args: inout [String], configuration: ServalRestfulClient.Configuration) -> Int32 {
    let cmd = args.isEmpty ? "" : args.remove(at: 0)
    var pin : String? = nil
    parseOptions(&args, [("--pin", { pin = $0 })])
    var status : Int32 = 0
    switch (cmd) {
    case "list":
        precondition(args.isEmpty)
        print("4")
        print("sid:identity:did:name")
        let semaphore = DispatchSemaphore(value: 0)
        let client = ServalRestfulClient(configuration: configuration)
        let request = ServalKeyring.listIdentities(client: client, pin: pin) { (identities, error) in
            if let error = error {
                print(error, to: &errorStream)
                status = 2
            }
            else if let identities = identities {
                for identity in identities {
                    print("\(identity.sid.hexUpper):\(identity.identity.hexUpper):\(identity.did ?? ""):\(identity.name ?? "")")
                }
            }
            semaphore.signal()
        }
        print("Waiting...", to: &debugStream)
        semaphore.wait()
        print("Done", to: &debugStream)
        request.close()

    case "add":
        var did : String? = nil
        var name : String? = nil
        parseOptions(&args, [("did", { did = $0 }), ("name", { name = $0 })])
        precondition(args.isEmpty)
        var message = "Adding (did="
        debugPrint(did as Any, terminator:"", to:&message)
        message += " name="
        debugPrint(name as Any, terminator:"", to:&message)
        message += " pin="
        debugPrint(pin as Any, terminator:"", to:&message)
        message += ")..."
        print(message, to: &debugStream)
        let semaphore = DispatchSemaphore(value: 0)
        let client = ServalRestfulClient(configuration: configuration)
        let request = ServalKeyring.addIdentity(client: client, did: did, name: name, pin: pin) { (identity, error) in
            if let error = error {
                print(error, to: &errorStream)
                status = 2
            }
            else if let identity = identity {
                printIdentity(identity: identity)
            }
            semaphore.signal()
        }
        print("Waiting...", to: &debugStream)
        semaphore.wait()
        print("Done", to: &debugStream)
        request.close()

    case "remove":
        let sid = SubscriberId(fromHex: args.remove(at: 0))!
        precondition(args.isEmpty)
        print("Removing (sid=\(sid.hexUpper))...")
        let semaphore = DispatchSemaphore(value: 0)
        let client = ServalRestfulClient(configuration: configuration)
        let request = ServalKeyring.removeIdentity(client: client, sid: sid, pin: pin) { (identity, error) in
            if let error = error {
                print(error, to: &errorStream)
                status = 2
            }
            else if let identity = identity {
                printIdentity(identity: identity)
            }
            semaphore.signal()
        }
        print("Waiting...", to: &debugStream)
        semaphore.wait()
        print("Done", to: &debugStream)
        request.close()

    case "set":
        let sid = SubscriberId(fromHex: args.remove(at: 0))!
        var did : String? = nil
        var name : String? = nil
        parseOptions(&args, [("did", { did = $0 }), ("name", { name = $0 })])
        precondition(args.isEmpty)
        var message = "Setting (sid=\(sid.hexUpper))..."
        message += " did="
        debugPrint(did as Any, terminator:"", to:&message)
        message += " name="
        debugPrint(name as Any, terminator:"", to:&message)
        message += " pin="
        debugPrint(pin as Any, terminator:"", to:&message)
        print(message, to: &debugStream)
        let semaphore = DispatchSemaphore(value: 0)
        let client = ServalRestfulClient(configuration: configuration)
        let request = ServalKeyring.setIdentity(client: client, sid: sid, did: did, name: name, pin: pin) { (identity, error) in
            if let error = error {
                print(error, to: &errorStream)
                status = 2
            }
            else if let identity = identity {
                printIdentity(identity: identity)
            }
            semaphore.signal()
        }
        print("Waiting...", to: &debugStream)
        semaphore.wait()
        print("Done", to: &debugStream)
        request.close()

    default:
        usage()
        status = 1
    }
    return status
}

main()
