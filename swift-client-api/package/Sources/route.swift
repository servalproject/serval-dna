/*
Serval DNA Swift API
Copyright (C) 2018 Flinders University

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

private protocol OptionalProtocol {
    func wrappedType() -> Any.Type
}

extension Optional: OptionalProtocol {
    func wrappedType() -> Any.Type {
        return Wrapped.self
    }
}

public class ServalRoute {

    public struct Identity {
        public let sid : SubscriberId
        public let did : String?
        public let name : String?
        public let is_self : Bool
        public let hop_count : Int
        public let reachable_broadcast : Bool
        public let reachable_unicast : Bool
        public let reachable_indirect : Bool
    }

    private static func unpackField<T, U>(_ json: [String: Any?], _ key: String, _ convert: (T) throws -> U) throws -> U {
        guard let opt = json[key] else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "missing \"\(key)\" element")
        }
        if let typed = opt as? T {
            return try convert(typed)
        }
        throw ServalRestfulClient.Exception.invalidJson(reason: "\(key) value is not \(String(describing: T.self)): \(opt ?? "nil")")
    }

    /* I cannot work out any way to combine this function into unpackField() by
     * detecting when T and U are Optional<> types.
     */
    private static func unpackOptionalField<T, U>(_ json: [String: Any?], _ key: String, _ convert: (T) throws -> U?) throws -> U? {
        guard let opt = json[key] else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "missing \"\(key)\" element")
        }
        guard let any = opt else {
            return nil
        }
        if let typed = any as? T {
            return try convert(typed)
        }
        throw ServalRestfulClient.Exception.invalidJson(reason: "\(key) value is not \(String(describing: T.self)): \(any)")
    }

    private static func convertSID(_ sidhex: String) throws -> SubscriberId {
        guard let sid = SubscriberId(fromHex: sidhex) else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "sid value is not hex: \(sidhex)")
        }
        return sid
    }

    private static func nonEmptyStringOrNil(_ s: String) -> String? {
        return s.isEmpty ? nil : s
    }

    private static func isBool(_ b: Bool) -> Bool {
        return b
    }

    private static func nonNegativeInt(i: Int) throws -> Int {
        if i < 0 {
            throw ServalRestfulClient.Exception.invalidJson(reason: "integer value is negative: \(i)")
        }
        return i
    }

    private static func unpackIdentity(fromJsonDict json: [String: Any?]) throws -> Identity
    {
        return Identity(sid: try unpackField(json, "sid", convertSID),
                        did: try unpackOptionalField(json, "did", nonEmptyStringOrNil),
                        name: try unpackOptionalField(json, "name", nonEmptyStringOrNil),
                        is_self: try unpackField(json, "is_self", isBool),
                        hop_count: try unpackField(json, "hop_count", nonNegativeInt),
                        reachable_broadcast: try unpackField(json, "reachable_broadcast", isBool),
                        reachable_unicast: try unpackField(json, "reachable_unicast", isBool),
                        reachable_indirect: try unpackField(json, "reachable_indirect", isBool))
    }

    public static func listIdentities(client: ServalRestfulClient = ServalRestfulClient(),
                                      pin: String? = nil,
                                      completionHandler: @escaping ([Identity]?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if pin != nil { param["pin"] = pin }
        return client.createRequest(verb: "GET",
                                    path: "restful/route/all.json",
                                    query: param) { (statusCode, json, error) in
            if let error = error {
                completionHandler(nil, error)
                return
            }
            guard statusCode! == 200 else {
                completionHandler(nil, ServalRestfulClient.Exception.requestFailed(statusCode: statusCode!))
                return
            }
            var identities : [Identity] = []
            do {
                for row in try ServalRestfulClient.transformJsonTable(json: json) {
                    identities.append(try unpackIdentity(fromJsonDict: row))
                }
            }
            catch let e {
                completionHandler(nil, e)
                return
            }
            completionHandler(identities, nil)
        }!
    }

}
