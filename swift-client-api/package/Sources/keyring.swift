/*
Serval DNA Swift API
Copyright (C) 2016-2018 Flinders University

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

public class ServalKeyring {

    public struct Identity {
        public let sid : SubscriberId
        public let identity : SubscriberId
        public let did : String?
        public let name : String?
    }

    private static func unpackIdentity(fromJsonDict json: [String: Any?]) throws -> Identity
    {
        guard let sidany = json["sid"] else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "missing \"sid\" element")
        }
        guard let sidhex = sidany as? String else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "sid value is not String")
        }
        guard let sid = SubscriberId(fromHex: sidhex) else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "sid value is not hex: \(sidhex)")
        }
        guard let idany = json["identity"] else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "missing \"identity\" element")
        }
        guard let idhex = idany as? String else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "identity value is not String")
        }
        guard let identity = SubscriberId(fromHex: idhex) else {
            throw ServalRestfulClient.Exception.invalidJson(reason: "identity value is not hex: \(idhex)")
        }
        var did: String?
        if let value = json["did"], value != nil {
            guard let text = value! as? String else {
                throw ServalRestfulClient.Exception.invalidJson(reason: "did value is not String")
            }
            if !text.isEmpty {
                did = text
            }
        }
        var name: String?
        if let value = json["name"], value != nil {
            guard let text = value! as? String else {
                throw ServalRestfulClient.Exception.invalidJson(reason: "name value is not String")
            }
            if !text.isEmpty {
                name = text
            }
        }
        return Identity(sid: sid, identity: identity, did: did, name: name)
    }

    public static func listIdentities(client: ServalRestfulClient = ServalRestfulClient(),
                                      pin: String? = nil,
                                      completionHandler: @escaping ([Identity]?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if pin != nil { param["pin"] = pin }
        return client.createRequest(verb: "GET",
                                    path: "restful/keyring/identities.json",
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

    private static func singleIdentityRequest(client: ServalRestfulClient = ServalRestfulClient(),
                                              verb: String,
                                              path: String,
                                              query: [String: String] = [:],
                                              successStatusCodes: Set<Int> = [200],
                                              completionHandler: @escaping (Identity?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        return client.createRequest(verb:verb, path: path, query: query) { (statusCode, json, error) in
            if let error = error {
                completionHandler(nil, error)
                return
            }
            do {
                guard successStatusCodes.contains(statusCode!) else {
                    throw ServalRestfulClient.Exception.requestFailed(statusCode: statusCode!)
                }
                guard let json_top = json as? [String: Any] else {
                    throw ServalRestfulClient.Exception.invalidJson(reason: "root is not JSON object")
                }
                guard let json_identity = json_top["identity"] as? [String: Any] else {
                    completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "'identity' is not JSON object"))
                    return
                }
                completionHandler(try unpackIdentity(fromJsonDict: json_identity), nil)
            }
            catch let e {
                completionHandler(nil, e)
            }
        }!
    }

    public static func addIdentity(client: ServalRestfulClient = ServalRestfulClient(),
                                   did: String? = nil,
                                   name: String? = nil,
                                   pin: String? = nil,
                                   completionHandler: @escaping (Identity?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if did != nil { param["did"] = did }
        if name != nil { param["name"] = name }
        if pin != nil { param["pin"] = pin }
        return self.singleIdentityRequest(client: client,
                                          verb: "POST",
                                          path: "restful/keyring/add",
                                          query: param,
                                          successStatusCodes: [201],
                                          completionHandler: completionHandler)
    }

    public static func getIdentity(client: ServalRestfulClient = ServalRestfulClient(),
                                   sid: SubscriberId,
                                   pin: String? = nil,
                                   completionHandler: @escaping (Identity?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if pin != nil { param["pin"] = pin }
        return self.singleIdentityRequest(client: client,
                                          verb: "GET",
                                          path: "restful/keyring/\(sid.hexUpper)",
                                          query: param,
                                          completionHandler: completionHandler)
    }

    public static func removeIdentity(client: ServalRestfulClient = ServalRestfulClient(),
                                      sid: SubscriberId,
                                      pin: String? = nil,
                                      completionHandler: @escaping (Identity?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if pin != nil { param["pin"] = pin }
        return self.singleIdentityRequest(client: client,
                                          verb: "DELETE",
                                          path: "restful/keyring/\(sid.hexUpper)",
                                          query: param,
                                          completionHandler: completionHandler)
    }

    public static func setIdentity(client: ServalRestfulClient = ServalRestfulClient(),
                                   sid: SubscriberId,
                                   did: String? = nil,
                                   name: String? = nil,
                                   pin: String? = nil,
                                   completionHandler: @escaping (Identity?, Error?) -> Void)
        -> ServalRestfulClient.Request
    {
        var param = [String: String]()
        if did != nil { param["did"] = did }
        if name != nil { param["name"] = name }
        if pin != nil { param["pin"] = pin }
        return self.singleIdentityRequest(client: client,
                                          verb: "PATCH",
                                          path: "restful/keyring/\(sid.hexUpper)",
                                          query: param,
                                          completionHandler: completionHandler)
    }

}
