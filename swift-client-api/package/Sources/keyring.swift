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
            guard let json_top = json as? [String: Any] else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "root is not JSON object"))
                return
            }
            var column_count = 0
            var sid_index = -1
            var identity_index = -1
            var did_index = -1
            var name_index = -1
            guard let header = json_top["header"] as? [String] else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "missing 'header' element"))
                return
            }
            for text in header {
                if text == "sid" {
                    sid_index = column_count
                }
                else if text == "identity" {
                    identity_index = column_count
                }
                else if text == "did" {
                    did_index = column_count
                }
                else if text == "name" {
                    name_index = column_count
                }
                column_count += 1
            }
            guard sid_index != -1 else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "missing 'sid' column"))
                return
            }
            guard identity_index != -1 else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "missing 'identity' column"))
                return
            }
            guard let rows = json_top["rows"] as? [[Any]] else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "missing 'rows' element"))
                return
            }
            var identities : [Identity] = []
            for row in rows {
                guard row.count == column_count else {
                    completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "row has \(row.count) elements; should be \(column_count)"))
                    return
                }
                var opt_sid : SubscriberId?
                var opt_identity : SubscriberId?
                var did : String?
                var name : String?
                if sid_index != -1 {
                    guard let hex = row[sid_index] as? String else {
                        completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "sid value is not String"))
                        return
                    }
                    opt_sid = SubscriberId(fromHex: hex)
                    guard opt_sid != nil else {
                        completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "sid value is not hex: \(hex)"))
                        return
                    }
                }
                if identity_index != -1 {
                    guard let hex = row[identity_index] as? String else {
                        completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "identity value is not String"))
                        return
                    }
                    opt_identity = SubscriberId(fromHex: hex)
                    guard opt_sid != nil else {
                        completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "identity value is not hex: \(hex)"))
                        return
                    }
                }
                if did_index != -1 {
                    let value = row[did_index]
                    if value as? NSNull == nil {
                        guard let text = value as? String else {
                            completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "did value is not String: \(value)"))
                            return
                        }
                        if !text.isEmpty {
                            did = text
                        }
                    }
                }
                if name_index != -1 {
                    let value = row[name_index]
                    if value as? NSNull == nil {
                        guard let text = value as? String else {
                            completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "name value is not String: \(value)"))
                            return
                        }
                        if !text.isEmpty {
                            name = text
                        }
                    }
                }
                identities.append(Identity(sid: opt_sid!, identity: opt_identity!, did: did, name: name))
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
            guard successStatusCodes.contains(statusCode!) else {
                completionHandler(nil, ServalRestfulClient.Exception.requestFailed(statusCode: statusCode!))
                return
            }
            guard let json_top = json as? [String: Any] else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "root is not JSON object"))
                return
            }
            guard let json_identity = json_top["identity"] as? [String: Any] else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "'identity' is not JSON object"))
                return
            }
            guard let sid_hex = json_identity["sid"] as? String else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "'sid' is not String"))
                return
            }
            guard let identity_hex = json_identity["identity"] as? String else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "'identity' is not String"))
                return
            }
            guard let sid = SubscriberId(fromHex: sid_hex) else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "invalid 'sid': \(sid_hex)"))
                return
            }
            guard let identity = SubscriberId(fromHex: identity_hex) else {
                completionHandler(nil, ServalRestfulClient.Exception.invalidJson(reason: "invalid 'identity': \(identity_hex)"))
                return
            }
            let did = json_identity["did"] as? String ?? ""
            let name = json_identity["name"] as? String ?? ""
            completionHandler(Identity(sid: sid, identity: identity, did: did, name: name), nil)
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
