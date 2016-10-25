/*
Serval DNA Swift API
Copyright (C) 2016 Flinders University

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

/* All the Serval Id types (SID, BundleId, etc.) are binary blobs that are
* typically represented in hexadecimal text format.  Some also have an
* "abbreviated" format.
*/

public protocol AbstractId : Hashable, CustomStringConvertible {
    init(fromBinary: [UInt8])
    init?(fromHex: String)
    var binary : [UInt8] { get }
    var hexUpper : String { get }
}

public protocol AbbreviatedId : AbstractId {
    var abbreviation : String { get }
}

/* Implementations of AbstractId that specialise GenericIdImplementation must
* also implement the ConcreteId protocol, which allows users to discover
* properties of the specialised type without instantiating it.
*/

public protocol ConcreteId {
    static var byteCount : Int { get }
    static var mimeType : String { get }
}

/* All Serval Id types are specialisations of this generic implementation,
* which stores the Id's value as an array of bytes, and derives all other
* properties from that representation.
*/

public class GenericIdImplementation : AbstractId {
    public let binary : [UInt8]

    public static func == (lhs: GenericIdImplementation, rhs: GenericIdImplementation) -> Bool {
        return lhs.binary == rhs.binary
    }

    public var hashValue : Int {
        return self.binary.map { $0.hashValue }.reduce(0) {
            (($0 << 8) | Int(UInt($0) >> UInt((MemoryLayout<Int>.size - 1) * 8))) ^ $1
        }
    }

    internal init(fill: UInt8) {
        self.binary = Array(repeating: fill, count: (type(of:self) as! ConcreteId.Type).byteCount)
    }

    public required init(fromBinary binary: [UInt8]) {
        self.binary = binary
        assert(self.binary.count == (type(of:self) as! ConcreteId.Type).byteCount)
    }

    public required init?(fromHex hex: String) {
        var binary = Array(repeating: UInt8(0), count: (type(of:self) as! ConcreteId.Type).byteCount)
        var index = hex.startIndex
        for i in 0 ..< binary.count {
            guard let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) else {
                return nil
            }
            let digits = hex.substring(with: index ..< next)
            guard let byte = UInt8(digits, radix: 16) else {
                return nil
            }
            binary[i] = byte
            index = next
        }
        guard index == hex.endIndex else {
            return nil
        }
        self.binary = binary
    }

    public var hexUpper : String {
        return self.binary.map { String(format: "%02hhX", $0) }.joined()
    }

    internal func hexUpper(digitCount: Int) -> String {
        let byteCount = (digitCount + 1) / 2
        assert(byteCount <= self.binary.count)
        let hex = self.binary[0 ..< byteCount].map { String(format: "%02hhX", $0) }.joined()
        return digitCount == byteCount * 2 ? hex : hex.substring(with: hex.startIndex ..< hex.index(hex.endIndex, offsetBy: -1))
    }

    public var description : String {
        return "\(type(of:self))(fromHex: \"\(self.hexUpper)\")"
    }
}
