import Foundation

// MARK: - Public

/**
 Indicates a type that may need to be persisted. Types conforming to this protocol **must only be persisted using one of the methods on this protocol**.
 */
public protocol PersistableData: Codable {
    
    init<Bytes: Collection>(bytes: Bytes) throws where Bytes.Element == UInt8
    
    func withUnsafeBytes<R>(closure: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    
    init(base64Encoded string: String) throws
    
    func base64EncodedString() -> String
    
}

// MARK: - Internal

/**
 Indicates a type for which every binary string of length `MemoryLayout<Self>.size` is a valid value.
 
 - note: This is **not** enforced by the compiler.
 */
protocol ExhaustiveBinaryRepresentable {

    init()

}

protocol PersistableData_Internal {
    
    associatedtype Raw: ExhaustiveBinaryRepresentable
    
    init(raw: Raw)
    
    var raw: Raw { get }

}

private enum Error: Swift.Error {
    case unexpectedByteCount(observed: Int, expected: Int)
    case invalidString(String)
}

extension PersistableData_Internal {
    
    public init<Bytes: Collection>(bytes: Bytes) throws where Bytes.Element == UInt8 {
        guard bytes.count == MemoryLayout<Self>.size else {
            throw Error.unexpectedByteCount(observed: bytes.count, expected: MemoryLayout<Self>.size)
        }
        var raw: Raw = Raw()
        withUnsafeMutableBytes(of: &raw) { rawBytes in
            rawBytes.copyBytes(from: bytes)
        }
        self.init(raw: raw)
    }
    
    public func withUnsafeBytes<R>(closure: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: raw, closure)
    }
    
    public func data() -> Data {
        return withUnsafeBytes { bytes in
            Data(bytes: bytes.baseAddress!, count: bytes.count)
        }
    }

    public func base64EncodedString() -> String {
        return data().base64EncodedString()
    }
    
    public init(base64Encoded string: String) throws {
        guard let data = Data(base64Encoded: string) else {
            throw Error.invalidString(string)
        }
        self = try Self(bytes: data)
    }
    
    public init(from decoder: Decoder) throws {
        let data = try decoder.singleValueContainer().decode(Data.self)
        self = try Self(bytes: data)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(data())
    }
    
}
