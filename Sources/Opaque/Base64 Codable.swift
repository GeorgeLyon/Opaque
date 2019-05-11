import Foundation

// MARK: - Codable

public protocol Base64Encodable {
    
    func base64EncodedString() -> String
    
}

public protocol Base64Decodable {

    init?(base64Encoded string: String)
    
}

public protocol Base64Codable: Base64Encodable & Base64Decodable { }

// MARK: - Raw Codable

protocol Base64RawCodable: Base64RawEncodable & Base64RawDecodable { }

protocol Base64RawDecodable: Decodable, Base64Decodable {
    
    associatedtype Raw: CStruct
    
    init(raw: Raw)
    
}

protocol Base64RawEncodable: Encodable, Base64Encodable {
    
    associatedtype Raw: CStruct
    
    var raw: Raw { get }
    
}

extension Base64RawDecodable {
    
    public init(from decoder: Decoder) throws {
        let data = try decoder.singleValueContainer().decode(Data.self)
        self = Self(rawData: data)
    }
    
    public init?(base64Encoded string: String) {
        guard let data = Data(base64Encoded: string),
              data.count == MemoryLayout<Raw>.size else {
            return nil
        }
        self = Self(rawData: data)
    }
    
    public init(rawData: Data) {
        var raw = Raw()
        withUnsafeMutableBytes(of: &raw) { rawBytes in
            rawData.withUnsafeBytes { decodedBytes in
                precondition(rawBytes.count == decodedBytes.count)
                rawBytes.copyMemory(from: decodedBytes)
            }
        }
        self = Self(raw: raw)
    }
    
}

extension Base64RawEncodable {
    
    private func data() -> Data {
        return withUnsafeBytes(of: raw) { bytes in
            Data(bytes: bytes.baseAddress!, count: bytes.count)
        }
    }
    
    public func base64EncodedString() -> String {
        return data().base64EncodedString()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(data())
    }
    
}

protocol CStruct {
    
    init()
    
}
