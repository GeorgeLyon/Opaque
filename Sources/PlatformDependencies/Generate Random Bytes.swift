import Foundation

@_cdecl("opq_generate_random_bytes")
func _generateRandomBytes(_ buffer: UnsafeMutablePointer<UInt64>,  _ length: UInt16) {
    var randomNumberGenerator = SystemRandomNumberGenerator()
    precondition(length % 8 == 0)
    for i in 0..<Int(length  / 8) {
        buffer[i] = randomNumberGenerator.next()
    }
}
