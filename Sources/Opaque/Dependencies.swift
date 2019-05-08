import Foundation

// LibECC

@_cdecl("get_random")
func __libecc_getRandom(_ buffer: UnsafeMutablePointer<UInt64>,  _ length: UInt16) {
    var randomNumberGenerator = SystemRandomNumberGenerator()
    precondition(length % 8 == 0)
    for i in 0..<Int(length  / 8) {
        buffer[i] = randomNumberGenerator.next()
    }
}

// TweetNaCl

@_cdecl("randombytes")
func __tweetnacl_randombytes(_ buffer: UnsafeMutablePointer<UInt64>, _ length: UInt64) {
    var randomNumberGenerator = SystemRandomNumberGenerator()
    precondition(length % 8 == 0)
    for i in 0..<Int(length  / 8) {
        buffer[i] = randomNumberGenerator.next()
    }
}
