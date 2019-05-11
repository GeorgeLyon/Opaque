import XCTest
@testable import Opaque

final class OpaqueTests: XCTestCase {
    func testExample() throws {
        // The server maintains a per-user salt
        let salt = try Opaque.Salt.random()
        var nextVerificationNonce: Opaque.VerificationNonce = .zero
        
        let password = "weak password"
        
        // Registration
        let encryptedPrivateKey: Opaque.EncryptedPrivateKey
        let publicKey: Opaque.PublicKey
        do {
            // 1. Client generates encryptedPassword and passwordKey
            let (encryptedPassword, passwordKey) = try Opaque.encrypt(password)
            
            // Client sends encryptedPassword to the server
        
            // Server salts the encrypted password
            let encryptedSaltedPassword = try encryptedPassword.salted(with: salt)
            
            // Server responds with encryptedSaltedPassword
            
            // Client generates encryptedPrivateKey and publicKey using the passwordKey from (1)
            (encryptedPrivateKey, publicKey) = try Opaque.generateKeys(encryptedSaltedPassword, passwordKey)
            
            // Client sends encryptedPrivateKey and publicKey to the server
            
            // Server stores both keys
        }
        
        // Successful Authentication
        do {
            // 1. Client generates encryptedPassword and passwordKey
            let (encryptedPassword, passwordKey) = try Opaque.encrypt(password)
            
            // Client sends encryptedPassword to the server
            
            // Server salts the encrypted password
            let encryptedSaltedPassword = try encryptedPassword.salted(with: salt)
            
            // Server creates an unused verificationNonce
            let verificationNonce = nextVerificationNonce
            try nextVerificationNonce.increment()
            
            // Server responds with encryptedSaltedPassword, encryptedPrivateKey and verificationNonce
            
            // Client generates a verification for the verificationNonce, using the passwordKey from (1)
            let verification = try Opaque.Verification(encryptedPrivateKey, verificationNonce, encryptedSaltedPassword, passwordKey)
            
            // Client sends the verification to the server
            
            // Server validates the client's verification using the stored public key
            try verification.validate(publicKey, verificationNonce)
        }
        
        // Failed authentication (wrong password)
        do {
            // 1. Client generates encryptedPassword and passwordKey
            let (encryptedPassword, passwordKey) = try Opaque.encrypt("wrong password")
            
            // Client sends encryptedPassword to the server
            
            // Server salts the encrypted password
            let encryptedSaltedPassword = try encryptedPassword.salted(with: salt)
            
            // Server creates an unused verificationNonce
            let verificationNonce = nextVerificationNonce
            try nextVerificationNonce.increment()
            
            // Server responds with encryptedSaltedPassword, encryptedPrivateKey and verificationNonce
            
            // The client should fail to generate a verification
            XCTAssertThrowsError(try Opaque.Verification(encryptedPrivateKey, verificationNonce, encryptedSaltedPassword, passwordKey))
        }
        
        // Failed authentication (garbled verification)
        do {
            // 1. Client generates encryptedPassword and passwordKey
            let (encryptedPassword, passwordKey) = try Opaque.encrypt(password)
            
            // Client sends encryptedPassword to the server
            
            // Server salts the encrypted password
            let encryptedSaltedPassword = try encryptedPassword.salted(with: salt)
            
            // Server creates an unused verificationNonce
            let verificationNonce = nextVerificationNonce
            try nextVerificationNonce.increment()
            
            // Server responds with encryptedSaltedPassword, encryptedPrivateKey and verificationNonce
            
            // Client generates a verification for the verificationNonce, using the passwordKey from (1)
            var verification = try Opaque.Verification(encryptedPrivateKey, verificationNonce, encryptedSaltedPassword, passwordKey)
            
            // Garble the verification
            withUnsafeMutableBytes(of: &verification) { verificationBytes in
                for i in 0..<verificationBytes.count {
                    verificationBytes[i] ^= 0b0101_0101
                }
            }
            
            // Client sends the verification to the server
            
            // The server should not accept the garbled verification
            XCTAssertThrowsError(try verification.validate(publicKey, verificationNonce))
        }
        
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
