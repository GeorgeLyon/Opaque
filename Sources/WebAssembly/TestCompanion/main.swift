import Opaque
import Foundation

let jsonDecoder = JSONDecoder()

let jsonEncoder = JSONEncoder()

struct RegistrationPayload: Codable {
    let encryptedPrivateKey: Opaque.EncryptedPrivateKey
    let publicKey: Opaque.PublicKey
}

let salt: Opaque.Salt = try .random()
var verificationNonce = Opaque.VerificationNonce()

let registrationPayload: RegistrationPayload
do {
    print("Paste encrypted password (1):")
    let encryptedPassword = Opaque.EncryptedPassword(
        base64Encoded: readLine()!)!

    let encryptedSaltedPassword = try encryptedPassword.salted(with: salt).base64EncodedString()
    print("Encrypted salted password:\n\(encryptedSaltedPassword)")
    
    print("Paste registration payload:")
    do {
        let data = readLine()!.data(using: .utf8)!
        registrationPayload = try jsonDecoder.decode(RegistrationPayload.self, from: data)
    }
}

// Authenticate
do {
    print("Paste encrypted password (2):")
    let encryptedPassword = Opaque.EncryptedPassword(base64Encoded: readLine()!)!
    
    struct VerificationRequest: Codable {
        let encryptedPrivateKey: Opaque.EncryptedPrivateKey
        let verificationNonce: Opaque.VerificationNonce
        let encryptedSaltedPassword: Opaque.EncryptedSaltedPassword
    }
    
    let currentVerificationNonce = verificationNonce
    try verificationNonce.increment()
    // At this point, we should save the incremented verification nonce to ensure it is never reused.
    
    let verificationRequest = VerificationRequest(
        encryptedPrivateKey: registrationPayload.encryptedPrivateKey,
        verificationNonce: currentVerificationNonce,
        encryptedSaltedPassword: try encryptedPassword.salted(with: salt)
    )
    let encodedVerificationRequest = String(data: try jsonEncoder.encode(verificationRequest), encoding: .utf8)!
    print("Verification request:\n\(encodedVerificationRequest)")
    
    print("Paste verification:")
    let verification = Opaque.Verification(base64Encoded: readLine()!)!
    try verification.validate(registrationPayload.publicKey, currentVerificationNonce)
    
    print("Verification is valid!")
}
