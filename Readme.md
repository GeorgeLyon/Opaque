# Opaque 

An implementation of the [OPAQUE protocol](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00)

## Reference

* [The Draft Proposal](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00)
* [The Academic Paper](https://eprint.iacr.org/2018/163.pdf)

## Discussion

Opaque is a new method of [augmented password-authenticated key exchange](https://en.wikipedia.org/wiki/Password-authenticated_key_agreement) (aPAKE). aPAKE allows a server and client to agree on a key without the server ever receiving the plaintext password. Opaque improves on previous methods by never revealing the server's [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) to the client, and thus is more resistent to certain classes of precomputation attack. The server never receiving a plaintext password is a very valuable property, as numerous services have accidentally logged millions of user passwords (including a recent, high-profile [Facebook blunder](https://krebsonsecurity.com/2019/03/facebook-stored-hundreds-of-millions-of-user-passwords-in-plain-text-for-years/)).
A more subtle feature of Opaque is that the protocol allows for a client-run [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) (KDF), which is traditionally run by the server. KDF makes authenticating a password more computationally expensive, and thus any attack involving guessing the password becomes much more computationally expensive. It is uncommon for servers to opt for the most secure KDFs, as that is often too costly from a resource standpoint. If that cost is distributed across clients, however, it becomes feasible to use the most secure KDFs, like [Argon2](https://en.wikipedia.org/wiki/Argon2), to secure client passwords. This is covered in [section 3.4](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00#section-3.4) of the draft.

## Selection of cryptographic primitives

While Opaque defines the methodology of authentication, it does not specify the specific cryptographic primitives to use. This implementation aims to provide a reasonable set of primitives to use, and configuration is not currently a non-goal.

### Multiplicative Blinding versus Exponential Blinding

In the academic paper, the password is protected using _exponential blinding_, while the internet draft suggests _multiplicative blinding_. For this implementation, we use exponential blinding because it results in a simpler API, which doesn't require the `v=g^k` term in the draft proposal. This may end up being slightly more computationally expensive, but this cost pales in comparison with even the simplest key derivation function.

### Cyclic Group of Prime Order: `secp256r1`

[Elliptic curves](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) are very highly regarded cryptographic primitives. `secp256r1` is a cousin to `secp256k1` but with ostensibly random parameters (hence `r` instead of `k`). It is impossible to prove that the parameters were, in fact, [randomly and not nefariously chosen](https://crypto.stackexchange.com/questions/18965/is-secp256r1-more-secure-than-secp256k1) but there seems to be enough evidence that `secp256r1` is robust, at least for our purposes. The Koblitz curve, `secp256k1`, was also a contender but the parameters were chosen in the interest of efficiency, which doesn't really matter for our use case since we also want to use a fairly robust KDF. Also, the surfeit of financial interest in Bitcoin, which utilizes `secp256k1` has given rise to specialized hardware for executing cryptographic operations on this curve. As a result, a user (who doesn't have specialized hardware) is at a disadvantage against an attacker (who may have specialized hardware).

**UPDATE:** Cloudflare's [League of Entropy](https://www.cloudflare.com/leagueofentropy/) now provides an interesting source of randomness, and may be a good candidate for generating verifiably random elliptic curves.

### Hash Function: `SHA-3`

[SHA-2](https://en.wikipedia.org/wiki/SHA-2) is showing signs of age, and it was developed by the US Government and not by the community at large. While [SHA-3](https://en.wikipedia.org/wiki/SHA-3) shares its name and is also endorsed by NIST, it was the product of a lengthy, open standardization process and thus engenders more confidence that it does not have a [back door](https://en.wikipedia.org/wiki/Backdoor_(computing)). SHA-3 is very simple, and can be implemented in a [couple hundred lines of C](https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c), and the underlying permutation ([Keccak](https://keccak.team)) is quite powerful and has [other cool applications](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/august/introducing-disco/).

### Key derivation function: `Argon2id`

[Scrypt](https://en.wikipedia.org/wiki/Scrypt) and [Argon2](https://en.wikipedia.org/wiki/Argon2) are the most popular high-security KDFs. Argon2 is based on [BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) which is based on [Daniel J. Bernstien](https://en.wikipedia.org/wiki/Daniel_J._Bernstein)'s [ChaCha](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) cipher. BLAKE2 participated in the SHA-3 competition, and though it lost to Keccak, it is still regarded as secure and Daniel J. Bernstein is very well regarded in the cryptography community.
Argon2 comes in a two variants, `Argon2i` and `Argon2d`. `Argon2id` is the hybrid mode which provides good protection against most adversaries. 

### Signatures and Encryption: `Curve25519`

As was mentioned in the previous secition, [Daniel J. Bernstien](https://en.wikipedia.org/wiki/Daniel_J._Bernstein) is well regarded in the cryptography community and his primitive of choice is `Curve25519`. There are many services using `Curve25519` and many implementations of the underlying cryptography. The default library, `NaCl`, also provides a simple, idiot-resistant API, mitigating several potential implementation issues.

## Dependencies 

All dependencies are vendored for convenience, though care is taken not to edit the dependency source unless absolutely necessary. The goal is to have this library build across many platforms without requiring that libraries be installed and available on those platforms.

### LibECC

We use [`libecc`](https://github.com/ANSSI-FR/libecc) for operations on `secp256r1`.  `libecc` also provides SHA3, which is convenient and saves us an extra dependency. Most importantly, `libecc` aims to be simple and uses a minimal amount of code to provide the functionality Opaque requires. Also, `libecc` seems to be under development by the French government, which gives me hope that it is (or will become) fairly robust.

### PHC-winner-argon2

[Argon2](https://github.com/P-H-C/phc-winner-argon2) won the [Password Hashing Competition](https://password-hashing.net). We currently use their reference implementation as it is compact and simple. The other alternative, `libsodium` is well regarded but seemed harder to vendor as a dpendency as it is often recommended to have the static library installed on your system to use.

### TweetNaCl

Again, though standard `NaCl` is almost certainly more performant, [tweetNaCl](https://tweetnacl.cr.yp.to) and its emphasis on compactness and simplicity was more aligned with our goals. Additionally, the performance of encryption and sigining are likely to be dwarfed by the computational cost of running a KDF, so we are not as worried about performance here.

## Development

### Swift

Currently, my use case for this library is for use with a Swift application and thus I'm using Swift Package Manager to build the C code. I also like that SwiftPM is more declarative than `make` and doesn't require specifying what shell commands to run.

To run the code, simply have Swift installed and run `swift test`. 

### WebAssembly

#### Compiling to WebAssembly

**NOTE:** WebAssembly requires a version of `clang` that supports  `--target=wasm32`. Notably, the clang that ships with Xcode does not support this. 

```
clang \
--target=wasm32 \
-Os \
-flto \
-nostdlib \
-Wl,--no-entry \
-Wl,--export={malloc,strlen} \
-Wl,--export=opq_{encrypt_password,generate_keys,generate_verification} \
-Wl,--export=opq_size_of_{result,encrypted_password,password_key,encrypted_salted_password,encrypted_private_key,public_key,verification_nonce,verification} \
-Wl,--export=opq_result_{message, type{,_{success,failure,fatal_error}}} \
-Wl,--export=Base64{en,de}code{,_len} \
-Wl,--allow-undefined \
-Wl,--lto-O3 \
-DWITH_LIBECC_CONFIG_OVERRIDE \
-DWITH_CURVE_SECP256R1 \
-DWITH_HASH_SHA3_256 \
-DWITH_SIG_ECDSA \
-DWORDSIZE=32 \
-DARGON2_NO_THREADS \
-I Sources/CLibOpaque/Dependencies/libecc/src \
-I Sources/CLibOpaque/Dependencies/argon2/include \
-I Sources/CLibOpaque/Dependencies/tweetnacl \
-I Sources/CLibOpaque/include \
-I Sources/WebAssembly/Shim/Dependencies/base64 \
-I Sources/WebAssembly/Shim/include \
$(swift package describe --type json | jq -r '.targets[] | select(.c99name == "CLibOpaque").sources[]' | sed 's@^@Sources/CLibOpaque/@') \
$(ls Sources/WebAssembly/Shim/*.c | grep -v emscripten) \
Sources/WebAssembly/Shim/Dependencies/base64/base64.c \
-o opaque.wasm
```

#### Testing WebAssembly

The `WebAssemblyTestCompanion` target can be used in conjunction with `opaque.html` and the compiled `opaque.wasm` to demonstrate compatibility between the C and WebAssembly products.

