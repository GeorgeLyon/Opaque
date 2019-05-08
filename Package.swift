// swift-tools-version:5.0

import PackageDescription

enum Sources {
    
    static let libargon2: [String] = [
        "src/argon2.c",
        "src/core.c",
        "src/blake2/blake2b.c",
        "src/thread.c",
        "src/encoding.c",
        "src/opt.c",
    ].map({ "Dependencies/argon2/\($0)" })
    
    static let libecc: [String] = [
        // These are enumerated by combining `libecc` and `libsig` from the "Compiling with environments without GNU make" section of the README.
        "src/curves/aff_pt.c",
        "src/curves/curves.c",
        "src/curves/ec_params.c",
        "src/curves/ec_params.o",
        "src/curves/ec_shortw.c",
        "src/curves/prj_pt.c",
        "src/curves/prj_pt_monty.c",
        "src/fp/fp.c",
        "src/fp/fp_add.c",
        "src/fp/fp_montgomery.c",
        "src/fp/fp_mul.c",
        "src/fp/fp_mul_redc1.c",
        "src/fp/fp_pow.c",
        "src/fp/fp_rand.c",
        "src/hash/hash_algs.c",
        "src/hash/sha224.c",
        "src/hash/sha256.c",
        "src/hash/sha3-224.c",
        "src/hash/sha3-256.c",
        "src/hash/sha3-384.c",
        "src/hash/sha3-512.c",
        "src/hash/sha3.c",
        "src/hash/sha384.c",
        "src/hash/sha512.c",
        "src/nn/nn.c",
        "src/nn/nn_add.c",
        "src/nn/nn_div.c",
        "src/nn/nn_logical.c",
        "src/nn/nn_modinv.c",
        "src/nn/nn_mul.c",
        "src/nn/nn_mul_redc1.c",
        "src/nn/nn_rand.c",
        "src/sig/ec_key.c",
        "src/sig/ecdsa.c",
        "src/sig/ecfsdsa.c",
        "src/sig/ecgdsa.c",
        "src/sig/eckcdsa.c",
        "src/sig/ecosdsa.c",
        "src/sig/ecrdsa.c",
        "src/sig/ecsdsa.c",
        "src/sig/ecsdsa_common.c",
        "src/sig/sig_algs.c",
        "src/utils/print_curves.c",
        "src/utils/print_fp.c",
        "src/utils/print_keys.c",
        "src/utils/print_nn.c",
        "src/utils/utils.c",
    ].map({ "Dependencies/libecc/\($0)" })
    
    static let tweetNaCl: [String] = [
        "Dependencies/tweetnacl/tweetnacl.c"
    ]
    
}

enum Settings  {
    
    static let libargon2: [CSetting] = [
        .headerSearchPath("Dependencies/argon2/include")
    ]
    
    static let libecc: [CSetting] = [
        .headerSearchPath("Dependencies/libecc/src"),
    ]
    
    static let tweetNaCl: [CSetting] = [
        .headerSearchPath("Dependencies/tweetnacl")
    ]
    
}

let package = Package(
    name: "Opaque",
    products: [
        .library(
            name: "libopaque",
            targets: ["CLibOpaque"]),
        .library(
            name: "Opaque",
            targets: ["Opaque"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "CLibOpaque",
            path: ".",
            sources: Array([
                Sources.libargon2,
                Sources.libecc,
                Sources.tweetNaCl,
                [ "Sources/CLibOpaque" ]
            ].joined()),
            publicHeadersPath: "Sources/CLibOpaque/include",
            cSettings: Settings.libargon2 + Settings.libecc + Settings.tweetNaCl),
        .target(
            name: "Opaque",
            dependencies: ["CLibOpaque"]),
        .testTarget(
            name: "OpaqueTests",
            dependencies: ["Opaque"]),
    ]
)
