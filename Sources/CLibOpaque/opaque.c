#import "libopaque.h"

// TODO: Remove standard library
#define WITH_STDLIB
#import "libsig.h"

#import "argon2.h"
#import "tweetnacl.h"

#import <string.h>
#import <assert.h>

#define MEMORY_HARDNESS 18

// MARK: - Result

#define SUCCESS ((opq_result){ OPQ_SUCCESS })
#define _NOT_SUCCESS(failure_type, message) \
    ((opq_result){ \
        .type = failure_type, \
        .body = { \
            .failure = { __FUNCTION__,  __LINE__, message } \
        } \
    })
#define FAILURE(message) _NOT_SUCCESS(OPQ_FAILURE, message)
#define FATAL_ERROR(message) _NOT_SUCCESS(OPQ_FATAL_ERROR, message)

// MARK: - Helpers

#define clear_struct(ref) { \
    static void *(*const volatile memset_sec)(void *, int, size_t) = &memset; \
    memset_sec(ref, 0, sizeof(*ref)); \
}

#define copy_struct(source, destination) { \
    int source_size = sizeof(*source);\
    int destination_size = sizeof(*destination); \
    if (source_size != destination_size) \
        FATAL_ERROR(#source " size must match " #destination); \
    memcpy(destination, source, source_size); \
}

// LibECC primitive

static void import_default_params(ec_params *out) {
    import_params(out, &secp256r1_str_params);
}

// Salted Password

typedef struct {
    opq_word words[4];
} opq_salted_password;

static opq_result opq_decrypt_salted_password(
                opq_salted_password *output_salted_password,
                const opq_encrypted_salted_password *encrypted_salted_password,
                const opq_password_key *password_key) {
    ec_params params;
    import_default_params(&params);
    
    // load r_inverse
    nn r_inverse;
    if (sizeof(*password_key) != BYTECEIL(params.ec_gen_order_bitlen))
        return FATAL_ERROR("Incorrect size for password key");
    nn_init_from_buf(&r_inverse, (const u8 *)password_key, sizeof(*password_key));
    
    // load beta
    prj_pt beta_pt;
    prj_pt_init(&beta_pt, &params.ec_curve);
    if (prj_pt_import_from_buf(&beta_pt, (const u8 *)encrypted_salted_password, sizeof(*encrypted_salted_password), &params.ec_curve) != 0)
        return FAILURE("Encrypted, salted password is invalid");
    
    // Calculate secret point
    prj_pt secret_prj;
    prj_pt_init(&secret_prj, &params.ec_curve);
    prj_pt_mul_monty(&secret_prj, &r_inverse, &beta_pt);
    
    // Convert secret point to affine
    aff_pt secret_aff;
    aff_pt_init(&secret_aff, &params.ec_curve);
    prj_pt_to_aff(&secret_aff, &secret_prj);
    
    // Export weaker secret
    unsigned char weaker_secret[BYTECEIL(params.ec_gen_order_bitlen)];
    fp_export_to_buf((u8 *)&weaker_secret, sizeof(weaker_secret), &secret_aff.x);
    
    nn_uninit(&r_inverse);
    prj_pt_uninit(&beta_pt);
    prj_pt_uninit(&secret_prj);
    aff_pt_uninit(&secret_aff);
    
    // Strengthen secret
    {
        if (sizeof(weaker_secret) % 2 != 0)
            return FATAL_ERROR("Incorrect size for salted password");
        unsigned char* password = (unsigned char *)&weaker_secret;
        int password_length = sizeof(weaker_secret) / 2;
        unsigned char* salt = password + password_length;
        int salt_length = sizeof(weaker_secret) - password_length;
        
        argon2_context context = {};
        
        // Argon2 Parameters
        context.t_cost = 2;
        context.m_cost = 1 << MEMORY_HARDNESS;
        
        context.out = (unsigned char *)output_salted_password;
        context.outlen = sizeof(*output_salted_password);
        context.pwd = password;
        context.pwdlen = password_length;
        context.salt = salt;
        context.saltlen = salt_length;
        context.secret = NULL;
        context.secretlen = 0;
        context.ad = NULL;
        context.adlen = 0;
        context.lanes = 1;
        context.threads = 1;
        context.flags = ARGON2_DEFAULT_FLAGS;
        context.version = ARGON2_VERSION_NUMBER;
        
        int result = argon2_ctx(&context, Argon2_id);
        clear_struct(&weaker_secret);
        
        return result == ARGON2_OK ? SUCCESS : FATAL_ERROR("Argon2id failed");
    }
}

// Keys (These needed to be padded with zeroes for NaCl)

typedef struct __attribute__((packed)) {
    unsigned char zeroes[crypto_secretbox_ZEROBYTES];
    unsigned char secret[crypto_sign_SECRETKEYBYTES];
} opq_plaintext_key;

typedef struct __attribute__((packed)) {
    unsigned char zeroes[crypto_secretbox_BOXZEROBYTES];
    unsigned char encrypted_secret[crypto_sign_SECRETKEYBYTES + (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)];
} opq_ciphertext_key;

// Signed Nonce

typedef struct __attribute__((packed)) {
    unsigned char signature[crypto_sign_BYTES];
    opq_verification_nonce nonce;
} opq_signed_nonce;

// MARK: - API

opq_result opq_generate_registration_token(
                opq_registration_token *output_registration_token)
{
    ec_params params;
    import_default_params(&params);

    nn random;
    nn_init(&random, 0);
    if (nn_get_random_mod(&random, &params.ec_gen_order) != 0)
        return FATAL_ERROR("Failed to generate entropy");

    assert(sizeof(*output_registration_token) == BYTECEIL(params.ec_gen_order_bitlen));
    nn_export_to_buf((u8 *)output_registration_token, sizeof(*output_registration_token), &random);
    nn_uninit(&random);

    return SUCCESS;
}

opq_result opq_generate_random_salt(
                opq_salt *output_salt)
{
    ec_params params;
    import_default_params(&params);

    nn random;
    nn_init(&random, 0);
    if (nn_get_random_mod(&random, &params.ec_gen_order) != 0)
        return FATAL_ERROR("Failed to generate entropy");

    assert(sizeof(*output_salt) == BYTECEIL(params.ec_gen_order_bitlen));
    nn_export_to_buf((u8 *)output_salt, sizeof(*output_salt), &random);
    nn_uninit(&random);

    return SUCCESS;
}

opq_result opq_encrypt_password(
                opq_encrypted_password *output_encrypted_password,
                opq_password_key *output_password_key,
                const char *password)
{
    ec_params params;
    import_default_params(&params);
    
    unsigned char password_digest[SHA3_256_DIGEST_SIZE];
    sha3_256((const unsigned char *)password, strlen(password), (u8 *)&password_digest);
    
    nn password_n;
    nn_init_from_buf(&password_n, (const u8 *)&password_digest, sizeof(password_digest));
    clear_struct(&password_digest);
    
    // a = generator * password_n
    prj_pt a;
    prj_pt_init(&a, &params.ec_curve);
    prj_pt_mul_monty(&a, &password_n, &params.ec_gen);
    
    // b = generator * password_n * r
    nn r;
    nn_init(&r, 0);
    if (nn_get_random_mod(&r, &params.ec_gen_order) != 0)
        return FATAL_ERROR("Entropy generation failed");
    prj_pt b;
    prj_pt_init(&b, &params.ec_curve);
    prj_pt_mul_monty(&b, &r, &a);
    
    // alpha = b
    if (prj_pt_export_to_buf(&b, (u8 *)output_encrypted_password, sizeof(*output_encrypted_password)) != 0)
        return FATAL_ERROR("Could not export alpha");
    
    // calulate r_inverse
    nn r_inverse;
    nn_init(&r_inverse, 0);
    nn_modinv(&r_inverse, &r, &params.ec_gen_order);
    if (sizeof(*output_password_key) != BYTECEIL(params.ec_gen_order_bitlen))
        return FATAL_ERROR("Incorrect size for password key");
    nn_export_to_buf((u8 *)output_password_key, sizeof(*output_password_key), &r_inverse);
    
    nn_uninit(&password_n);
    nn_uninit(&r);
    nn_uninit(&r_inverse);
    prj_pt_uninit(&a);
    prj_pt_uninit(&b);
    
    return SUCCESS;
}

opq_result opq_salt_encrypted_password(
                opq_encrypted_salted_password *output_encrypted_salted_password,
                const opq_encrypted_password *encrypted_password,
                const opq_salt *salt) {
    ec_params params;
    import_default_params(&params);
    
    // load salt
    nn salt_nn;
    if (sizeof(*salt) != BYTECEIL(params.ec_gen_order_bitlen))
        return FATAL_ERROR("Incorrect size for salt");
    nn_init_from_buf(&salt_nn, (const u8 *)&salt, sizeof(*salt));
    
    // load alpha
    prj_pt alpha_pt;
    prj_pt_init(&alpha_pt, &params.ec_curve);
    if (prj_pt_import_from_buf(&alpha_pt, (const u8 *)encrypted_password, sizeof(*encrypted_password), &params.ec_curve) != 0)
        return FAILURE("Invalid alpha value");
    
    // beta_pt = alpha_pt * salt
    prj_pt beta_pt;
    prj_pt_init(&beta_pt, &params.ec_curve);
    prj_pt_mul_monty(&beta_pt, &salt_nn, &alpha_pt);
    if (prj_pt_export_to_buf(&beta_pt, (u8 *)output_encrypted_salted_password, sizeof(*output_encrypted_salted_password)) != 0)
        return FATAL_ERROR("Could not export beta");
    
    nn_uninit(&salt_nn);
    prj_pt_uninit(&alpha_pt);
    prj_pt_uninit(&beta_pt);
    
    return SUCCESS;
}

opq_result opq_generate_keys(
                opq_encrypted_private_key *output_encrypted_private_key,
                opq_public_key *output_public_key,
                const opq_encrypted_salted_password *encrypted_salted_password,
                const opq_password_key *password_key) {
    opq_salted_password salted_password;
    {
        opq_result result = opq_decrypt_salted_password(&salted_password, encrypted_salted_password, password_key);
        if (result.type != OPQ_SUCCESS)
            return result;
    }
    
    // Generate registration keys
    opq_plaintext_key plaintext_key = {};
    {
        if (sizeof(*output_public_key) != crypto_sign_PUBLICKEYBYTES)
            return FATAL_ERROR("Incorrect size for public key");
        
        int result = crypto_sign_keypair(
                (unsigned char *)output_public_key,
                (unsigned char *)&plaintext_key.secret);
        if (result != 0)
            return FATAL_ERROR("Failed to generate key pair");
    }
    
    // Generate encrypted secret key
    {
        // Using "0" as a nonce is acceptable here because we will only ever encrypt this one message with the secret key. If we want to change the user's password, we run the whole algorithm again with a new salt.
        unsigned char nonce[crypto_secretbox_NONCEBYTES] = {};
        
        if (sizeof(salted_password) != crypto_secretbox_KEYBYTES)
            return FATAL_ERROR("Incorrect size for salted password");
    
        opq_ciphertext_key ciphertext_key = {};
        int result = crypto_secretbox(
            (unsigned char *)&ciphertext_key,
            (const unsigned char *)&plaintext_key, sizeof(plaintext_key),
            (const unsigned char *)&nonce,
            (const unsigned char *)&salted_password);
        
        clear_struct(&plaintext_key);
        clear_struct(&salted_password);
        
        if (result != 0)
            return FATAL_ERROR("Failed to encrypt keypair");
        
        if (sizeof(*output_encrypted_private_key) != sizeof(ciphertext_key.encrypted_secret))
            FATAL_ERROR("Incorrect size for encrypted key");
        
        copy_struct(&ciphertext_key.encrypted_secret, output_encrypted_private_key);
    }
    
    return SUCCESS;
}


opq_result opq_increment_verification_nonce(
                opq_verification_nonce *verification_nonce)
{
    uint64_t *value_pointer = (uint64_t *)(&verification_nonce->words[0]);
    if (*value_pointer == UINT64_MAX)
        return FAILURE("All nonces have been used");
    *value_pointer += 1;
    return SUCCESS;
}

opq_result opq_generate_verification(
                opq_verification *output_verification,
                const opq_encrypted_private_key *encrypted_private_key,
                const opq_verification_nonce *verification_nonce,
                const opq_encrypted_salted_password *encrypted_salted_password,
                const opq_password_key *password_key) {
    opq_salted_password salted_password;
    {
        opq_result result = opq_decrypt_salted_password(&salted_password, encrypted_salted_password, password_key);
        if (result.type != OPQ_SUCCESS)
            return result;
    }
    
    // decrypt the registration
    opq_plaintext_key plaintext_key;
    {
        
        opq_ciphertext_key ciphertext_key = {};
        
        copy_struct(encrypted_private_key, &ciphertext_key.encrypted_secret)
        
        // See note in opq_generate_keys
        unsigned char nonce[crypto_secretbox_NONCEBYTES] = {};
        
        int result = crypto_secretbox_open(
                (unsigned char *)&plaintext_key,
                (const unsigned char *)&ciphertext_key, sizeof(ciphertext_key),
                (const unsigned char *)&nonce,
                (const unsigned char *)&salted_password);
        
        clear_struct(&salted_password);
        
        if (result != 0)
            return FAILURE("Authentication failed.");
    }
    
    {
        opq_signed_nonce signed_nonce = {};
        unsigned long long signed_nonce_length = 0;
        
        int result = crypto_sign(
                (unsigned char *)&signed_nonce, &signed_nonce_length,
                (const unsigned char *)verification_nonce, sizeof(*verification_nonce),
                (const unsigned char *)&plaintext_key.secret);
        
        clear_struct(&plaintext_key);
        
        if (sizeof(*output_verification) != crypto_sign_BYTES)
            return FATAL_ERROR("Incorrect size for verification");
        copy_struct(&signed_nonce.signature, output_verification)
        
        clear_struct(&signed_nonce);
        
        if (result != 0)
            return FATAL_ERROR("Failed to sign verification");
    }
    
    return SUCCESS;
}

opq_result opq_validate_verification(
                const opq_public_key *public_key,
                const opq_verification_nonce *verification_nonce,
                const opq_verification *verification) {
    opq_signed_nonce signed_nonce = {};
    {
        copy_struct(verification_nonce, &signed_nonce.nonce)
        
        if (sizeof(*verification) != crypto_sign_BYTES)
            return FATAL_ERROR("Incorrect size for verification");
        copy_struct(verification, &signed_nonce.signature)
    }
    
    if (sizeof(*public_key) != crypto_sign_PUBLICKEYBYTES)
        return FATAL_ERROR("Incorrect size for public key");
    
    opq_signed_nonce verified_nonce;
    unsigned long long verified_nonce_length = 0;
    
    int result = crypto_sign_open(
        (unsigned char *)&verified_nonce, &verified_nonce_length,
        (const unsigned char *)&signed_nonce, sizeof(signed_nonce),
        (const unsigned char *)public_key);
    if (result != 0
        || verified_nonce_length != sizeof(opq_verification_nonce)
        || memcmp(&signed_nonce.nonce, &verified_nonce, verified_nonce_length) != 0)
        return FAILURE("Verification is invalid");
    
    return SUCCESS;
}
