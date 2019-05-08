#ifndef libopaque_h
#define libopaque_h

typedef enum { OPQ_FATAL_ERROR, OPQ_FAILURE, OPQ_SUCCESS } OPQResultType;
typedef struct {
    OPQResultType type;
    
    union {
        // Valid if type is OPQ_SUCCESS
        struct {
            
        } success;
        
        // Valid if type is OPQ_FATAL_ERROR or OPQ_FAILURE
        struct {
            const char *file;
            int line;
            const char *function;
            const char *message;
        } failure;
    } body;
} opq_result;

typedef struct { unsigned char bytes[8]; } opq_word;

typedef struct {
    opq_word words[4];
} opq_salt;

typedef struct {
    opq_word words[4];
} opq_password_key;

typedef struct {
    opq_word words[12];
} opq_encrypted_password;

typedef struct {
    opq_word words[12];
} opq_encrypted_salted_password;

typedef struct {
    opq_word words[10];
} opq_encrypted_private_key;

typedef struct {
    opq_word words[4];
} opq_public_key;

typedef struct {
    opq_word words[1];
} opq_verification_nonce;

typedef struct {
    opq_word words[8];
} opq_verification;

opq_result opq_generate_random_salt(
                opq_salt *output_salt);

opq_result opq_encrypt_password(
                opq_encrypted_password *output_encrypted_password,
                opq_password_key *output_password_key,
                const unsigned char *password, int password_length);

opq_result opq_salt_encrypted_password(
                opq_encrypted_salted_password *output_encrypted_salted_password,
                const opq_encrypted_password *encrypted_password,
                const opq_salt *salt);

opq_result opq_generate_keys(
                opq_encrypted_private_key *output_encrypted_secret_key,
                opq_public_key *output_public_key,
                const opq_encrypted_salted_password *output_encrypted_salted_password,
                const opq_password_key *password_key);

opq_result opq_increment_verification_nonce(
                opq_verification_nonce *verification_nonce);

opq_result opq_generate_verification(
                opq_verification *output_verification,
                const opq_encrypted_private_key *encrypted_secret_key,
                const opq_verification_nonce *verification_nonce,
                const opq_encrypted_salted_password *output_encrypted_salted_password,
                const opq_password_key *password_key);

opq_result opq_validate_verification(
                const opq_public_key *public_key,
                const opq_verification_nonce *verification_nonce,
                const opq_verification *verification);

#endif /* libopaque_h */
