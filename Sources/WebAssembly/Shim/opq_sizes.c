#import "libopaque.h"

int opq_size_of_result() {
    return sizeof(opq_result);
}

int opq_size_of_encrypted_password() {
    return sizeof(opq_encrypted_password);
}

int opq_size_of_password_key() {
    return sizeof(opq_password_key);
}

int opq_size_of_encrypted_salted_password() {
    return sizeof(opq_encrypted_salted_password);
}

int opq_size_of_encrypted_private_key() {
    return sizeof(opq_encrypted_private_key);
}

int opq_size_of_public_key() {
    return sizeof(opq_public_key);
}

int opq_size_of_verification_nonce() {
    return sizeof(opq_verification_nonce);
}

int opq_size_of_verification() {
    return sizeof(opq_verification);
}
