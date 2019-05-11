#import "libopaque.h"

int wasm_test()
{
  char *password = "weak password";
  opq_result result;
    
  opq_salt salt = {};
  result = opq_generate_random_salt(&salt);
  
  opq_verification_nonce next_verification_nonce = {};

  // Registration
  opq_encrypted_private_key encrypted_private_key = {};
  opq_public_key public_key = {};
  {
    opq_encrypted_password encrypted_password = {};
    opq_password_key password_key = {};
    result = opq_encrypt_password(
      &encrypted_password, 
      &password_key, 
      password);
    if (result.type != OPQ_SUCCESS)
      return 1;

    opq_encrypted_salted_password encrypted_salted_password = {};
    result = opq_salt_encrypted_password(
      &encrypted_salted_password,
      &encrypted_password,
      &salt);
    if (result.type != OPQ_SUCCESS)
      return 1;

    result = opq_generate_keys(
      &encrypted_private_key,
      &public_key,
      &encrypted_salted_password,
      &password_key);
    if (result.type != OPQ_SUCCESS)
      return 1;
  }

  // Successful Authentication
  {
    opq_encrypted_password encrypted_password = {};
    opq_password_key password_key = {};
    result = opq_encrypt_password(
      &encrypted_password, 
      &password_key, 
      password);
    if (result.type != OPQ_SUCCESS)
      return 1;

    opq_encrypted_salted_password encrypted_salted_password = {};
    result = opq_salt_encrypted_password(
      &encrypted_salted_password,
      &encrypted_password,
      &salt);
    if (result.type != OPQ_SUCCESS)
      return 1;

    opq_verification_nonce verification_nonce = next_verification_nonce;
    result = opq_increment_verification_nonce(
      &verification_nonce);
    if (result.type != OPQ_SUCCESS)
      return 1;

    opq_verification verification = {};
    result = opq_generate_verification(
      &verification,
      &encrypted_private_key,
      &verification_nonce,
      &encrypted_salted_password,
      &password_key);
    if (result.type != OPQ_SUCCESS)
      return 1;

    result = opq_validate_verification(
      &public_key,
      &verification_nonce,
      &verification);
    if (result.type != OPQ_SUCCESS)
      return 1;
  }

  return 0;
}
