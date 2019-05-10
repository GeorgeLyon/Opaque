#import "libopaque.h"
#import "emscripten.h"

#import <string.h>

unsigned char *global_entropy_buffer = NULL;
unsigned int global_entropy_buffer_length = 0;

void opq_generate_random_bytes(unsigned char *buffer, int buffer_length)
{
  if (global_entropy_buffer_length < buffer_length)
    emscripten_force_exit(1);
  memcpy(buffer, global_entropy_buffer, buffer_length);
  memset(global_entropy_buffer, buffer_length, 0);
  global_entropy_buffer_length -= buffer_length;
}

EMSCRIPTEN_KEEPALIVE
opq_result wasm_generate_random_salt(
    opq_salt *output_salt,
    unsigned char entropy[64])
{
  global_entropy_buffer = entropy;
  global_entropy_buffer_length = 64;
  opq_result result = opq_generate_random_salt(output_salt);
  if (global_entropy_buffer_length != 0)
    emscripten_force_exit(1);
  return result;
}