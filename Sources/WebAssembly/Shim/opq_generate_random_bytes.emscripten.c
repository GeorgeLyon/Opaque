#include "libopaque.h"
#include "emscripten.h"

EM_JS(void, opq_generate_random_bytes, (unsigned char *buffer, int buffer_length), {
  var array = new Uint8Array(buffer_length);
  window.crypto.getRandomValues(array);
  for (var i = 0; i < buffer_length; i++)
  {
    setValue(buffer + i, array[i], "i8")
  }
});