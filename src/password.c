#include "password.h"
#include "logging.h"
#include <stdbool.h>
#include <assert.h>
#include <crypt.h>
#include <string.h>

/**
 * Tries to call crypt_gensalt() and crypt_r() with some known hash algorithms.
 * If none of the known algorithms work, logs an error message and returns false.
 * Ensures that the hash outputted has length < max_hash_length, otherwise fails.
 * On success, hash will be available in data->output. (On failure, the values
 * in `data` are undefined).
 * Returns true on success, false on failure.
 */
bool _get_hash(struct crypt_data *data, size_t max_hash_length) {
  // TODO: provide a fallback option
  static_assert(CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY,
    "libcrypt 4.0.0 or newer is required. (Make sure you're in the CITS3007 SDE "
    "and have installed the packages in `apt-packages.txt`)."
  );

  char *out;
  char *hash;

  // locally scoped macro to reduce code repetition
#define TRY_HASH(prefix, count) do { \
  out = crypt_gensalt_rn(prefix, count, NULL, 0, data->setting, sizeof data->setting); \
  if (out != NULL && out[0] != '*') { \
    hash = crypt_r(data->input, data->setting, data); \
    if (hash != NULL && data->output[0] != '*' && strlen(data->output) < max_hash_length) { \
      return true; \
    } \
  } \
} while (0)

  TRY_HASH("$y$", HASH_COUNT_YESCRYPT); // should be 73 chars
  TRY_HASH("$7$", HASH_COUNT_SCRYPT);   // should be 80 chars
  TRY_HASH("$2b$", HASH_COUNT_BCRYPT);  // should be 60 chars
  TRY_HASH("$6$", HASH_COUNT_SHA512);   // should be <=123 chars

#undef TRY_HASH

  log_message(LOG_ERROR, "None of the available hashing algorithms are supported.");

  return false;
}

