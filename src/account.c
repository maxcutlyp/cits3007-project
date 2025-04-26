#include "account.h"
#include "logging.h"
#include <crypt.h>
#include <string.h>
#include <assert.h>

// Somewhat arbitrary values for crypt_gensalt's "count" value
// Would've included them in the header, but it will be reset on submission.
#define HASH_COUNT_YESCRYPT 9       // 1..11, logarithmic
#define HASH_COUNT_SCRYPT 10        // 6..11, logarithmic
#define HASH_COUNT_BCRYPT 12        // 4..31, logarithmic
#define HASH_COUNT_SHA512 1000000   // 1000..999,999,999

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) plaintext_password;
  (void) email;
  (void) birthdate;

  return NULL;
}


void account_free(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

/**
 * Tries to call crypt_gensalt() and crypt_r() with some known hash algorithms.
 * If none of the known algorithms work, allows libcrypt to choose an algorithm
 * (and a "low default cost" value for "count").
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

#if CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
  TRY_HASH(NULL, 0); // will select a "low default cost"
#endif

#undef TRY_HASH

  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  struct crypt_data data = {0};
  strncpy(data.input, new_plaintext_password, CRYPT_MAX_PASSPHRASE_SIZE);

  bool success = _get_hash(&data, HASH_LENGTH);
  if (!success) {
    log_message(LOG_ERROR, "Couldn't hash a password.");
    return false;
  }

  // _get_hash() guarantees that strlen(data.output) < HASH_LENGTH
  memcpy(acc->password_hash, data.output, HASH_LENGTH);

  return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) ip;
}

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

