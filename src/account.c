#include "account.h"
#include "logging.h"
#include "password.h"
#include <crypt.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

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
                         const char *email, const char *birthdate)
{
    if (!userid || !plaintext_password || !email || !birthdate) {
        log_message(LOG_ERROR, "account_create: One or more input parameters are NULL.");
        return NULL;
    }
    
    // Check input lengths - make sure birthdate has at least BIRTHDATE_LENGTH chars
    if (strlen(userid) >= USER_ID_LENGTH ||
        strlen(email) >= EMAIL_LENGTH ||
        strlen(birthdate) < BIRTHDATE_LENGTH) {
        log_message(LOG_ERROR, "account_create: One or more input parameters have invalid length.");
        return NULL;
    }
    
    account_t *acc = malloc(sizeof(account_t));
    if (!acc) {
        log_message(LOG_ERROR, "account_create: Failed to allocate memory for account.");
        return NULL;
    }
    memset(acc, 0, sizeof(account_t));
    
    // Copy user ID and email with null termination
    strncpy(acc->userid, userid, sizeof(acc->userid) - 1);
    acc->userid[sizeof(acc->userid) - 1] = '\0';
    strncpy(acc->email, email, sizeof(acc->email) - 1);
    acc->email[sizeof(acc->email) - 1] = '\0';
    
    // Copy exactly BIRTHDATE_LENGTH characters from birthdate
    // This will handle the case if birthdate has extra characters like \n
    memcpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH);
    
    struct crypt_data data = {0};
    strncpy(data.input, plaintext_password, CRYPT_MAX_PASSPHRASE_SIZE);
    if (!_get_hash(&data, HASH_LENGTH)) {
        log_message(LOG_ERROR, "account_create: Failed to hash password.");
        free(acc);
        return NULL;
    }
    memcpy(acc->password_hash, data.output, HASH_LENGTH);
    
    // Set default values
    acc->login_fail_count = 0;
    acc->expiration_time = 0;
    acc->unban_time = 0;
    return acc;
}


void account_free(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
    if (!acc) return;

    memset(acc, 0, sizeof(account_t));
    free(acc);
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  struct crypt_data data = {0};

  static_assert(sizeof acc->password_hash <= sizeof data.setting, "Password hash is too big to be processed by libcrypt.");
  memcpy(data.setting, acc->password_hash, sizeof acc->password_hash);
  strncpy(data.input, plaintext_password, sizeof data.input);

  char *out_hash = crypt_r(data.input, data.setting, &data);
  if (out_hash == NULL) return false;

  return strncmp(out_hash, acc->password_hash, sizeof acc->password_hash) == 0;
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

