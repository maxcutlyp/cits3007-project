#include "account.h"
#include "logging.h"
#include <crypt.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>

// Somewhat arbitrary values for crypt_gensalt's "count" value
#define HASH_COUNT_YESCRYPT 7       // 1..11, logarithmic
#define HASH_COUNT_SCRYPT 8     // 6..11, logarithmic
#define HASH_COUNT_BCRYPT 11        // 4..31, logarithmic
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
    memcpy(acc->birthdate, birthdate, sizeof acc->birthdate);
    
    // Set default values
    acc->login_fail_count = 0;
    acc->expiration_time = 0;
    acc->unban_time = 0;
    
  
    if (!account_update_password(acc, plaintext_password)) {
        log_message(LOG_ERROR, "account_create: Failed to hash password.");
        free(acc);
        return NULL;
    }
    
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

  if (strlen(plaintext_password) >= sizeof data.input) {
      log_message(LOG_ERROR, "account_validate_password: plaintext_password is too big to be processed by libcrypt.");
      return false;
  }

  static_assert(sizeof acc->password_hash <= sizeof data.setting, "Password hash is too big to be processed by libcrypt.");
  memcpy(data.setting, acc->password_hash, sizeof acc->password_hash);
  strncpy(data.input, plaintext_password, sizeof data.input);

  char *out_hash = crypt_r(data.input, data.setting, &data);
  if (out_hash == NULL) return false;

  return strncmp(out_hash, acc->password_hash, sizeof acc->password_hash) == 0;
}

/**
 * Used by account_update_password() to generate a hash.
 * Should not be used elsewhere! Call account_update_password() directly instead.
 *
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

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  struct crypt_data data = {0};

  if (strlen(new_plaintext_password) >= sizeof data.input) {
      log_message(LOG_ERROR, "account_update_password: new_plaintext_password is too big to be processed by libcrypt.");
      return false;
  }

  strncpy(data.input, new_plaintext_password, sizeof data.input);

  bool success = _get_hash(&data, HASH_LENGTH);
  if (!success) {
    log_message(LOG_ERROR, "Couldn't hash a password.");
    return false;
  }

  // _get_hash() guarantees that strlen(data.output) < HASH_LENGTH
  memcpy(acc->password_hash, data.output, sizeof acc->password_hash);

  return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    if (acc == NULL) {
        log_message(LOG_ERROR, "Tried to record login success on a NULL account.");
        return;
    }
    acc->login_fail_count = 0;               
    acc->last_login_time = time(NULL);       
    acc->last_ip = ip;                 
}

void account_record_login_failure(account_t *acc) {
    if (acc == NULL) {
        log_message(LOG_ERROR, "Tried to record login failure on a NULL account.");
        return;
    }
    acc->login_fail_count++;                
    acc->login_count = 0;                    
    acc->last_login_time = time(NULL);       
                  
}

bool account_is_banned(const account_t *acc) {
    if (acc == NULL) {
      log_message(LOG_ERROR, "Tried to check ban status on a NULL account.");
      return false;
    }
    time_t now = time(NULL);
    if (now == (time_t)-1) {
      log_message(LOG_ERROR, "Failed to get current time in account_is_banned");
      return false;
    }
    time_t unban = acc->unban_time;
    if(unban > now)  {
      return true;
    }
    return false;
}


bool account_is_expired(const account_t *acc) {
    if (acc == NULL) {
        log_message(LOG_ERROR, "Tried to check expiration on a NULL account.");
        return false;
    }
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        log_message(LOG_ERROR, "Failed to get current time in account_is_expired.");
        return false;
    }
    time_t expired = acc->expiration_time;
    if(expired == 0) {
      return false;
    }
    return now > expired;
}

void account_set_unban_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    return;
  }
  acc->unban_time = t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  if (acc == NULL) {
    return;
  }
  acc->expiration_time = t;
}

void account_set_email(account_t *acc, const char *new_email) {
  if (acc == NULL || new_email == NULL) { // check for null pointers
    return;
  }

  for (const char *p = new_email; *p; p++) {
      if (!isprint((unsigned char)*p) || *p == ' ') { // check for printable characters and spaces
          log_message(LOG_ERROR, "Invalid email address."); 
          return;
      }
  }

  strncpy(acc->email, new_email, (sizeof acc->email) - 1);
  acc->email[EMAIL_LENGTH - 1] = '\0'; 
}

bool account_print_summary(const account_t *acct, int fd) {
  if (acct == NULL || fd < 0) {
    return false; // ensures we aren't working with a null pointer or invalid fd
  }

  char buffer[512];
  int len = 0;

  char login_time_str[26];
  char unban_time_str[26];
  char expire_time_str[26];

  char *ct;
#define SAFE_STRNCPY_CTIME(dest, src) do { \
  if ((ct = ctime(&(src))) == NULL) { \
    log_message(LOG_ERROR, "Couldn't convert " #src " to ctime."); \
    return false; \
  } \
  strncpy(dest, ct, sizeof(dest)); \
  dest[sizeof(dest) - 1] = '\0'; \
} while (0)
  SAFE_STRNCPY_CTIME(login_time_str, acct->last_login_time);
  SAFE_STRNCPY_CTIME(unban_time_str, acct->unban_time);
  SAFE_STRNCPY_CTIME(expire_time_str, acct->expiration_time);

  len = snprintf(buffer, sizeof(buffer), // prints out the summary of the account
      "User ID: %s\n"
      "Email: %s\n"
      "Login Count: %u\n"
      "Login Fail Count: %u\n"
      "Last Login Time: %s"
      "Last IP: %u.%u.%u.%u\n"
      "Unban Time: %s"
      "Expiration Time: %s",
      acct->userid,
      acct->email,
      acct->login_count,
      acct->login_fail_count,
      login_time_str,
      (acct->last_ip >> 24) & 0xFF,
      (acct->last_ip >> 16) & 0xFF,
      (acct->last_ip >> 8) & 0xFF,
      acct->last_ip & 0xFF,
      unban_time_str,
      expire_time_str
  );

  if (len < 0) {
    return false;
  }
  return write(fd, buffer, (size_t)len) == len;
}
