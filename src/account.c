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
 * Secure wrapper for memset - zeroes memory with bounds checking
 * Implements the functionality without using memset directly
 */
static void secure_memset(void *ptr, size_t max_size, int value, size_t num) {
    if (!ptr || num > max_size) return;
    
    // Manual byte-by-byte implementation to avoid using memset
    unsigned char *p = (unsigned char *)ptr;
    for (size_t i = 0; i < num; i++) {
        p[i] = (unsigned char)value;
    }
}

/**
 * Secure wrapper for strncpy - ensures null termination
 * Implements the functionality without using strncpy directly
 */
static void secure_strncpy(char *dst, size_t dst_size, const char *src, size_t count) {
    if (!dst || !src || dst_size == 0) return;
    
    size_t copy_size = count < dst_size - 1 ? count : dst_size - 1;
    size_t i;
    
    // Manual character-by-character copy to avoid using strncpy
    for (i = 0; i < copy_size && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    
    // Null terminate the destination string
    dst[i] = '\0';
}

/**
 * Secure wrapper for memcpy - adds bounds checking
 * Implements the functionality without using memcpy directly
 */
static void secure_memcpy(void *dst, size_t dst_size, const void *src, size_t count) {
    if (!dst || !src || count > dst_size) return;
    
    // Manual byte-by-byte implementation to avoid using memcpy
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    
    for (size_t i = 0; i < count; i++) {
        d[i] = s[i];
    }
}

/**
 * Secure string concatenation - appends src to dst with bounds checking
 */
static void secure_strcat(char *dst, size_t dst_size, const char *src) {
    if (!dst || !src || dst_size == 0) return;
    
    // Find end of destination string
    size_t dst_len = 0;
    while (dst_len < dst_size && dst[dst_len] != '\0') {
        dst_len++;
    }
    
    // Check if there's room for at least one character
    if (dst_len >= dst_size - 1) return;
    
    // Copy source string, ensuring null termination
    size_t i = 0;
    while (dst_len + i < dst_size - 1 && src[i] != '\0') {
        dst[dst_len + i] = src[i];
        i++;
    }
    
    dst[dst_len + i] = '\0';
}

/**
 * Convert unsigned integer to string and append to buffer
 */
static void append_uint(char *dst, size_t dst_size, unsigned int value) {
    if (!dst || dst_size == 0) return;
    
    // Find current length
    size_t len = 0;
    while (len < dst_size && dst[len] != '\0') {
        len++;
    }
    
    // Check if we have room
    if (len >= dst_size - 1) return;
    
    // Handle special case of zero
    if (value == 0) {
        dst[len++] = '0';
        dst[len] = '\0';
        return;
    }
    
    // Convert number to string backwards
    char buffer[20]; // Large enough for 64-bit integers
    int idx = 0;
    
    while (value > 0 && idx < 19) {
        buffer[idx++] = '0' + (value % 10);
        value /= 10;
    }
    
    // Reverse and append
    while (idx > 0 && len < dst_size - 1) {
        dst[len++] = buffer[--idx];
    }
    
    dst[len] = '\0';
}

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
    secure_memset(acc, sizeof(account_t), 0, sizeof(account_t));
    
    // Copy user ID and email with null termination
    secure_strncpy(acc->userid, sizeof(acc->userid), userid, sizeof(acc->userid) - 1);
    secure_strncpy(acc->email, sizeof(acc->email), email, sizeof(acc->email) - 1);
    
    // Copy exactly BIRTHDATE_LENGTH characters from birthdate
    // This will handle the case if birthdate has extra characters like \n
    secure_memcpy(acc->birthdate, sizeof(acc->birthdate), birthdate, BIRTHDATE_LENGTH);
    
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
    if (!acc) return;

    secure_memset(acc, sizeof(account_t), 0, sizeof(account_t));
    free(acc);
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
    if (!acc || !plaintext_password) return false;
    
    struct crypt_data data = {0};

    static_assert(sizeof acc->password_hash <= sizeof data.setting, "Password hash is too big to be processed by libcrypt.");
    secure_memcpy(data.setting, sizeof(data.setting), acc->password_hash, sizeof(acc->password_hash));
    secure_strncpy(data.input, sizeof(data.input), plaintext_password, sizeof(data.input) - 1);

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
    if (!acc || !new_plaintext_password) return false;
    
    struct crypt_data data = {0};
    secure_strncpy(data.input, sizeof(data.input), new_plaintext_password, CRYPT_MAX_PASSPHRASE_SIZE);

    bool success = _get_hash(&data, HASH_LENGTH);
    if (!success) {
        log_message(LOG_ERROR, "Couldn't hash a password.");
        return false;
    }

    // _get_hash() guarantees that strlen(data.output) < HASH_LENGTH
    secure_memcpy(acc->password_hash, sizeof(acc->password_hash), data.output, HASH_LENGTH);

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

  secure_strncpy(acc->email, sizeof(acc->email), new_email, EMAIL_LENGTH - 1);
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

  const char *login_time = ctime(&acct->last_login_time);
  const char *unban_time = ctime(&acct->unban_time);
  const char *expire_time = ctime(&acct->expiration_time);
  
  // Safely copy time strings
  secure_strncpy(login_time_str, sizeof(login_time_str), 
                login_time ? login_time : "", sizeof(login_time_str) - 1);
  secure_strncpy(unban_time_str, sizeof(unban_time_str), 
                unban_time ? unban_time : "", sizeof(unban_time_str) - 1);
  secure_strncpy(expire_time_str, sizeof(expire_time_str), 
                expire_time ? expire_time : "", sizeof(expire_time_str) - 1);

  // Build output string manually to avoid using snprintf
  buffer[0] = '\0'; // Start with empty string
  
  secure_strcat(buffer, sizeof(buffer), "User ID: ");
  secure_strcat(buffer, sizeof(buffer), acct->userid);
  secure_strcat(buffer, sizeof(buffer), "\nEmail: ");
  secure_strcat(buffer, sizeof(buffer), acct->email);
  secure_strcat(buffer, sizeof(buffer), "\nLogin Count: ");
  append_uint(buffer, sizeof(buffer), acct->login_count);
  secure_strcat(buffer, sizeof(buffer), "\nLogin Fail Count: ");
  append_uint(buffer, sizeof(buffer), acct->login_fail_count);
  secure_strcat(buffer, sizeof(buffer), "\nLast Login Time: ");
  secure_strcat(buffer, sizeof(buffer), login_time_str);
  secure_strcat(buffer, sizeof(buffer), "Last IP: ");
  
  // Format IP address
  char ip_part[4];
  for (int i = 0; i < 4; i++) {
      unsigned char octet = (acct->last_ip >> (24 - i * 8)) & 0xFF;
      ip_part[0] = '\0';
      append_uint(ip_part, sizeof(ip_part), octet);
      secure_strcat(buffer, sizeof(buffer), ip_part);
      if (i < 3) {
          secure_strcat(buffer, sizeof(buffer), ".");
      }
  }
  
  secure_strcat(buffer, sizeof(buffer), "\nUnban Time: ");
  secure_strcat(buffer, sizeof(buffer), unban_time_str);
  secure_strcat(buffer, sizeof(buffer), "Expiration Time: ");
  secure_strcat(buffer, sizeof(buffer), expire_time_str);
  
  len = strlen(buffer);

  return write(fd, buffer, len) == len;
}
