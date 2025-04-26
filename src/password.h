#include <crypt.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef PASSWORD_H
#define PASSWORD_H

// Somewhat arbitrary values for crypt_gensalt's "count" value
#define HASH_COUNT_YESCRYPT 9       // 1..11, logarithmic
#define HASH_COUNT_SCRYPT 10        // 6..11, logarithmic
#define HASH_COUNT_BCRYPT 12        // 4..31, logarithmic
#define HASH_COUNT_SHA512 1000000   // 1000..999,999,999

/**
 * Used by account_update_password() to generate a hash.
 * Should not be used elsewhere! Call account_update_password() directly instead.
 */
bool _get_hash(struct crypt_data *data, size_t max_hash_length);

#endif // PASSWORD_H
