#define _POSIX_C_SOURCE 200809L

#include "../src/account.h"
#include <check.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

START_TEST (test_password_success) {
    account_t *acc = malloc(sizeof(account_t));
    bool res = account_update_password(acc, "test password");
    ck_assert_int_eq(res, true);
}
END_TEST

START_TEST (test_password_length) {
    account_t *acc = malloc(sizeof(account_t));
    bool res = account_update_password(acc, "test password");
    ck_assert_int_eq(res, true);
    ck_assert_int_lt(strnlen(acc->password_hash, HASH_LENGTH), HASH_LENGTH);
}
END_TEST

START_TEST (test_password_validation) {
    account_t *acc = malloc(sizeof(account_t));
    bool res = account_update_password(acc, "test password");
    ck_assert_int_eq(res, true);

    ck_assert_int_eq(account_validate_password(acc, "test password"), true);
    ck_assert_int_eq(account_validate_password(acc, "different password"), false);
}
END_TEST

START_TEST(test_account_create_success) {
    account_t *acc = account_create("user123", "securepass", "user@example.com", "1990-01-01");
    ck_assert_ptr_nonnull(acc);
    ck_assert_str_eq(acc->userid, "user123");
    ck_assert_str_eq(acc->email, "user@example.com");
    ck_assert_str_eq(acc->birthdate, "1990-01-01");
    ck_assert_int_eq(account_validate_password(acc, "securepass"), true);

    account_free(acc);
}
END_TEST

START_TEST(test_account_create_null_inputs) {
    ck_assert_ptr_null(account_create(NULL, "pass", "email", "dob"));
    ck_assert_ptr_null(account_create("user", NULL, "email", "dob"));
    ck_assert_ptr_null(account_create("user", "pass", NULL, "dob"));
    ck_assert_ptr_null(account_create("user", "pass", "email", NULL));
}
END_TEST

START_TEST(test_account_create_long_inputs) {
    char long_userid[USER_ID_LENGTH + 10];
    memset(long_userid, 'a', sizeof(long_userid));
    long_userid[sizeof(long_userid) - 1] = '\0';

    char long_email[EMAIL_LENGTH + 10];
    memset(long_email, 'b', sizeof(long_email));
    long_email[sizeof(long_email) - 1] = '\0';

    // Should fail due to input length
    ck_assert_ptr_null(account_create(long_userid, "pass", "email", "dob"));
    ck_assert_ptr_null(account_create("user", "pass", long_email, "dob"));
}
END_TEST

START_TEST(test_account_free_null) {
    // Should not crash
    account_free(NULL);
}
END_TEST

Suite *account_suite(void) {
    Suite *s = suite_create("Accounts");

    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_password_success);
    tcase_add_test(tc_core, test_password_length);
    tcase_add_test(tc_core, test_password_validation);

    tcase_add_test(tc_core, test_account_create_success);
    tcase_add_test(tc_core, test_account_create_null_inputs);
    tcase_add_test(tc_core, test_account_create_long_inputs);
    tcase_add_test(tc_core, test_account_free_null);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    Suite *s = account_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    int n_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return n_failed;
}

