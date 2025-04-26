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

Suite *account_suite(void) {
    Suite *s = suite_create("Accounts");

    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_password_success);
    tcase_add_test(tc_core, test_password_length);
    tcase_add_test(tc_core, test_password_validation);

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

