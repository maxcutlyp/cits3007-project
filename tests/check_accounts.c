#include <check.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../src/account.h"

START_TEST (test_password_hash) {
    account_t *acc = malloc(sizeof(account_t));
    bool res = account_update_password(acc, "test password");
    ck_assert_int_eq(res, true);
}
END_TEST

Suite *account_suite(void) {
    Suite *s = suite_create("Accounts");

    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_password_hash);
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

