#include "logging.h"
#include "account.h"
#include "login.h"
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 7) {
    log_message(LOG_ERROR, "Not enough arguments");
    return 1;
  }

  char *userid = argv[1];
  char *password = argv[2];
  char *email = argv[3];
  char *birthdate = argv[4];

  account_t *acc = account_create(userid, password, email, birthdate);
  if (!account_validate_password(acc, password)) abort(); // trigger a crash to trip the fuzzer; this should never be false

  char *new_password = argv[5];
  account_update_password(acc, new_password);

  char *new_email = argv[6];
  account_set_email(acc, new_email);
  account_print_summary(acc, STDOUT_FILENO);

  login_session_data_t session = {0};

  handle_login(userid, password, 0, 0, STDOUT_FILENO, STDOUT_FILENO, &session);

  account_free(acc);

  return 0;
}
