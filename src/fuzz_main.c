// afl-fuzz doesn't natively support fuzzing argv; instead, we have a
// wrapper entrypoint that transforms a given input file into argv.

#define _GNU_SOURCE
#include "logging.h"
#include "account.h"
#include "login.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define MAX_ARGS 128
#define MAX_LINE 4096

int _real_main(int argc, char **argv) {
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

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s input_file\n", argv[0]);
    return 1;
  }

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 1;
  }

  char line[MAX_LINE];
  if (!fgets(line, sizeof(line), f)) {
    perror("fgets");
    fclose(f);
    return 1;
  }
  fclose(f);

  // Tokenize line on whitespace
  char *args[MAX_ARGS];
  int i = 0;
  args[i++] = argv[0]; // set argv[0]

  char *token = strtok(line, " \t\r\n");
  while (token && i < MAX_ARGS - 1) {
    args[i++] = token;
    token = strtok(NULL, " \t\r\n");
  }
  args[i] = NULL;

  if (i == 0) {
    fprintf(stderr, "No arguments provided in file.\n");
    return 1;
  }

  return _real_main(i, args);
}
