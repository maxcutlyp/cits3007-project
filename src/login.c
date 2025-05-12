#define _POSIX_C_SOURCE 200809L

#include "login.h"
#include "account.h"
#include "logging.h"
#include "db.h"
#include <string.h>
#include <unistd.h>
#include <time.h>

login_result_t handle_login(
    const char *userid,
    const char *password,
    ip4_addr_t client_ip,
    time_t login_time,
    int client_output_fd,
    int log_fd,
    login_session_data_t *session
) {
    if (!userid || !password || !session) {
        log_message(LOG_ERROR, "handle_login: null input");
        dprintf(client_output_fd, "Login failed: internal error\n");
        dprintf(log_fd, "Login failed: internal error (null input)\n");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    account_t acc;
    if (!account_lookup_by_userid(userid, &acc)) {
        log_message(LOG_INFO, "User '%s' not found", userid);
        dprintf(client_output_fd, "Login failed: user not found\n");
        dprintf(log_fd, "User '%s' not found\n", userid);
        return LOGIN_FAIL_USER_NOT_FOUND;
    }

    if (account_is_banned(&acc)) {
        log_message(LOG_INFO, "User '%s' is banned", userid);
        dprintf(client_output_fd, "Login failed: account is banned\n");
        dprintf(log_fd, "User '%s' is banned\n", userid);
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    if (account_is_expired(&acc)) {
        log_message(LOG_INFO, "User '%s' is expired", userid);
        dprintf(client_output_fd, "Login failed: account expired\n");
        dprintf(log_fd, "User '%s' account expired\n", userid);
        return LOGIN_FAIL_ACCOUNT_EXPIRED;
    }

    if (!account_validate_password(&acc, password)) {
        account_record_login_failure(&acc);
        log_message(LOG_INFO, "Invalid password for user '%s'", userid);
        dprintf(client_output_fd, "Login failed: incorrect password\n");
        dprintf(log_fd, "Invalid password attempt for user '%s'\n", userid);
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    account_record_login_success(&acc, client_ip);

    session->account_id = acc.account_id;
    session->session_start = login_time;
    session->expiration_time = login_time + 3600; // 1 hour session

    log_message(LOG_INFO, "Login success for user '%s'", userid);
    dprintf(client_output_fd, "Login successful! Welcome, %s\n", userid);
    dprintf(log_fd, "User '%s' logged in successfully\n", userid);

    return LOGIN_SUCCESS;
}

