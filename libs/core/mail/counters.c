/**
 * @file
 * @brief   Functions used to calculate mail message metrics needed to implement business rules.
 */

#include <dime/core/magma.h>

/**
 * @brief   Count the number of "Received:" lines in a mail message.
 * @param   message     a managed string containing the mail message to be scanned.
 * @return  the number of matching lines found, or 0 on failure.
 */
uint32_t mail_count_received(stringer_t *message) {

    size_t len;
    uchr_t *ptr;
    uint32_t result = 0;

    if (st_empty_out(message, &ptr, &len) || len <= 9) {
        log_pedantic("Message is too short to hold any valid received lines.");
        return result;
    }

    // Loop through and check every new line.
    // LOW: This loop could be improved using the new string interfaces.
    for (size_t i = 0; i <= (len - 9); i++) {

        // Make sure we detect the end of a header on messages without headers.
        if (*ptr == '\n' || i == 0) {

            // Detect the end of a header.
            if (*(ptr + 1) == '\r' && *(ptr + 2) == '\n') {
                i = len;
            } else if (*(ptr + 1) == '\n') {
                i = len;
            } else if (st_cmp_ci_starts(PLACER(ptr + 1, len - i - 1), PLACER("Received:", 9)) == 0) {
                result++;
            }

        }
        ptr++;
    }

    return result;
}

/**
 * @brief   Get the number of bytes taken up by a mail header.
 * @param   message     a managed string containing the full smtp mail message.
 * @return  0 on failure, or the number of bytes occupied by the mail header.
 */
size_t mail_header_end(stringer_t *message) {

    const chr_t *msg;
    size_t msglen;

    if (!message) {
        log_pedantic("Received a NULL message pointer.");
        return 0;
    }

    msglen = st_length_get(message);
    msg = st_char_get(message);

    for (size_t i = 0; i < msglen; i++) {
        if (msg[i] == '\n') {
            if (i + 1 < msglen && msg[i + 1] == '\n') {
                return i + 2;
            }
            if (i + 2 < msglen && msg[i + 1] == '\r' && msg[i + 2] == '\n') {
                return i + 3;
            }
        }
    }

    return msglen;
}
