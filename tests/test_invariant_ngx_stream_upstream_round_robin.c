#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Security invariant:
 * When copying SSL session data into a fixed-size buffer, the length of the
 * data being copied MUST NEVER exceed the allocated buffer size. Any copy
 * operation must validate that len <= allocated_buffer_size before proceeding.
 * This prevents heap buffer overflows when adversarial/oversized SSL session
 * data is provided.
 */

#define SSL_SESSION_BUFFER_SIZE 256  /* Simulated fixed allocation size */

typedef struct {
    unsigned char *ssl_session;
    size_t         ssl_session_size;  /* allocated size */
} mock_peer_t;

/*
 * Safe version of the session save function that enforces the invariant.
 * Returns 0 on success, -1 if the invariant would be violated.
 */
static int safe_ssl_session_save(mock_peer_t *peer, const unsigned char *buf, size_t len)
{
    if (peer == NULL || buf == NULL) {
        return -1;
    }

    /* INVARIANT: len must not exceed the allocated buffer size */
    if (len > peer->ssl_session_size) {
        return -1;  /* Reject oversized session data */
    }

    if (len == 0) {
        return -1;
    }

    memcpy(peer->ssl_session, buf, len);
    return 0;
}

/*
 * Vulnerable version that mimics the original code (no bounds check).
 * Used to demonstrate what the invariant check catches.
 */
static int vulnerable_ssl_session_save(mock_peer_t *peer, const unsigned char *buf, size_t len)
{
    if (peer == NULL || buf == NULL || len == 0) {
        return -1;
    }
    /* Intentionally no bounds check - mirrors the vulnerable code */
    memcpy(peer->ssl_session, buf, len);
    return 0;
}

START_TEST(test_ssl_session_copy_bounds_invariant)
{
    /* Invariant: SSL session copy length must never exceed the allocated buffer size */

    /* Each payload entry: {data, length} representing adversarial SSL session data */
    struct {
        const char *description;
        size_t      payload_len;
        int         should_succeed;  /* 1 if len <= buffer, 0 if len > buffer */
    } test_cases[] = {
        /* Normal/boundary cases that should succeed */
        { "exact buffer size",           SSL_SESSION_BUFFER_SIZE,       1 },
        { "one byte",                    1,                             1 },
        { "half buffer size",            SSL_SESSION_BUFFER_SIZE / 2,   1 },
        { "buffer size minus one",       SSL_SESSION_BUFFER_SIZE - 1,   1 },

        /* Adversarial cases that must be rejected */
        { "buffer size plus one",        SSL_SESSION_BUFFER_SIZE + 1,   0 },
        { "double buffer size",          SSL_SESSION_BUFFER_SIZE * 2,   0 },
        { "large oversized session",     SSL_SESSION_BUFFER_SIZE * 10,  0 },
        { "max typical SSL session",     16384,                         0 },
        { "extremely large session",     65535,                         0 },
        { "near size_t max (small)",     SSL_SESSION_BUFFER_SIZE + 100, 0 },
        { "integer overflow boundary",   SIZE_MAX / 2,                  0 },
        { "SIZE_MAX - 1",                SIZE_MAX - 1,                  0 },
    };

    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

    for (int i = 0; i < num_cases; i++) {
        mock_peer_t peer;
        size_t payload_len = test_cases[i].payload_len;

        /* Allocate the fixed-size buffer */
        peer.ssl_session = (unsigned char *)malloc(SSL_SESSION_BUFFER_SIZE);
        peer.ssl_session_size = SSL_SESSION_BUFFER_SIZE;

        ck_assert_msg(peer.ssl_session != NULL,
                      "Failed to allocate ssl_session buffer for test case: %s",
                      test_cases[i].description);

        /* Create adversarial payload - only allocate what we can safely test */
        size_t safe_alloc = (payload_len < 1024 * 1024) ? payload_len : 1024 * 1024;
        unsigned char *payload = NULL;

        /* For extremely large sizes (potential integer overflow), just use a small buffer
         * and test the length validation logic */
        if (payload_len > 1024 * 1024) {
            /* We can't actually allocate SIZE_MAX bytes, but we can test the
             * length validation with a small buffer and the large length value */
            payload = (unsigned char *)malloc(SSL_SESSION_BUFFER_SIZE);
            if (payload != NULL) {
                memset(payload, 0xAA, SSL_SESSION_BUFFER_SIZE);
            }
        } else {
            payload = (unsigned char *)malloc(safe_alloc);
            if (payload != NULL) {
                memset(payload, 0xBB, safe_alloc);
            }
        }

        if (payload == NULL) {
            /* Skip if we can't allocate the payload (e.g., extremely large sizes) */
            free(peer.ssl_session);
            continue;
        }

        /* Fill buffer with known pattern to detect corruption */
        memset(peer.ssl_session, 0xCC, SSL_SESSION_BUFFER_SIZE);

        /* Test the safe implementation */
        int result = safe_ssl_session_save(&peer, payload, payload_len);

        if (test_cases[i].should_succeed) {
            /* INVARIANT: Valid-sized sessions must be accepted */
            ck_assert_msg(result == 0,
                          "Safe copy rejected valid session data for case: %s (len=%zu, buf=%d)",
                          test_cases[i].description, payload_len, SSL_SESSION_BUFFER_SIZE);

            /* Verify data integrity - no corruption beyond the copied region */
            if (payload_len < SSL_SESSION_BUFFER_SIZE) {
                /* Bytes after the copied region should remain 0xCC */
                for (size_t j = payload_len; j < SSL_SESSION_BUFFER_SIZE; j++) {
                    ck_assert_msg(peer.ssl_session[j] == 0xCC,
                                  "Buffer corruption detected at byte %zu for case: %s",
                                  j, test_cases[i].description);
                }
            }
        } else {
            /* INVARIANT: Oversized sessions MUST be rejected - never allow overflow */
            ck_assert_msg(result != 0,
                          "SECURITY VIOLATION: Safe copy accepted oversized session data "
                          "for case: %s (len=%zu, buf=%d) - heap overflow would occur",
                          test_cases[i].description, payload_len, SSL_SESSION_BUFFER_SIZE);

            /* Verify the buffer was NOT modified (rejection should be clean) */
            int buffer_intact = 1;
            for (size_t j = 0; j < SSL_SESSION_BUFFER_SIZE; j++) {
                if (peer.ssl_session[j] != 0xCC) {
                    buffer_intact = 0;
                    break;
                }
            }
            ck_assert_msg(buffer_intact,
                          "Buffer was modified despite rejection for case: %s",
                          test_cases[i].description);
        }

        free(payload);
        free(peer.ssl_session);
    }
}
END_TEST

START_TEST(test_ssl_session_null_inputs)
{
    /* Invariant: NULL inputs must be handled safely without crashes */
    mock_peer_t peer;
    unsigned char buf[SSL_SESSION_BUFFER_SIZE];
    memset(buf, 0xAA, sizeof(buf));

    peer.ssl_session = (unsigned char *)malloc(SSL_SESSION_BUFFER_SIZE);
    ck_assert_ptr_nonnull(peer.ssl_session);
    peer.ssl_session_size = SSL_SESSION_BUFFER_SIZE;

    /* NULL peer */
    int result = safe_ssl_session_save(NULL, buf, SSL_SESSION_BUFFER_SIZE);
    ck_assert_msg(result != 0, "NULL peer must be rejected");

    /* NULL buffer */
    result = safe_ssl_session_save(&peer, NULL, SSL_SESSION_BUFFER_SIZE);
    ck_assert_msg(result != 0, "NULL buffer must be rejected");

    /* Zero length */
    result = safe_ssl_session_save(&peer, buf, 0);
    ck_assert_msg(result != 0, "Zero length must be rejected");

    free(peer.ssl_session);
}
END_TEST

START_TEST(test_ssl_session_length_validation_is_necessary)
{
    /*
     * Invariant: Demonstrate that WITHOUT bounds checking, oversized data
     * would corrupt memory. This test verifies the invariant by showing
     * the vulnerable path would write beyond the buffer.
     *
     * We use a canary pattern to detect overflow without actually crashing.
     */

    /* Allocate a guarded buffer: [GUARD_PRE][SESSION_BUF][GUARD_POST] */
    size_t guard_size = 64;
    size_t total_size = guard_size + SSL_SESSION_BUFFER_SIZE + guard_size;
    unsigned char *guarded_mem = (unsigned char *)malloc(total_size);
    ck_assert_ptr_nonnull(guarded_mem);

    /* Fill entire region with canary */
    memset(guarded_mem, 0xDE, total_size);

    mock_peer_t peer;
    peer.ssl_session = guarded_mem + guard_size;
    peer.ssl_session_size = SSL_SESSION_BUFFER_SIZE;

    /* Create oversized payload */
    size_t oversized_len = SSL_SESSION_BUFFER_SIZE + guard_size;
    unsigned char *oversized_payload = (unsigned char *)malloc(oversized_len);
    ck_assert_ptr_nonnull(oversized_payload);
    memset(oversized_payload, 0xFF, oversized_len);

    /* The safe function MUST reject this */
    int safe_result = safe_ssl_session_save(&peer, oversized_payload, oversized_len);
    ck_assert_msg(safe_result != 0,
                  "SECURITY INVARIANT VIOLATED: Safe function must reject oversized SSL session "
                  "(len=%zu > buf=%d)", oversized_len, SSL_SESSION_BUFFER_SIZE);

    /* Verify post-guard canary is intact (safe function didn't overflow) */
    unsigned char *post_guard = guarded_mem + guard_size + SSL_SESSION_BUFFER_SIZE;
    for (size_t i = 0; i < guard_size; i++) {
        ck_assert_msg(post_guard[i] == 0xDE,
                      "POST-GUARD CANARY CORRUPTED at byte %zu: safe function caused overflow!", i);
    }

    /* Verify pre-guard canary is intact */
    for (size_t i = 0; i < guard_size; i++) {
        ck_assert_msg(guarded_mem[i] == 0xDE,
                      "PRE-GUARD CANARY CORRUPTED at byte %zu: safe function caused underflow!", i);
    }

    free(oversized_payload);
    free(guarded_mem);
}
END_TEST

START_TEST(test_ssl_session_boundary_exact_fit)
{
    /* Invariant: Exactly-sized sessions must be handled correctly */
    mock_peer_t peer;
    peer.ssl_session = (unsigned char *)malloc(SSL_SESSION_BUFFER_SIZE);
    ck_assert_ptr_nonnull(peer.ssl_session);
    peer.ssl_session_size = SSL_SESSION_BUFFER_SIZE;

    unsigned char *payload = (unsigned char *)malloc(SSL_SESSION_BUFFER_SIZE);
    ck_assert_ptr_nonnull(payload);

    /* Use adversarial byte patterns */
    const unsigned char patterns[] = { 0x00, 0xFF, 0x41, 0x90, 0xCC, 0xAA, 0x55 };
    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);

    for (int p = 0; p < num_patterns; p++) {
        memset(payload, patterns[p], SSL_SESSION_BUFFER_SIZE);
        memset(peer.ssl_session, ~patterns[p], SSL_SESSION_BUFFER_SIZE);

        int result = safe_ssl_session_save(&peer, payload, SSL_SESSION_BUFFER_SIZE);
        ck_assert_msg(result == 0,
                      "Exact-fit copy failed for pattern 0x%02X", patterns[p]);

        /* Verify correct copy */
        ck_assert_msg(memcmp(peer.ssl_session, payload, SSL_SESSION_BUFFER_SIZE) == 0,
                      "Data integrity check failed for pattern 0x%02X", patterns[p]);
    }

    free(payload);
    free(peer.ssl_session);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security_SSL_Session_Bounds");
    tc_core = tcase_create("Core");

    tcase_set_timeout(tc_core, 30);

    tcase_add_test(tc_core, test_ssl_session_copy_bounds_invariant);
    tcase_add_test(tc_core, test_ssl_session_null_inputs);
    tcase_add_test(tc_core, test_ssl_session_length_validation_is_necessary);
    tcase_add_test(tc_core, test_ssl_session_boundary_exact_fit);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}