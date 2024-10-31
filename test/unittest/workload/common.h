#ifndef __TEST_COMMON_H
#define __TEST_COMMON_H

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
// Test result codes
#define TEST_PASS  0
#define TEST_FAIL  1
#define TEST_SKIP  2
#define TEST_ERROR 3

// Coverage related paths
#define COVERAGE_PROG_PIN_DIR "/sys/fs/bpf/prog"
#define COVERAGE_MAP_PIN_DIR  "/sys/fs/bpf/map"
#define COVERAGE_BLOCK_LIST   "/tmp/block.list"
#define COVERAGE_OUTPUT       "/tmp/coverage.html"

#define MAX_SUBTESTS 64

typedef enum {
    TEST_STATUS_NONE = 0,
    TEST_STATUS_RUNNING,
    TEST_STATUS_COMPLETED,
    TEST_STATUS_FAILED,
    TEST_STATUS_SKIPPED
} test_status_t;

typedef struct {
    const char *name;
    test_status_t status;
    int result;
    const char *message;
    double duration; // Test execution time in seconds
} test_context_t;

// Global test state
typedef struct {
    const char *suite_name;
    test_context_t subtests[MAX_SUBTESTS];
    int subtest_count;
    int passed_count;
    int failed_count;
    int skipped_count;
} test_suite_t;

static test_suite_t current_suite = {0};
static test_context_t *current_test_ctx = NULL;

static inline void test_init(const char *test_name)
{
    printf("\n=== Starting test suite: %s ===\n", test_name);
    current_suite.suite_name = test_name;
    current_suite.subtest_count = 0;
    current_suite.passed_count = 0;
    current_suite.failed_count = 0;
    current_suite.skipped_count = 0;
}

static inline void test_finish(void)
{
    printf("\n=== Test suite summary: %s ===\n", current_suite.suite_name);
    printf("Total tests: %d\n", current_suite.subtest_count);
    printf("  Passed:  %d\n", current_suite.passed_count);
    printf("  Failed:  %d\n", current_suite.failed_count);
    printf("  Skipped: %d\n", current_suite.skipped_count);

    if (current_suite.subtest_count > 0) {
        printf("\nDetailed results:\n");
        for (int i = 0; i < current_suite.subtest_count; i++) {
            test_context_t *test = &current_suite.subtests[i];
            const char *status_str = test->result == TEST_PASS ? "PASS" :
                                     test->result == TEST_SKIP ? "SKIP" :
                                     test->result == TEST_FAIL ? "FAIL" :
                                                                 "ERROR";

            printf("  %s: %s (%.3fs)", test->name, status_str, test->duration);
            if (test->message) {
                printf(" - %s", test->message);
            }
            printf("\n");
        }
    }

    printf("\n=== Final result: %s ===\n\n", current_suite.failed_count > 0 ? "FAILED" : "PASSED");
}

#define TEST(test_name, fn)                                                                                            \
    do {                                                                                                               \
        const char *_test_name = test_name;                                                                            \
        if (current_suite.subtest_count >= MAX_SUBTESTS) {                                                             \
            printf("ERROR: Too many subtests\n");                                                                      \
            break;                                                                                                     \
        }                                                                                                              \
        test_context_t *_test_ctx = &current_suite.subtests[current_suite.subtest_count++];                            \
        _test_ctx->name = _test_name;                                                                                  \
        _test_ctx->status = TEST_STATUS_RUNNING;                                                                       \
        _test_ctx->result = TEST_PASS;                                                                                 \
        _test_ctx->message = NULL;                                                                                     \
        current_test_ctx = _test_ctx; /* Set current test context */                                                   \
        struct timespec _start_time, _end_time;                                                                        \
        clock_gettime(CLOCK_MONOTONIC, &_start_time);                                                                  \
        test_log("\n--- Starting test: %s ---", _test_name);                                                           \
        fn();                                                                                                          \
        clock_gettime(CLOCK_MONOTONIC, &_end_time);                                                                    \
        _test_ctx->duration =                                                                                          \
            (_end_time.tv_sec - _start_time.tv_sec) + (_end_time.tv_nsec - _start_time.tv_nsec) / 1e9;                 \
        _test_ctx->status = TEST_STATUS_COMPLETED;                                                                     \
        switch (_test_ctx->result) {                                                                                   \
        case TEST_PASS:                                                                                                \
            current_suite.passed_count++;                                                                              \
            break;                                                                                                     \
        case TEST_FAIL:                                                                                                \
            current_suite.failed_count++;                                                                              \
            break;                                                                                                     \
        case TEST_SKIP:                                                                                                \
            current_suite.skipped_count++;                                                                             \
            break;                                                                                                     \
        }                                                                                                              \
        test_log(                                                                                                      \
            "--- Test %s: %s ---\n",                                                                                   \
            _test_ctx->name,                                                                                           \
            _test_ctx->result == TEST_PASS ? "PASSED" :                                                                \
            _test_ctx->result == TEST_SKIP ? "SKIPPED" :                                                               \
                                             "FAILED");                                                                \
        current_test_ctx = NULL; /* Clear current test context */                                                      \
    } while (0)

#define SKIP_SUB_TEST(msg)                                                                                             \
    do {                                                                                                               \
        test_log("Skipping test: %s", msg);                                                                            \
        current_test_ctx->result = TEST_SKIP;                                                                          \
        current_test_ctx->message = msg;                                                                               \
        break;                                                                                                         \
    } while (0)

#define test_assert(cond, msg)                                                                                         \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            test_log("Assert failed: %s", msg);                                                                        \
            test_log("At %s:%d", __FILE__, __LINE__);                                                                  \
            if (current_test_ctx) {                                                                                    \
                current_test_ctx->result = TEST_FAIL;                                                                  \
                current_test_ctx->message = msg;                                                                       \
            }                                                                                                          \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

// Test logging
#define test_log(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

// Test setup/teardown helpers
typedef void (*test_setup_fn)(void);
typedef void (*test_teardown_fn)(void);

#endif /* __TEST_COMMON_H */