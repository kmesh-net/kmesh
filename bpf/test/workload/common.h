#ifndef __TEST_COMMON_H
#define __TEST_COMMON_H

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

// Test result codes
#define TEST_PASS    0
#define TEST_FAIL    1
#define TEST_SKIP    2
#define TEST_ERROR   3

// Test framework macros
#define test_init()                          \
    int test_result = TEST_PASS;             \
    do {

#define test_finish()                        \
    } while (0);                            \
    return test_result;

#define TEST(name, body)                     \
    do {                                    \
        printf("Running test: %s\n", name);  \
        body                                \
        printf("Test %s: PASS\n", name);     \
    } while (0);

// Assert macros
#define test_assert(cond, msg)               \
    do {                                    \
        if (!(cond)) {                      \
            printf("Assert failed: %s\n", msg); \
            printf("At %s:%d\n", __FILE__, __LINE__); \
            test_result = TEST_FAIL;         \
            return;                         \
        }                                   \
    } while (0)

// Skip test macro
#define SKIP_TEST(msg)                       \
    do {                                    \
        printf("Skipping test: %s\n", msg);  \
        test_result = TEST_SKIP;             \
        return;                             \
    } while (0)

// Test logging
#define test_log(fmt, ...)                   \
    printf(fmt "\n", ##__VA_ARGS__)

// Test setup/teardown helpers
typedef void (*test_setup_fn)(void);
typedef void (*test_teardown_fn)(void);

struct test_context {
    test_setup_fn setup;
    test_teardown_fn teardown;
    void *data;
};

static inline void test_run_with_context(const char *name, 
                                       struct test_context *ctx,
                                       void (*test_fn)(void *data))
{
    if (ctx->setup) {
        ctx->setup();
    }
    
    printf("Running test: %s\n", name);
    test_fn(ctx->data);
    
    if (ctx->teardown) {
        ctx->teardown(); 
    }
}

#endif /* __TEST_COMMON_H */