#ifndef TESTS_H
#define TESTS_H

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "blockchain.h"
#include "crypto.h"

// Test result structure
typedef struct {
    int tests_run;
    int tests_passed;
    int tests_failed;
} TestResults;

// Test functions
void run_all_tests(void);
void test_mining(void);
void test_transactions(void);
void test_chain_integrity(void);

// Helper functions
void assert_true(const char* test_name, int condition);
void assert_equal_double(const char* test_name, double expected, double actual, double epsilon);
void assert_equal_str(const char* test_name, const char* expected, const char* actual);

#endif 