#include "tests.h"

static TestResults results = {0, 0, 0};

void assert_true(const char* test_name, int condition) {
    results.tests_run++;
    if (condition) {
        results.tests_passed++;
        printf("✓ %s\n", test_name);
    } else {
        results.tests_failed++;
        printf("✗ %s\n", test_name);
    }
}

void assert_equal_double(const char* test_name, double expected, double actual, double epsilon) {
    assert_true(test_name, fabs(expected - actual) < epsilon);
}

void assert_equal_str(const char* test_name, const char* expected, const char* actual) {
    assert_true(test_name, strcmp(expected, actual) == 0);
}

void test_mining(void) {
    printf("\nRunning mining tests...\n");
    
    cleanup_chain();
    initialize_user("test_user");
    
    mine_reward();
    
    // Test mining reward credited correctly
    const char* user_address = get_current_user_address();
    double balance = get_account_balance(user_address);
    assert_equal_double("Mining reward credited correctly", 
                       MINING_REWARD, balance, 0.0001);
    
    // Test mining transaction structure
    Transaction* head = get_chain_head();
    assert_true("Mining transaction exists", head != NULL);
    assert_equal_str("Mining reward sender is correct", 
                    "BLOCKCHAIN_REWARD", 
                    head->sender);
    assert_equal_str("Mining reward recipient is correct", 
                    user_address, 
                    head->recipient);
    assert_equal_double("Mining reward amount is correct", 
                       MINING_REWARD, 
                       head->amount, 
                       0.001);
    
    cleanup_chain();
}

void test_transactions(void) {
    printf("\nRunning transaction tests...\n");
    
    // Setup
    cleanup_chain();
    initialize_user("sender");
    const char* sender = get_current_user_address();
    
    // Mine some coins first
    mine_reward();
    double initial_balance = get_account_balance(sender);
    
    // Test valid transaction
    assert_true("Valid transaction succeeds",
                add_transaction("0xabcdef", 10.0));
    
    double expected_balance = initial_balance - 11.0; // amount + fee
    assert_equal_double("Balance reduced correctly after transaction",
                       expected_balance,
                       get_account_balance(sender),
                       0.001);
    
    // Test invalid transactions
    assert_true("Transaction with insufficient funds fails",
                !add_transaction("0xabcdef", initial_balance + 100.0));
    
    assert_true("Transaction with invalid address fails",
                !add_transaction("invalid", 1.0));
    
    assert_true("Transaction with zero amount fails",
                !add_transaction("0xabcdef", 0.0));
    
    cleanup_chain();
}

void test_chain_integrity(void) {
    printf("\nRunning chain integrity tests...\n");
    
    cleanup_chain();
    initialize_user("test_user");
    
    assert_true("Empty chain is valid", verify_chain_integrity());
    
    mine_reward();
    assert_true("Chain valid after mining", verify_chain_integrity());
    
    // Add regular transaction
    add_transaction("0xabcdef", 10.0);
    assert_true("Chain valid after transaction", verify_chain_integrity());
    
    cleanup_chain();
}

void run_all_tests(void) {
    printf("Starting AxChain tests...\n");
    
    test_mining();
    test_transactions();
    test_chain_integrity();
    
    printf("\nTest Results:\n");
    printf("Tests run: %d\n", results.tests_run);
    printf("Tests passed: %d\n", results.tests_passed);
    printf("Tests failed: %d\n", results.tests_failed);
} 