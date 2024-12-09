/**
 * blockchain.h
 * 
 * Core blockchain data structures and operations.
 * Defines the transaction structure, chain operations, and system constants.
 * Provides interfaces for mining, transaction management, and chain validation.
 * 
 * Key components:
 * - Transaction structure and chain management
 * - Mining and validation operations
 * - Account balance tracking
 * - Chain persistence (save/load)
 * - Chain statistics and monitoring
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <time.h>
#include <assert.h>

// System constants
#define HASH_SIZE SHA256_DIGEST_LENGTH
#define MINING_REWARD 50.0
#define DIFFICULTY 5  // 5 leading zeros
#define CHAIN_FILE "bin/axchain.dat"
#define TEMP_CHAIN_FILE "bin/axchain.tmp"
#define TRANSACTION_FEE 1.0  // Fixed fee that gets burned
#define CURRENCY_SYMBOL "AX"  // Currency symbol
#define ADDRESS_LENGTH 6      // Length of address in hex chars (excluding '0x')
#define FULL_ADDRESS_LENGTH (ADDRESS_LENGTH + 2)  // Including '0x'
#define ADDRESS_BUFFER_SIZE (FULL_ADDRESS_LENGTH + 1)  // Including null terminator
#define ADDRESS_PREFIX "0x"   // Prefix for addresses
#define RSA_SIG_SIZE 256  // RSA-2048 signature size in bytes
#define HEX_SIG_SIZE (RSA_SIG_SIZE * 2 + 1)  // Each byte becomes 2 hex chars + null
#define MINING_REWARD_SENDER "BLOCKCHAIN_REWARD"
#define MINING_REWARD_BUFFER_SIZE 18  // "BLOCKCHAIN_REWARD" + null
#define CHAIN_FILE_VERSION 1

typedef struct Transaction {
    char prev_hash[HASH_SIZE * 2 + 1];    // Hex string of previous hash
    char data_hash[HASH_SIZE * 2 + 1];    // Hex string of transaction data hash
    char signature[HEX_SIG_SIZE];         // Hex string of signature (512 chars + null)
    char sender[MINING_REWARD_BUFFER_SIZE];  // Large enough for both address and mining reward
    char recipient[ADDRESS_BUFFER_SIZE];   // Recipient's address (0x + 6 hex chars + null)
    double amount;                         // Transaction amount
    double fee;                           // Transaction fee (burned)
    time_t timestamp;                      // When the transaction was created
    struct Transaction* next;              // Next transaction in chain
} Transaction;

typedef struct ChainFileHeader {
    uint32_t version;
    uint32_t transaction_count;
    uint32_t checksum;  // Simple integrity check
} ChainFileHeader;

static_assert(sizeof(((Transaction*)0)->sender) >= ADDRESS_BUFFER_SIZE, 
              "Sender address field too small");
static_assert(sizeof(((Transaction*)0)->recipient) >= ADDRESS_BUFFER_SIZE, 
              "Recipient address field too small");
static_assert(sizeof(((Transaction*)0)->signature) >= HEX_SIG_SIZE, 
              "Signature field too small for RSA-2048 hex string");

// Core blockchain operations
int add_transaction(const char* recipient, double amount);  // Returns 1 on success, 0 on failure
void mine_reward(void);  // Changed from mine_transaction
void print_chain(void);
Transaction* get_chain_head(void);

// Chain persistence
int save_chain(void);  // Returns 1 on success, 0 on failure
int load_chain(void);  // Returns 1 on success, 0 on failure
void cleanup_chain(void);

// Account operations
double get_account_balance(const char* address);

// Validation operations
int validate_transaction(Transaction* tx);  // Returns 1 if valid, 0 if invalid
int verify_chain_integrity(void);          // Returns 1 if chain is valid, 0 if corrupted
int is_double_spend(Transaction* tx);      // Returns 1 if double spend detected, 0 if ok

// Statistics functions
size_t get_transaction_count(void);
size_t get_active_accounts(void);
double get_total_supply(void);

// Add these declarations
time_t get_chain_modified_time(void);
int has_chain_changed(void);

#endif 