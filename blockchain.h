/**
 * blockchain.h
 * 
 * CHANGES:
 * - Reorganized function declarations into logical groups
 * - Added helper function declarations
 * - Improved comments for educational purposes
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
#include <stdint.h>

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

// ------------------------------------------------------------------
// Data Structures
// ------------------------------------------------------------------

/**
 * Transaction
 * 
 * Represents a single transaction in the blockchain.
 * Each transaction links to the previous one via prev_hash.
 */
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

/**
 * Chain File Header
 * 
 * Used for persistence to ensure compatibility and integrity.
 */
typedef struct ChainFileHeader {
    uint32_t version;
    uint32_t transaction_count;
    uint32_t checksum;  // Simple integrity check
} ChainFileHeader;

// Ensure our structure field sizes are sufficient
static_assert(sizeof(((Transaction*)0)->sender) >= ADDRESS_BUFFER_SIZE, 
              "Sender address field too small");
static_assert(sizeof(((Transaction*)0)->recipient) >= ADDRESS_BUFFER_SIZE, 
              "Recipient address field too small");
static_assert(sizeof(((Transaction*)0)->signature) >= HEX_SIG_SIZE, 
              "Signature field too small for RSA-2048 hex string");

// ------------------------------------------------------------------
// Core Chain Operations
// ------------------------------------------------------------------

// Chain access operations
Transaction* get_chain_head(void);
size_t get_transaction_count(void);

// Transaction operations
int add_transaction(const char* recipient, double amount);  // Returns 1 on success, 0 on failure
int validate_transaction(Transaction* tx);  // Returns 1 if valid, 0 if invalid
int is_double_spend(Transaction* tx);      // Returns 1 if double spend detected, 0 if ok

// Mining operations
void mine_reward(void);  // Mine a new block for current user

// Chain inspection
void print_chain(void);

// ------------------------------------------------------------------
// Chain Validation
// ------------------------------------------------------------------

int verify_chain_integrity(void);          // Returns 1 if chain is valid, 0 if corrupted

// ------------------------------------------------------------------
// Balance and Account Operations
// ------------------------------------------------------------------

double get_account_balance(const char* address);
size_t get_active_accounts(void);
double get_total_supply(void);

// ------------------------------------------------------------------
// Chain Persistence
// ------------------------------------------------------------------

int save_chain(void);  // Returns 1 on success, 0 on failure
int load_chain(void);  // Returns 1 on success, 0 on failure
void cleanup_chain(void);

// ------------------------------------------------------------------
// Chain Monitoring
// ------------------------------------------------------------------

time_t get_chain_modified_time(void);
int has_chain_changed(void);

// ------------------------------------------------------------------
// Helper Functions
// ------------------------------------------------------------------

int validate_address_format(const char* address);
int calculate_transaction_hash(Transaction* tx);
void append_transaction_to_chain(Transaction* tx);

#endif 