/**
 * blockchain_utils.h
 * 
 * CHANGES:
 * - New file created to centralize common utility functions
 * - Contains helper methods to reduce code duplication
 * 
 * Provides utility functions used throughout the blockchain system:
 * - Address validation and formatting
 * - Transaction hash calculations
 * - Chain traversal helpers
 * - Common string formatting and manipulation
 */

#ifndef BLOCKCHAIN_UTILS_H
#define BLOCKCHAIN_UTILS_H

#include "blockchain.h"

// ------------------------------------------------------------------
// Address Operations
// ------------------------------------------------------------------

/**
 * Validates an address format:
 * - Must start with "0x"
 * - Must have 6 hex characters after "0x"
 * - Total length must be 8 characters
 * 
 * Returns:
 *   1 if address is valid
 *   0 if address is invalid
 */
int validate_address_format(const char* address);

/**
 * Format address for display:
 * - For system addresses like "BLOCKCHAIN_REWARD", returns descriptive name
 * - For normal addresses, returns the address as-is
 */
const char* format_address_for_display(const char* address);

// ------------------------------------------------------------------
// Hash Operations
// ------------------------------------------------------------------

/**
 * Calculates the transaction data hash
 * Hashes the relevant transaction fields for chaining and validation
 * 
 * Returns:
 *   1 on success
 *   0 on failure
 */
int calculate_transaction_hash(Transaction* tx);

/**
 * Generates a hash prefix with the given number of zeros
 * Used to check if a hash meets the difficulty target
 * 
 * Returns: 
 *   Pointer to a static buffer containing zeros
 */
const char* get_difficulty_prefix(int difficulty);

// ------------------------------------------------------------------
// Chain Operations
// ------------------------------------------------------------------

/**
 * Finds the last transaction in the chain
 * 
 * Returns:
 *   Pointer to the last transaction
 *   NULL if chain is empty
 */
Transaction* find_chain_tail(void);

/**
 * Appends a transaction to the end of the chain
 */
void append_transaction_to_chain(Transaction* tx);

/**
 * Safely copies a transaction to a new memory location
 * 
 * Returns:
 *   Pointer to the new transaction
 *   NULL on failure
 */
Transaction* copy_transaction(const Transaction* src);

// ------------------------------------------------------------------
// String Operations
// ------------------------------------------------------------------

/**
 * Safely copies a string with bounds checking
 * 
 * Returns:
 *   1 on success
 *   0 if string is too large for buffer
 */
int safe_string_copy(char* dest, const char* src, size_t dest_size);

/**
 * Verifies if the string contains only hexadecimal characters
 * 
 * Returns:
 *   1 if string contains only hex characters
 *   0 otherwise
 */
int is_hex_string(const char* str);

#endif 