/**
 * blockchain_utils.c
 * 
 * CHANGES:
 * - New file created to centralize common utility functions 
 * - Implementation of helper methods to reduce code duplication
 * 
 * Provides utility functions used throughout the blockchain system:
 * - Address validation and formatting
 * - Transaction hash calculations 
 * - Chain traversal helpers
 * - Common string formatting and manipulation
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "blockchain_utils.h"
#include "blockchain.h"
#include "crypto.h"

// External reference to chain_head
extern Transaction* get_chain_head(void);

// ------------------------------------------------------------------
// Address Operations
// ------------------------------------------------------------------

int validate_address_format(const char* address) {
    // Check for NULL
    if (!address) {
        return 0;
    }

    // Check length (including '0x' prefix)
    size_t address_len = strlen(address);
    if (address_len != 8) {
        printf("Error: Invalid address length %zu (expected 8)\n", address_len);
        return 0;
    }
    
    // Check '0x' prefix
    if (strncmp(address, "0x", 2) != 0) {
        printf("Error: Address must start with '0x'\n");
        return 0;
    }
    
    // Validate hex characters after '0x'
    for (int i = 2; i < 8; i++) {
        if (!isxdigit((unsigned char)address[i])) {
            printf("Error: Invalid hex character in address at position %d\n", i);
            return 0;
        }
    }
    
    return 1;
}

const char* format_address_for_display(const char* address) {
    if (strcmp(address, MINING_REWARD_SENDER) == 0) {
        return "System Mining Reward";
    }
    return address;
}

// ------------------------------------------------------------------
// Hash Operations
// ------------------------------------------------------------------

int calculate_transaction_hash(Transaction* tx) {
    if (!tx) {
        return 0;
    }
    
    // Generate data hash from transaction fields
    char data[512];
    snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%ld",
            tx->sender, tx->recipient, tx->amount, tx->fee,
            tx->prev_hash, tx->timestamp);
    
    // Calculate hash using the crypto module
    generate_hash(data, strlen(data), tx->data_hash);
    tx->data_hash[sizeof(tx->data_hash) - 1] = '\0';
    
    return 1;
}

const char* get_difficulty_prefix(int difficulty) {
    static char zeros[DIFFICULTY + 1];
    memset(zeros, '0', difficulty);
    zeros[difficulty] = '\0';
    return zeros;
}

// ------------------------------------------------------------------
// Chain Operations
// ------------------------------------------------------------------

Transaction* find_chain_tail(void) {
    Transaction* chain_head = get_chain_head();
    
    if (chain_head == NULL) {
        return NULL;
    }
    
    Transaction* current = chain_head;
    while (current->next != NULL) {
        current = current->next;
    }
    
    return current;
}

void append_transaction_to_chain(Transaction* tx) {
    if (!tx) {
        return;
    }
    
    Transaction* chain_head = get_chain_head();
    
    // Set next pointer to NULL
    tx->next = NULL;
    
    // If chain is empty, set as head
    if (chain_head == NULL) {
        // This function call relies on the implementation in blockchain.c
        // which will need to be updated to use our new utility functions
        extern void set_chain_head(Transaction* tx);
        set_chain_head(tx);
        return;
    }
    
    // Find chain tail
    Transaction* tail = find_chain_tail();
    tail->next = tx;
}

Transaction* copy_transaction(const Transaction* src) {
    if (!src) {
        return NULL;
    }
    
    Transaction* new_tx = malloc(sizeof(Transaction));
    if (!new_tx) {
        printf("Error: Memory allocation failed for transaction copy\n");
        return NULL;
    }
    
    // Copy all fields
    memcpy(new_tx, src, sizeof(Transaction));
    
    // Set next to NULL to avoid unintended chain modification
    new_tx->next = NULL;
    
    return new_tx;
}

// ------------------------------------------------------------------
// String Operations
// ------------------------------------------------------------------

int safe_string_copy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) {
        return 0;
    }
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        // String too large for destination buffer
        return 0;
    }
    
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    
    return 1;
}

int is_hex_string(const char* str) {
    if (!str) {
        return 0;
    }
    
    while (*str) {
        if (!isxdigit((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    
    return 1;
} 