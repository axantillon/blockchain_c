/**
 * blockchain.c
 * 
 * CHANGES:
 * - Added set_chain_head function needed by blockchain_utils
 * - Reduced code duplication by using utility functions
 * - Improved code organization and comments
 * 
 * Implementation of the blockchain core functionality.
 * Handles all blockchain operations including:
 * - Transaction creation and validation
 * - Mining new blocks with proof-of-work
 * - Chain integrity verification
 * - File persistence and chain state management
 * - Account balance calculations
 * - Chain statistics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "blockchain.h"
#include "blockchain_utils.h"
#include "crypto.h"
#include <ctype.h>  // For isxdigit()
#include <sys/stat.h>  // For stat()

// Global chain head
static Transaction* chain_head = NULL;
static time_t last_check_time = 0;
static time_t last_known_time = 0;

// Function prototypes for internal functions
static int perform_proof_of_work(Transaction* tx, int check_updates);

/**
 * set_chain_head
 * 
 * Sets the head of the blockchain to the given transaction.
 * ONLY to be used by blockchain_utils.c
 */
void set_chain_head(Transaction* tx) {
    chain_head = tx;
}

/**
 * get_chain_head
 * 
 * Returns the head of the blockchain.
 * 
 * Returns:
 *  Pointer to the head of the blockchain
 */
Transaction* get_chain_head(void) {
    return chain_head;
}

/**
 * verify_chain_integrity
 * 
 * Validates the entire blockchain for:
 * - Valid transaction formats
 * - Correct mining rewards
 * - Valid address formats
 * - Proper chain linking
 * 
 * Returns:
 *  1 if chain is valid
 *  0 if any validation fails
 */
int verify_chain_integrity(void) {
    Transaction* current = chain_head;
    char* prev_hash = NULL;
    
    while (current != NULL) {
        // Basic format validation
        if (!current->sender[0] || !current->recipient[0] || 
            current->amount < 0 || current->fee < 0) {
            printf("Error: Invalid transaction data detected\n");
            return 0;
        }

        // Verify chain linking
        if (prev_hash == NULL) {
            // First transaction should have all zeros
            char zeros[HASH_SIZE * 2 + 1] = {0};
            memset(zeros, '0', HASH_SIZE * 2);
            if (strcmp(current->prev_hash, zeros) != 0) {
                printf("Error: Invalid chain linking detected\n");
                return 0;
            }
        } else {
            // Other transactions should link to previous hash
            if (strcmp(current->prev_hash, prev_hash) != 0) {
                printf("Error: Invalid chain linking detected\n");
                return 0;
            }
        }

        // Verify proof of work
        if (strncmp(current->data_hash, get_difficulty_prefix(DIFFICULTY), DIFFICULTY) != 0) {
            printf("Error: Invalid proof of work\n");
            return 0;
        }

        // Verify transaction type-specific rules
        if (strcmp(current->sender, MINING_REWARD_SENDER) == 0) {
            // Mining reward validation
            if (current->amount != MINING_REWARD || current->fee != 0) {
                printf("Error: Invalid mining reward\n");
                return 0;
            }
        } else {
            // Normal transaction
            // Verify address format
            if (!validate_address_format(current->sender) || 
                !validate_address_format(current->recipient)) {
                return 0;
            }
            
            // Verify signature for non-reward transactions
            if (!verify_transaction(current)) {
                printf("Error: Invalid transaction signature\n");
                return 0;
            }
        }
        
        // Save hash for next iteration
        prev_hash = current->data_hash;
        current = current->next;
    }
    
    return 1;  // Chain is valid
}

/**
 * mine_reward
 * 
 * Mines a new reward transaction for the current user.
 * Performs proof-of-work to find a valid hash.
 */
void mine_reward(void) {
    Transaction* tx = malloc(sizeof(Transaction));
    if (!tx) {
        printf("Error: Failed to allocate transaction memory\n");
        return;
    }
    memset(tx, 0, sizeof(Transaction));
    
    // Set up mining reward transaction
    safe_string_copy(tx->sender, MINING_REWARD_SENDER, sizeof(tx->sender));
    safe_string_copy(tx->recipient, get_current_user_address(), sizeof(tx->recipient));
    tx->amount = MINING_REWARD;
    tx->fee = 0.0;  // No fee for mining rewards
    tx->timestamp = time(NULL);
    
    // Find previous hash from chain tail
    Transaction* tail = find_chain_tail();
    if (tail != NULL) {
        safe_string_copy(tx->prev_hash, tail->data_hash, sizeof(tx->prev_hash));
    } else {
        // First transaction in the chain
        memset(tx->prev_hash, '0', sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    }
    
    // Generate initial hash
    calculate_transaction_hash(tx);
    
    // Perform proof of work
    printf("Mining now, please wait...\n");
    if (!perform_proof_of_work(tx, 1)) {  // Check for updates
        printf("Mining aborted\n");
        free(tx);
        return;
    }
    
    // Add to chain
    append_transaction_to_chain(tx);
    printf("Successfully mined %0.2f %s!\n", MINING_REWARD, CURRENCY_SYMBOL);
}

/**
 * get_account_balance
 * 
 * Calculates the balance of a given address by iterating through all transactions.
 * 
 * Parameters:
 *   address: The address to check
 * 
 * Returns:
 *   Current balance of the address
 */
double get_account_balance(const char* address) {
    if (!address) return 0.0;
    
    double balance = 0.0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        // Add received money
        if (strcmp(current->recipient, address) == 0) {
            balance += current->amount;
        }
        
        // Subtract spent money
        if (strcmp(current->sender, address) == 0) {
            balance -= (current->amount + current->fee);
        }
        
        current = current->next;
    }
    
    return balance;
}

/**
 * print_chain
 * 
 * Displays the entire blockchain transaction history.
 * Shows details for each transaction including:
 * - Transaction type
 * - Sender and recipient addresses
 * - Amount, fees, and timestamps
 * - Hash details
 */
void print_chain(void) {
    if (chain_head == NULL) {
        printf("\nBlockchain is empty\n");
        return;
    }
    
    Transaction* current = chain_head;
    int index = 0;
    double total_burned = 0.0;
    
    printf("\n═══════════════════════════════════════════════\n");
    printf("             TRANSACTION HISTORY\n");
    printf("═══════════════════════════════════════════════\n\n");
    
    while (current != NULL) {
        char time_str[26];
        struct tm* tm_info = localtime(&current->timestamp);
        strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        
        // Transaction header
        printf("Transaction #%d\n", index++);
        printf("─────────────────────────────────────────────\n");
        
        // Transaction type with icon
        if (strcmp(current->sender, MINING_REWARD_SENDER) == 0) {
            printf("⛏️  Mining Reward\n");
        } else {
            printf("💸 Transfer\n");
        }
        
        // Transaction details
        printf("Time     : %s\n", time_str);
        
        // Format addresses for better readability
        printf("From     : %s\n", format_address_for_display(current->sender));
        printf("To       : %s\n", current->recipient);
        
        // Amount with currency symbol
        printf("Amount   : %.2f %s", current->amount, CURRENCY_SYMBOL);
        if (current->fee > 0) {
            printf(" (+ %.2f %s fee)\n", current->fee, CURRENCY_SYMBOL);
            total_burned += current->fee;
        } else {
            printf("\n");
        }
        
        // Technical details in a more compact format
        printf("Hash     : %s\n", current->data_hash);
        printf("Prev Hash: %s\n", current->prev_hash);
        
        printf("\n");
        current = current->next;
    }
    
    // Summary footer
    printf("═══════════════════════════════════════════════\n");
    printf("Total Transactions: %u\n", (unsigned int)index);
    if (total_burned > 0) {
        printf("Total Fees Burned: %.2f %s\n", total_burned, CURRENCY_SYMBOL);
    }
    printf("═══════════════════════════════════════════════\n\n");
}

/**
 * save_chain
 * 
 * Handles blockchain persistence with:
 * - Version checking
 * - Checksum validation
 * - Atomic file updates
 * - Chain integrity verification
 * 
 * Returns:
 *   1 on success
 *   0 on any error
 */
int save_chain(void) {
    // First verify chain integrity before saving
    if (!verify_chain_integrity()) {
        printf("Error: Cannot save corrupted chain\n");
        return 0;
    }

    FILE* file = fopen(TEMP_CHAIN_FILE, "wb");
    if (!file) {
        printf("Error: Could not create temporary chain file: %s\n", strerror(errno));
        return 0;
    }

    // Write header
    ChainFileHeader header = {
        .version = CHAIN_FILE_VERSION,
        .transaction_count = get_transaction_count(),
        .checksum = 0  // Will be calculated as we write
    };

    if (fwrite(&header, sizeof(header), 1, file) != 1) {
        printf("Error: Failed to write file header\n");
        fclose(file);
        remove(TEMP_CHAIN_FILE);
        return 0;
    }

    // Write transactions
    Transaction* current = chain_head;
    uint32_t checksum = 0;
    
    while (current != NULL) {
        // Write transaction
        if (fwrite(current, sizeof(Transaction), 1, file) != 1) {
            printf("Error: Failed to write transaction\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        
        // Update checksum (simple additive)
        for (size_t i = 0; i < sizeof(Transaction); i++) {
            checksum += ((unsigned char*)current)[i];
        }
        
        // Set next to NULL in file (will be reconstructed on load)
        Transaction* next = current->next;
        long pos = ftell(file);
        if (pos < 0) {
            printf("Error: Failed to get file position\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        
        // Go back to the next pointer position
        if (fseek(file, pos - sizeof(Transaction*), SEEK_SET) != 0) {
            printf("Error: Failed to seek in file\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        
        // Write NULL as next pointer
        Transaction* null_ptr = NULL;
        if (fwrite(&null_ptr, sizeof(Transaction*), 1, file) != 1) {
            printf("Error: Failed to write next pointer\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        
        // Restore position
        if (fseek(file, pos, SEEK_SET) != 0) {
            printf("Error: Failed to restore file position\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        
        current = next;
    }
    
    // Update header with checksum
    header.checksum = checksum;
    if (fseek(file, 0, SEEK_SET) != 0) {
        printf("Error: Failed to seek to file start\n");
        fclose(file);
        remove(TEMP_CHAIN_FILE);
        return 0;
    }
    
    if (fwrite(&header, sizeof(header), 1, file) != 1) {
        printf("Error: Failed to write updated header\n");
        fclose(file);
        remove(TEMP_CHAIN_FILE);
        return 0;
    }
    
    fclose(file);
    
    // Atomic update by renaming
    if (remove(CHAIN_FILE) != 0 && errno != ENOENT) {
        printf("Error: Failed to remove old chain file: %s\n", strerror(errno));
        remove(TEMP_CHAIN_FILE);
        return 0;
    }
    
    if (rename(TEMP_CHAIN_FILE, CHAIN_FILE) != 0) {
        printf("Error: Failed to rename chain file: %s\n", strerror(errno));
        remove(TEMP_CHAIN_FILE);
        return 0;
    }
    
    // Update last known modified time
    last_known_time = get_chain_modified_time();
    
    printf("Chain saved successfully (%u transactions)\n", header.transaction_count);
    return 1;
}

/**
 * load_chain
 * 
 * Loads blockchain from persistent storage:
 * - Validates file format and version
 * - Verifies checksum integrity
 * - Reconstructs transaction linked list
 * - Validates loaded chain
 * 
 * Returns:
 *   1 on success
 *   0 on any error
 */
int load_chain(void) {
    FILE* file = fopen(CHAIN_FILE, "rb");
    if (!file) {
        if (errno == ENOENT) {
            printf("No existing chain file found\n");
        } else {
            printf("Error opening chain file: %s\n", strerror(errno));
        }
        return 0;
    }
    
    // Read header
    ChainFileHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        printf("Error: Failed to read file header\n");
        fclose(file);
        return 0;
    }
    
    // Verify version
    if (header.version != CHAIN_FILE_VERSION) {
        printf("Error: Incompatible chain file version %u (expected %u)\n", 
               header.version, CHAIN_FILE_VERSION);
        fclose(file);
        return 0;
    }
    
    // Read transactions
    Transaction* new_chain = NULL;
    Transaction* tail = NULL;
    uint32_t checksum = 0;
    
    for (uint32_t i = 0; i < header.transaction_count; i++) {
        Transaction* tx = malloc(sizeof(Transaction));
        if (!tx) {
            printf("Error: Memory allocation failed\n");
            
            // Cleanup already loaded chain
            Transaction* current = new_chain;
            while (current != NULL) {
                Transaction* next = current->next;
                free(current);
                current = next;
            }
            
            fclose(file);
            return 0;
        }
        
        // Read transaction
        if (fread(tx, sizeof(Transaction), 1, file) != 1) {
            printf("Error: Failed to read transaction %u\n", i);
            free(tx);
            
            // Cleanup already loaded chain
            Transaction* current = new_chain;
            while (current != NULL) {
                Transaction* next = current->next;
                free(current);
                current = next;
            }
            
            fclose(file);
            return 0;
        }
        
        // Update checksum
        for (size_t j = 0; j < sizeof(Transaction); j++) {
            checksum += ((unsigned char*)tx)[j];
        }
        
        // Set next to NULL (will be updated below)
        tx->next = NULL;
        
        // Add to new chain
        if (new_chain == NULL) {
            new_chain = tx;
            tail = tx;
        } else {
            tail->next = tx;
            tail = tx;
        }
    }
    
    fclose(file);
    
    // Verify checksum
    if (checksum != header.checksum) {
        printf("Error: Chain file checksum mismatch\n");
        
        // Cleanup loaded chain
        Transaction* current = new_chain;
        while (current != NULL) {
            Transaction* next = current->next;
            free(current);
            current = next;
        }
        
        return 0;
    }
    
    // Clean up existing chain
    cleanup_chain();
    
    // Set new chain
    chain_head = new_chain;
    
    // Update last known modified time
    last_known_time = get_chain_modified_time();
    last_check_time = time(NULL);
    
    // Verify loaded chain integrity
    if (!verify_chain_integrity()) {
        printf("Warning: Loaded chain failed integrity check\n");
        return 0;
    }
    
    printf("Loaded %u transactions from chain file\n", header.transaction_count);
    return 1;
}

/**
 * cleanup_chain
 * 
 * Frees all memory associated with the blockchain:
 * - Iterates through all transactions
 * - Frees each transaction
 * - Resets chain head
 */
void cleanup_chain(void) {
    Transaction* current = chain_head;
    while (current != NULL) {
        Transaction* next = current->next;
        free(current);
        current = next;
    }
    chain_head = NULL;
}

/**
 * add_transaction
 * 
 * Creates and validates a new transaction:
 * 1. Validates addresses and amounts
 * 2. Checks sufficient balance
 * 3. Signs transaction
 * 4. Adds to chain if valid
 * 
 * Parameters:
 *   recipient: Target address (0x... format)
 *   amount: Amount to send (> 0)
 * 
 * Returns:
 *   1 if transaction added successfully
 *   0 if validation fails
 */
int add_transaction(const char* recipient, double amount) {
    // Validate recipient address format
    if (!validate_address_format(recipient)) {
        return 0;
    }
    
    // Validate amount
    if (amount <= 0) {
        printf("Error: Transaction amount must be positive\n");
        return 0;
    }
    
    // Get sender address
    const char* sender_address = get_current_user_address();
    
    // Check sender balance
    double balance = get_account_balance(sender_address);
    if (balance < amount + TRANSACTION_FEE) {
        printf("Error: Insufficient balance (%.2f %s). Need %.2f %s\n", 
               balance, CURRENCY_SYMBOL, amount + TRANSACTION_FEE, CURRENCY_SYMBOL);
        return 0;
    }
    
    // Create new transaction
    Transaction* tx = malloc(sizeof(Transaction));
    if (!tx) {
        printf("Error: Memory allocation failed\n");
        return 0;
    }
    memset(tx, 0, sizeof(Transaction));
    
    // Set transaction details
    safe_string_copy(tx->recipient, recipient, sizeof(tx->recipient));
    safe_string_copy(tx->sender, sender_address, sizeof(tx->sender));
    tx->amount = amount;
    tx->fee = TRANSACTION_FEE;
    tx->timestamp = time(NULL);
    
    // Get previous hash from chain tail
    Transaction* tail = find_chain_tail();
    if (tail != NULL) {
        safe_string_copy(tx->prev_hash, tail->data_hash, sizeof(tx->prev_hash));
    } else {
        // First transaction in the chain
        memset(tx->prev_hash, '0', sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    }
    
    // Generate data hash
    calculate_transaction_hash(tx);
    
    // Make a backup of the sender address (protection against sign_transaction modifying the sender)
    char backup_sender[ADDRESS_BUFFER_SIZE];
    safe_string_copy(backup_sender, tx->sender, sizeof(backup_sender));
    
    // Sign transaction
    sign_transaction(tx);
    
    // Verify sender wasn't corrupted
    if (strcmp(tx->sender, backup_sender) != 0) {
        safe_string_copy(tx->sender, backup_sender, sizeof(tx->sender));
    }
    
    // Validate transaction
    if (!validate_transaction(tx)) {
        free(tx);
        return 0;
    }
    
    // Perform proof of work
    if (!perform_proof_of_work(tx, 0)) {  // Don't check for updates
        free(tx);
        return 0;
    }
    
    // Add to chain
    append_transaction_to_chain(tx);
    
    printf("Transaction added successfully! Fee of %.2f %s burned\n", 
           TRANSACTION_FEE, CURRENCY_SYMBOL);
    return 1;
}

/**
 * validate_transaction
 * 
 * Performs comprehensive transaction validation:
 * - Address format and validity
 * - Amount and fee validation
 * - Balance checks
 * - Signature verification
 * - Mining reward validation
 * 
 * Parameters:
 *   tx: Transaction to validate
 * 
 * Returns:
 *   1 if transaction is valid
 *   0 if any validation fails
 */
int validate_transaction(Transaction* tx) {
    if (!tx) return 0;

    // Skip validation for mining rewards
    if (strcmp(tx->sender, MINING_REWARD_SENDER) == 0) {
        return tx->amount == MINING_REWARD && tx->fee == 0;
    }

    // Check for double spend
    if (is_double_spend(tx)) {
        printf("Error: Double spend detected\n");
        return 0;
    }

    // Verify transaction amount is positive
    if (tx->amount <= 0) {
        printf("Error: Transaction amount must be positive\n");
        return 0;
    }

    // Debug output
    printf("Debug: Validating transaction\n");
    printf("  Sender: '%s' (len: %zu)\n", tx->sender, strlen(tx->sender));
    printf("  Recipient: '%s' (len: %zu)\n", tx->recipient, strlen(tx->recipient));

    // Verify address format for both sender and recipient
    if (!validate_address_format(tx->sender)) {
        return 0;
    }
    
    if (!validate_address_format(tx->recipient)) {
        return 0;
    }

    // Verify signature
    if (!verify_transaction(tx)) {
        printf("Error: Invalid transaction signature\n");
        return 0;
    }

    // Check sender has sufficient balance
    double balance = get_account_balance(tx->sender);
    if (balance < tx->amount + tx->fee) {
        printf("Error: Insufficient balance (%.2f %s). Need %.2f %s\n", 
               balance, CURRENCY_SYMBOL, tx->amount + tx->fee, CURRENCY_SYMBOL);
        return 0;
    }

    return 1;
}

/**
 * is_double_spend
 * 
 * Checks if a transaction would result in double spending:
 * - Calculates total balance of sender
 * - Compares with transaction amount + fee
 * - Considers all existing transactions in the chain
 * 
 * Parameters:
 *   tx: Transaction to check
 * 
 * Returns:
 *   1 if double spend detected
 *   0 if transaction is valid
 */
int is_double_spend(Transaction* tx) {
    if (!tx) return 1;  // Invalid transaction
    
    // Mining rewards can't be double spends
    if (strcmp(tx->sender, MINING_REWARD_SENDER) == 0) {
        return 0;
    }
    
    // Calculate sender's balance
    double balance = get_account_balance(tx->sender);
    
    // Check if balance is sufficient
    if (balance < tx->amount + tx->fee) {
        printf("Double spend detected: Balance %.2f %s, trying to spend %.2f %s\n",
               balance, CURRENCY_SYMBOL, tx->amount + tx->fee, CURRENCY_SYMBOL);
        return 1;
    }
    
    return 0;
}

/**
 * get_transaction_count
 * 
 * Counts the total number of transactions in the blockchain
 * 
 * Returns:
 *   Total number of transactions
 */
size_t get_transaction_count(void) {
    size_t count = 0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        count++;
        current = current->next;
    }
    
    return count;
}

/**
 * get_mining_reward_count
 * 
 * Counts total number of mining rewards in the chain
 * 
 * Returns:
 *   Total number of mining rewards
 */
size_t get_mining_reward_count(void) {
    size_t count = 0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        if (strcmp(current->sender, MINING_REWARD_SENDER) == 0) {
            count++;
        }
        current = current->next;
    }
    
    return count;
}

/**
 * get_total_fees_burned
 * 
 * Calculates total fees burned in the chain
 * 
 * Returns:
 *   Total fees burned
 */
double get_total_fees_burned(void) {
    double total = 0.0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        if (strcmp(current->sender, MINING_REWARD_SENDER) != 0) {
            total += current->fee;
        }
        current = current->next;
    }
    
    return total;
}


// AccountNode structure for tracking active accounts
typedef struct AccountNode {
    char address[MINING_REWARD_BUFFER_SIZE];
    struct AccountNode* next;
} AccountNode;

/**
 * get_active_accounts
 * 
 * Counts unique addresses with positive balances:
 * - Tracks both senders and recipients
 * - Excludes zero balance accounts
 * - Uses temporary linked list for tracking
 * 
 * Returns:
 *   Number of active accounts
 */
size_t get_active_accounts(void) {
    AccountNode* head = NULL;
    size_t count = 0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        // Check sender
        if (strcmp(current->sender, MINING_REWARD_SENDER) != 0) {
            // Check if address already counted
            AccountNode* node = head;
            int found = 0;
            while (node != NULL) {
                if (strcmp(node->address, current->sender) == 0) {
                    found = 1;
                    break;
                }
                node = node->next;
            }
            
            if (!found && get_account_balance(current->sender) > 0) {
                AccountNode* new_node = malloc(sizeof(AccountNode));
                strncpy(new_node->address, current->sender, ADDRESS_BUFFER_SIZE);
                new_node->next = head;
                head = new_node;
                count++;
            }
        }
        
        // Check recipient
        AccountNode* node = head;
        int found = 0;
        while (node != NULL) {
            if (strcmp(node->address, current->recipient) == 0) {
                found = 1;
                break;
            }
            node = node->next;
        }
        
        if (!found && get_account_balance(current->recipient) > 0) {
            AccountNode* new_node = malloc(sizeof(AccountNode));
            strncpy(new_node->address, current->recipient, ADDRESS_BUFFER_SIZE);
            new_node->next = head;
            head = new_node;
            count++;
        }
        
        current = current->next;
    }
    
    // Cleanup
    while (head != NULL) {
        AccountNode* temp = head;
        head = head->next;
        free(temp);
    }
    
    return count;
}

/**
 * get_total_supply
 * 
 * Calculates total currency in circulation:
 * - Sums all mining rewards
 * - Excludes transaction fees (burned)
 * 
 * Returns:
 *   Total supply of currency
 */
double get_total_supply(void) {
    double total = 0.0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        if (strcmp(current->sender, MINING_REWARD_SENDER) == 0) {
            total += current->amount;  // Add mining rewards
        }
        current = current->next;
    }
    
    return total;
}

/**
 * get_chain_modified_time
 * 
 * Retrieves the last modification time of the chain file
 * Used for detecting external changes to the chain
 * 
 * Returns:
 *   Modification time as time_t
 *   0 if file does not exist or error occurs
 */
time_t get_chain_modified_time(void) {
    struct stat st;
    if (stat(CHAIN_FILE, &st) == 0) {
        return st.st_mtime;
    }
    return 0;  // File doesn't exist or error
}

/**
 * has_chain_changed
 * 
 * Determines if the chain file has been modified since last check
 * Used to detect changes made by another instance of the program
 * Implements rate limiting to avoid excessive file system checks
 * 
 * Returns:
 *   1 if chain has changed externally
 *   0 if unchanged or cannot determine
 */
int has_chain_changed(void) {
    // Rate limiting - check at most once per second
    time_t now = time(NULL);
    if (now - last_check_time < 1) {
        return 0;
    }
    
    last_check_time = now;
    
    // Get file modification time
    time_t current_mod_time = get_chain_modified_time();
    if (current_mod_time == 0) {
        return 0;  // File doesn't exist or error
    }
    
    // If file has been modified since last check
    if (current_mod_time > last_known_time) {
        return 1;
    }
    
    return 0;
}

/**
 * perform_proof_of_work
 * 
 * Implements the mining algorithm:
 * - Increments nonce until hash starts with specified zeros
 * - Monitors for chain updates if requested
 * - Reports progress during mining
 * 
 * Parameters:
 *   tx: Transaction to mine
 *   check_updates: Whether to check for chain updates
 * 
 * Returns:
 *   1 if successful
 *   0 if interrupted or failed
 */
static int perform_proof_of_work(Transaction* tx, int check_updates) {
    printf("\nFinding hash with %d leading zeros...\n\n", DIFFICULTY);
    unsigned int nonce = 0;
    char data[512];
    const char* difficulty_prefix = get_difficulty_prefix(DIFFICULTY);

    printf("═══════════════════════════════════════\n");
    do {
        if (nonce % 100000 == 0) {
            printf("\rHashes tried: %-10u", nonce);
            fflush(stdout);
            
            // Only check for updates if requested (mining rewards)
            if (check_updates && has_chain_changed()) {
                printf("\n\nChain updated by another instance, stopping...\n");
                return 0;
            }
        }
        
        // Generate hash with current nonce
        snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%u%ld",
                tx->sender, tx->recipient, tx->amount, tx->fee,
                tx->prev_hash, nonce, tx->timestamp);
        generate_hash(data, strlen(data), tx->data_hash);
        tx->data_hash[sizeof(tx->data_hash) - 1] = '\0';
        
        nonce++;
    } while (strncmp(tx->data_hash, difficulty_prefix, DIFFICULTY) != 0);

    printf("\n\nBlock mined!\n");
    printf("Hash    : %s\n", tx->data_hash);
    
    return 1;
}

