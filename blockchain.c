/**
 * blockchain.c
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
        char zeros[DIFFICULTY + 1];
        memset(zeros, '0', DIFFICULTY);
        zeros[DIFFICULTY] = '\0';
        if (strncmp(current->data_hash, zeros, DIFFICULTY) != 0) {
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
            // Normal transaction validation
            if (strlen(current->sender) != 8 || strncmp(current->sender, "0x", 2) != 0) {
                printf("Error: Invalid sender address format\n");
                return 0;
            }

            // Verify transaction signature
            if (!verify_transaction(current)) {
                printf("Error: Invalid transaction signature\n");
                return 0;
            }
        }
        
        // Always validate recipient
        if (strlen(current->recipient) != 8 || strncmp(current->recipient, "0x", 2) != 0) {
            printf("Error: Invalid recipient address format\n");
            return 0;
        }

        prev_hash = current->data_hash;
        current = current->next;
    }
    
    return 1;
}

/**
 * mine_reward
 * 
 * Performs proof-of-work mining to create a reward block:
 * 1. Creates mining reward transaction
 * 2. Finds hash with required difficulty (leading zeros)
 * 3. Monitors for chain updates during mining
 * 4. Adds block to chain if successful
 * 
 * Mining can be interrupted if chain is updated by another instance
 */
void mine_reward(void) {
    // Check for updates before starting
    if (has_chain_changed()) {
        printf("\nChain updated by another instance, reloading...\n");
        if (!load_chain()) {
            printf("Warning: Failed to reload chain\n");
            return;  // Don't start mining with outdated chain
        }
    }

    Transaction* tx = malloc(sizeof(Transaction));
    if (!tx) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    memset(tx, 0, sizeof(Transaction));
    
    // Set mining reward transaction
    const char* user_address = get_current_user_address();
    strncpy(tx->recipient, user_address, sizeof(tx->recipient) - 1);
    tx->recipient[sizeof(tx->recipient) - 1] = '\0';
    
    strncpy(tx->sender, MINING_REWARD_SENDER, sizeof(tx->sender) - 1);
    tx->sender[sizeof(tx->sender) - 1] = '\0';
    
    tx->amount = MINING_REWARD;
    tx->fee = 0;  // No fee for mining rewards
    tx->timestamp = time(NULL);
    
    // Get previous hash from the tail (newest transaction)
    Transaction* tail = chain_head;
    if (tail != NULL) {
        while (tail->next != NULL) {
            tail = tail->next;
        }
        strncpy(tx->prev_hash, tail->data_hash, sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    } else {
        memset(tx->prev_hash, '0', sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    }
    
    printf("\n        MINING BLOCK\n");
    printf("═══════════════════════════════════════\n");
    
    if (!perform_proof_of_work(tx, 1)) {  // Check for updates
        free(tx);
        load_chain();
        return;
    }
    
    printf("Reward  : %.2f AX\n", MINING_REWARD);
    printf("═══════════════════════════════════════\n\n");
    
    // Add to chain (chronologically)
    if (chain_head == NULL) {
        chain_head = tx;
    } else {
        // Find tail
        Transaction* current = chain_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = tx;
    }
    tx->next = NULL;  // Ensure new transaction is the tail
}

/**
 * get_account_balance
 * 
 * Calculates the current balance for an address by:
 * - Adding all received amounts
 * - Subtracting all sent amounts and fees
 * - Excluding mining rewards from fee calculations
 * 
 * Parameters:
 *   address: The address to check balance for
 * 
 * Returns:
 *   Current balance for the address
 */
double get_account_balance(const char* address) {
    double balance = 0.0;
    Transaction* current = chain_head;
    
    while (current != NULL) {
        // Add received amounts
        if (strcmp(current->recipient, address) == 0) {
            balance += current->amount;
        }
        // Subtract sent amounts (including fees)
        if (strcmp(current->sender, address) == 0 && 
            strcmp(current->sender, MINING_REWARD_SENDER) != 0) {
            balance -= (current->amount + current->fee);
        }
        current = current->next;
    }
    
    return balance;
}

/**
 * print_chain
 * 
 * Displays the entire blockchain in a formatted view:
 * - Transaction details
 * - Mining rewards vs transfers
 * - Timestamps and amounts
 * - Technical details (hashes)
 * - Summary statistics
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
        if (strcmp(current->sender, MINING_REWARD_SENDER) == 0) {
            printf("From     : System Mining Reward\n");
        } else {
            printf("From     : %s\n", current->sender);
        }
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

    // Write transactions and calculate checksum
    Transaction* current = chain_head;
    uint32_t checksum = 0;
    while (current != NULL) {
        // Update checksum
        const unsigned char* data = (const unsigned char*)current;
        for (size_t i = 0; i < sizeof(Transaction); i++) {
            checksum = (checksum << 1) | (checksum >> 31);  // Rotate left
            checksum ^= data[i];
        }

        if (fwrite(current, sizeof(Transaction), 1, file) != 1) {
            printf("Error: Failed to write transaction\n");
            fclose(file);
            remove(TEMP_CHAIN_FILE);
            return 0;
        }
        current = current->next;
    }

    // Write final checksum
    fseek(file, offsetof(ChainFileHeader, checksum), SEEK_SET);
    fwrite(&checksum, sizeof(checksum), 1, file);
    fclose(file);

    // Atomically replace old file
    if (rename(TEMP_CHAIN_FILE, CHAIN_FILE) != 0) {
        printf("Error: Failed to save chain file: %s\n", strerror(errno));
        remove(TEMP_CHAIN_FILE);
        return 0;
    }

    printf("Chain saved successfully (%u transactions)\n", header.transaction_count);
    last_check_time = time(NULL);
    last_known_time = get_chain_modified_time();
    return 1;
}

/**
 * load_chain
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
int load_chain(void) {
    FILE* file = fopen(CHAIN_FILE, "rb");
    if (!file) {
        if (errno != ENOENT) {
            printf("Error opening chain file: %s\n", strerror(errno));
        }
        return 0;
    }

    // Read and verify header
    ChainFileHeader header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        printf("Error: Failed to read file header\n");
        fclose(file);
        return 0;
    }

    if (header.version != CHAIN_FILE_VERSION) {
        printf("Error: Incompatible chain file version\n");
        fclose(file);
        return 0;
    }

    cleanup_chain();
    Transaction* prev = NULL;
    uint32_t checksum = 0;
    size_t loaded_count = 0;

    // Read transactions
    Transaction tx;
    while (fread(&tx, sizeof(Transaction), 1, file) == 1) {
        // Update checksum
        const unsigned char* data = (const unsigned char*)&tx;
        for (size_t i = 0; i < sizeof(Transaction); i++) {
            checksum = (checksum << 1) | (checksum >> 31);
            checksum ^= data[i];
        }

        Transaction* new_tx = malloc(sizeof(Transaction));
        if (!new_tx) {
            printf("Error: Memory allocation failed\n");
            fclose(file);
            cleanup_chain();
            return 0;
        }

        memcpy(new_tx, &tx, sizeof(Transaction));
        new_tx->next = NULL;

        if (prev == NULL) {
            chain_head = new_tx;
        } else {
            prev->next = new_tx;
        }
        prev = new_tx;
        loaded_count++;
    }

    fclose(file);

    // Verify transaction count and checksum
    if (loaded_count != header.transaction_count) {
        printf("Error: Transaction count mismatch\n");
        cleanup_chain();
        return 0;
    }

    if (checksum != header.checksum) {
        printf("Error: Chain file corrupted (checksum mismatch)\n");
        cleanup_chain();
        return 0;
    }

    // Verify chain integrity
    if (!verify_chain_integrity()) {
        printf("Error: Chain integrity check failed\n");
        cleanup_chain();
        return 0;
    }

    printf("Chain loaded successfully (%u transactions)\n", (unsigned int)loaded_count);
    last_check_time = time(NULL);
    last_known_time = get_chain_modified_time();
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
    Transaction* tx = malloc(sizeof(Transaction));
    if (!tx) {
        printf("Error: Memory allocation failed\n");
        return 0;
    }
    memset(tx, 0, sizeof(Transaction));
    
    // Set transaction details
    strncpy(tx->recipient, recipient, sizeof(tx->recipient) - 1);
    tx->recipient[sizeof(tx->recipient) - 1] = '\0';
    
    // Get and validate sender address before setting
    const char* sender_address = get_current_user_address();
    if (!sender_address) {
        printf("Error: Could not get sender address\n");
        free(tx);
        return 0;
    }
    
    // Copy sender address with explicit length check
    size_t sender_len = strlen(sender_address);
    if (sender_len != 8 || strncmp(sender_address, "0x", 2) != 0) {
        printf("Error: Invalid sender address format\n");
        free(tx);
        return 0;
    }
    
    // Use strncpy for the sender address
    strncpy(tx->sender, sender_address, sizeof(tx->sender) - 1);
    tx->sender[sizeof(tx->sender) - 1] = '\0';
    
    tx->amount = amount;
    tx->fee = TRANSACTION_FEE;
    tx->timestamp = time(NULL);
    
    // Get previous hash from the tail (newest transaction)
    Transaction* tail = chain_head;
    if (tail != NULL) {
        while (tail->next != NULL) {
            tail = tail->next;
        }
        strncpy(tx->prev_hash, tail->data_hash, sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    } else {
        memset(tx->prev_hash, '0', sizeof(tx->prev_hash) - 1);
        tx->prev_hash[sizeof(tx->prev_hash) - 1] = '\0';
    }
    
    // Generate data hash
    char data[512];
    snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%ld",
            tx->sender, tx->recipient, tx->amount, tx->fee,
            tx->prev_hash, tx->timestamp);
    generate_hash(data, strlen(data), tx->data_hash);
    tx->data_hash[sizeof(tx->data_hash) - 1] = '\0';
    
    // Make a backup of the sender address
    char backup_sender[ADDRESS_BUFFER_SIZE];
    strncpy(backup_sender, tx->sender, sizeof(backup_sender));
    
    // Sign transaction
    sign_transaction(tx);
    
    // Verify sender wasn't corrupted
    if (strcmp(tx->sender, backup_sender) != 0) {
        strncpy(tx->sender, backup_sender, sizeof(tx->sender) - 1);
        tx->sender[sizeof(tx->sender) - 1] = '\0';
    }
    
    // Validate transaction
    if (!validate_transaction(tx)) {
        free(tx);
        return 0;
    }
    
    if (!perform_proof_of_work(tx, 0)) {  // Don't check for updates
        free(tx);
        return 0;
    }
    
    // Add to chain (chronologically)
    if (chain_head == NULL) {
        chain_head = tx;
    } else {
        // Find tail
        Transaction* current = chain_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = tx;
    }
    tx->next = NULL;  // Ensure new transaction is the tail
    
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

    // Add zero amount check
    if (tx->amount <= 0) {
        printf("Error: Transaction amount must be positive\n");
        return 0;
    }

    // Check for double spend
    if (is_double_spend(tx)) {
        printf("Error: Double spend detected\n");
        return 0;
    }

    // Debug output
    printf("Debug: Validating transaction\n");
    printf("  Sender: '%s' (len: %zu)\n", tx->sender, strlen(tx->sender));
    printf("  Recipient: '%s' (len: %zu)\n", tx->recipient, strlen(tx->recipient));

    // Verify address format
    if (!tx->sender[0] || !tx->recipient[0]) {
        printf("Error: Empty address\n");
        return 0;
    }

    // Check address length (including '0x' prefix)
    if (strlen(tx->sender) != 8) {
        printf("Error: Invalid sender address length %zu (expected 8)\n", strlen(tx->sender));
        return 0;
    }
    
    if (strlen(tx->recipient) != 8) {
        printf("Error: Invalid recipient address length %zu (expected 8)\n", strlen(tx->recipient));
        return 0;
    }

    // Check '0x' prefix
    if (strncmp(tx->sender, "0x", 2) != 0) {
        printf("Error: Sender address must start with '0x'\n");
        return 0;
    }
    
    if (strncmp(tx->recipient, "0x", 2) != 0) {
        printf("Error: Recipient address must start with '0x'\n");
        return 0;
    }

    // Validate hex characters after '0x'
    for (int i = 2; i < 8; i++) {
        if (!isxdigit((unsigned char)tx->sender[i])) {
            printf("Error: Invalid hex character in sender address at position %d\n", i);
            return 0;
        }
        if (!isxdigit((unsigned char)tx->recipient[i])) {
            printf("Error: Invalid hex character in recipient address at position %d\n", i);
            return 0;
        }
    }

    // Check balance
    double balance = get_account_balance(tx->sender);
    if (balance < (tx->amount + tx->fee)) {
        printf("Error: Insufficient balance (%.2f) for transaction (%.2f + %.2f fee)\n",
               balance, tx->amount, tx->fee);
        return 0;
    }

    // Verify signature
    if (!verify_transaction(tx)) {
        printf("Error: Invalid transaction signature\n");
        return 0;
    }

    return 1;
}

/**
 * is_double_spend
 * 
 * Checks if a transaction is attempting to double spend:
 * - Looks for transactions with same sender and timestamp
 * 
 * Parameters:
 *   tx: Transaction to check
 * 
 * Returns:
 *   1 if double spend detected
 *   0 if transaction is unique
 */
int is_double_spend(Transaction* tx) {
    Transaction* current = chain_head;
    
    while (current != NULL) {
        // Look for another transaction with same sender and timestamp
        if (current != tx && 
            strcmp(current->sender, tx->sender) == 0 &&
            current->timestamp == tx->timestamp) {
            return 1;
        }
        current = current->next;
    }
    
    return 0;
}

/**
 * get_transaction_count
 * 
 * Counts total number of transactions in the chain
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
 * Gets the last modification time of the chain file
 * 
 * Returns:
 *   Modification timestamp
 *   0 if file doesn't exist
 */
time_t get_chain_modified_time(void) {
    struct stat st;
    if (stat(CHAIN_FILE, &st) == 0) {
        return st.st_mtime;
    }
    return 0;  // File doesn't exist
}

/**
 * has_chain_changed
 * 
 * Monitors blockchain file for updates from other instances:
 * - Checks modification time
 * - Throttles checks to once per second
 * - Handles file existence
 * 
 * Returns:
 *   1 if chain needs reload
 *   0 if chain is current
 */
int has_chain_changed(void) {
    time_t current_time = time(NULL);
    
    // Throttle checks to once per second
    if (current_time - last_check_time < 1) {
        return 0;
    }
    
    last_check_time = current_time;
    time_t file_time = get_chain_modified_time();
    
    // If file doesn't exist or hasn't changed
    if (file_time == 0 || file_time <= last_known_time) {
        return 0;
    }
    
    // File has been modified
    last_known_time = file_time;
    return 1;
}

/**
 * perform_proof_of_work
 * 
 * Performs the mining proof-of-work algorithm:
 * - Generates hashes with increasing nonce
 * - Checks for required number of leading zeros
 * - Can be interrupted by chain updates
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
    char zeros[DIFFICULTY + 1];
    memset(zeros, '0', DIFFICULTY);
    zeros[DIFFICULTY] = '\0';

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
        
        snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%u%ld",
                tx->sender, tx->recipient, tx->amount, tx->fee,
                tx->prev_hash, nonce, tx->timestamp);
        generate_hash(data, strlen(data), tx->data_hash);
        tx->data_hash[sizeof(tx->data_hash) - 1] = '\0';
        
        nonce++;
    } while (memcmp(tx->data_hash, zeros, DIFFICULTY) != 0);

    printf("\n\nBlock mined!\n");
    printf("Hash    : %s\n", tx->data_hash);
    
    return 1;
}
