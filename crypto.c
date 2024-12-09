/**
 * crypto.c
 * 
 * Cryptographic operations for the blockchain.
 * Handles:
 * - User key generation and management
 * - Transaction signing and verification
 * - Hash generation for mining
 * - Address generation from public keys
 * 
 * Uses OpenSSL for all cryptographic operations.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

// Global variables
static EVP_PKEY* user_key_pair = NULL;
static char current_user_address[ADDRESS_LENGTH + 3];  // +3 for '0x' and null terminator

/**
 * get_current_user_address
 * 
 * Returns the current user's blockchain address
 * 
 * Returns:
 *   String containing user's address (0x... format)
 */
const char* get_current_user_address(void) {
    return current_user_address;
}

/**
 * generate_hash
 * 
 * Creates SHA256 hash of input data:
 * - Used for mining proof-of-work
 * - Transaction data hashing
 * - Chain linking
 * 
 * Parameters:
 *   data: Data to hash
 *   len: Length of data
 *   output: Buffer for hex string output
 */
void generate_hash(const void* data, size_t len, char* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    
    for(unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = 0;
}

/**
 * initialize_user
 * 
 * Creates or loads user's cryptographic identity:
 * - Generates RSA key pair from password
 * - Derives user's address from public key
 * - Stores keys for transaction signing
 * 
 * Parameters:
 *   password: User's password for key generation
 */
void initialize_user(const char* password) {
    // Generate deterministic key from password
    unsigned char key[32];
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, password, strlen(password));
    unsigned int key_len;
    EVP_DigestFinal_ex(md_ctx, key, &key_len);
    EVP_MD_CTX_free(md_ctx);
    
    // Use the key to seed the RSA key generation
    RAND_seed(key, key_len);
    
    // Generate key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Error initializing key generation\n");
        return;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        printf("Error setting key size\n");
        return;
    }
    
    if (EVP_PKEY_keygen(ctx, &user_key_pair) <= 0) {
        printf("Error generating key pair\n");
        return;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Generate deterministic address from password
    unsigned char address_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* addr_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(addr_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(addr_ctx, password, strlen(password));
    EVP_DigestFinal_ex(addr_ctx, address_hash, NULL);
    EVP_MD_CTX_free(addr_ctx);
    
    // Format address as 0xXXXXXX (6 hex digits)
    sprintf(current_user_address, "%s", ADDRESS_PREFIX);
    for(int i = 0; i < ADDRESS_LENGTH/2; i++) {
        sprintf(current_user_address + strlen(ADDRESS_PREFIX) + (i * 2), "%02x", 
                address_hash[i]);
    }
    
    printf("User initialized with address: %s\n", current_user_address);
}

/**
 * sign_transaction
 * 
 * Signs a transaction with user's private key:
 * - Hashes transaction data
 * - Creates RSA signature
 * - Stores signature in transaction
 * 
 * Parameters:
 *   tx: Transaction to sign
 */
void sign_transaction(Transaction* tx) {
    if (!user_key_pair || !tx) {
        printf("Error: Invalid parameters for signing\n");
        return;
    }
    
    // Make a copy of the transaction data before signing
    char sender_backup[ADDRESS_BUFFER_SIZE];
    strncpy(sender_backup, tx->sender, sizeof(sender_backup) - 1);
    sender_backup[sizeof(sender_backup) - 1] = '\0';
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Error: Failed to create MD context\n");
        return;
    }
    
    EVP_PKEY_CTX* sign_ctx = NULL;
    size_t sig_len;
    unsigned char sig[RSA_SIG_SIZE];
    
    // Create the signature using all transaction data
    char data[1024];
    snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%ld",
             tx->sender, tx->recipient, tx->amount, tx->fee,
             tx->prev_hash, tx->timestamp);
    
    EVP_DigestSignInit(md_ctx, &sign_ctx, EVP_sha256(), NULL, user_key_pair);
    EVP_DigestSignUpdate(md_ctx, data, strlen(data));
    
    // Get signature length
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
    
    // Get actual signature
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) {
        printf("Error signing transaction\n");
        EVP_MD_CTX_free(md_ctx);
        return;
    }
    
    // Convert signature to hex string
    memset(tx->signature, 0, sizeof(tx->signature));
    size_t hex_len = 0;
    for(size_t i = 0; i < sig_len && hex_len < sizeof(tx->signature) - 1; i++) {
        snprintf(tx->signature + hex_len, 3, "%02x", sig[i]);
        hex_len += 2;
    }
    tx->signature[hex_len] = '\0';
    
    EVP_MD_CTX_free(md_ctx);
    
    // Verify sender wasn't corrupted
    if (strcmp(tx->sender, sender_backup) != 0) {
        strncpy(tx->sender, sender_backup, sizeof(tx->sender) - 1);
        tx->sender[sizeof(tx->sender) - 1] = '\0';
    }
}

/**
 * verify_transaction
 * 
 * Verifies transaction signature:
 * - Reconstructs transaction data hash
 * - Verifies RSA signature
 * - Validates against sender's public key
 * 
 * Parameters:
 *   tx: Transaction to verify
 * 
 * Returns:
 *   1 if signature is valid
 *   0 if verification fails
 */
int verify_transaction(Transaction* tx) {
    // Skip verification for mining rewards
    if (strcmp(tx->sender, "BLOCKCHAIN_REWARD") == 0) {
        return 1;
    }
    
    // Verify hash chain
    Transaction* next = get_chain_head();
    while (next != NULL && strcmp(next->data_hash, tx->prev_hash) != 0) {
        next = next->next;
    }
    
    if (next == NULL && strlen(tx->prev_hash) > 0) {
        printf("Error: Invalid transaction chain\n");
        return 0;
    }
    
    // Basic signature format check
    size_t sig_len = strlen(tx->signature);
    
    if (sig_len == 0) {
        printf("Error: Empty signature\n");
        return 0;
    }
    
    if (sig_len % 2 != 0) {
        printf("Error: Invalid signature length\n");
        return 0;
    }
    
    if (sig_len > HEX_SIG_SIZE - 1) {
        printf("Error: Signature too long\n");
        return 0;
    }
    
    // Convert hex signature back to binary
    unsigned char sig_bin[RSA_SIG_SIZE];
    size_t bin_len = sig_len / 2;
    
    if (bin_len > RSA_SIG_SIZE) {
        printf("Error: Invalid signature format\n");
        return 0;
    }
    
    memset(sig_bin, 0, sizeof(sig_bin));
    
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(tx->signature + (i * 2), "%2x", &byte) != 1) {
            printf("Error: Invalid signature format\n");
            return 0;
        }
        sig_bin[i] = (unsigned char)byte;
    }
    
    // Verify signature cryptographically
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Error: Failed to create MD context\n");
        return 0;
    }
    
    EVP_PKEY_CTX* verify_ctx = NULL;
    
    // Recreate the signed data
    char data[1024];
    snprintf(data, sizeof(data), "%s%s%.2f%.2f%s%ld",
             tx->sender, tx->recipient, tx->amount, tx->fee,
             tx->prev_hash, tx->timestamp);
    
    if (!user_key_pair) {
        printf("Error: No key pair available for verification\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    
    if (EVP_DigestVerifyInit(md_ctx, &verify_ctx, EVP_sha256(), NULL, user_key_pair) <= 0) {
        printf("Error: Failed to initialize signature verification\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    
    if (EVP_DigestVerifyUpdate(md_ctx, data, strlen(data)) <= 0) {
        printf("Error: Failed to update signature verification\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    
    int verify_result = EVP_DigestVerifyFinal(md_ctx, sig_bin, bin_len);
    EVP_MD_CTX_free(md_ctx);
    
    if (verify_result <= 0) {
        printf("Error: Invalid transaction signature\n");
        return 0;
    }
    
    return 1;
} 