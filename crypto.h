/**
 * crypto.h
 * 
 * Cryptographic operations interface for the blockchain.
 * Provides:
 * - Hash generation
 * - Digital signatures
 * - Key management
 * - Address generation
 * 
 * Uses OpenSSL for cryptographic operations.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/rsa.h>
#include "blockchain.h"

void initialize_user(const char* password);
void generate_hash(const void* data, size_t len, char* output);
int verify_transaction(Transaction* tx);
void sign_transaction(Transaction* tx);
const char* get_current_user_address(void);

#endif 