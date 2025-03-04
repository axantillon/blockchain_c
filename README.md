# AXChain

A blockchain implementation in C using OpenSSL for cryptographic operations.

## Project Structure

The project has been refactored for improved readability and educational value:

- `blockchain.h/c` - Core blockchain implementation
- `blockchain_utils.h/c` - Utility functions for blockchain operations
- `crypto.h/c` - Cryptographic utilities using OpenSSL
- `main.c` - Main program entry point
- `tests.c` - Test suite
- `test_main.c` - Test runner

## Prerequisites

- GCC compiler
- OpenSSL development libraries
- Homebrew (for macOS users)

### Installing OpenSSL on macOS

```
brew install openssl
```

## Features

- Transaction-based blockchain implementation
- Proof-of-work mining system with configurable difficulty
- Secure cryptographic operations using OpenSSL
- Deterministic address generation
- Transaction validation and verification
- Chain persistence and state management
- Real-time chain monitoring for updates
- Comprehensive test suite

### Blockchain Statistics

AXChain provides several useful statistics about the blockchain:

- **Total Transactions**: Counts all transactions in the blockchain
- **Mining Rewards**: Tracks the number of mining rewards issued
- **Active Accounts**: Shows the number of accounts that have sent or received tokens
- **Total Supply**: Calculates the total amount of AX tokens in circulation
- **Fees Burned**: Tracks the total amount of transaction fees that have been burned
- **Chain Integrity**: Verifies the integrity of the entire blockchain

These statistics provide insight into the blockchain's state and growth over time.

## Building the Project

1. Build the main program:

```
make clean && make
```

The executable will be created at `bin/axchain`

## Running Tests

To build and run the test suite:

```
make test
```

The test suite verifies:

- Mining operations
- Transaction validation
- Chain integrity
- Account balance tracking
- Cryptographic functions

## Usage

After building, run the program:

```
./bin/axchain
```

### Getting Started Guide

Follow these steps to quickly get started with AXChain:

1. **Create Your Wallet**:
   When you first run AXChain, you'll be prompted to enter a password:

   ```
   Please enter your password: mySecurePassword
   ```

   This password is used to generate your cryptographic identity and wallet address.

2. **Mine Your First Coins**:
   Select option `2` from the main menu to mine your first 50 AX tokens.
   The mining process will begin, and you'll receive a reward when complete.

3. **View Your Balance**:
   Your balance is displayed at the top of the main menu screen.
   You can also see all transactions by selecting option `3`.

4. **Send Tokens**:
   To send tokens to another address:

   - Select option `1` from the main menu
   - Enter the recipient's address (e.g., `0xabcdef`)
   - Enter the amount to send
   - The transaction will be processed and mined automatically

5. **Monitor the Blockchain**:
   AXChain automatically saves and loads the blockchain state.
   Multiple instances of the program can run simultaneously, with changes synced between them.

### Main Features:

1. Send AX Tokens: Transfer tokens to other addresses
2. Mine Blocks: Earn rewards through proof-of-work mining
3. View Chain: Inspect the complete blockchain history
4. Auto-save: Chain state is automatically persisted

### System Constants:

- Mining Reward: 50.0 AX
- Transaction Fee: 1.0 AX (burned)
- Mining Difficulty: 5 leading zeros
- Address Format: 0x + 6 hex characters

## CLI Interface Examples

Below are examples of the CLI interface screens you'll encounter when using AXChain:

### Main Menu and Account Status

When you start the application, you'll see your account information and the main menu:

```
        AXCHAIN STATUS
═══════════════════════════════════════

NETWORK STATISTICS
• Total Transactions : 12
• Active Accounts    : 3
• Total Supply       : 350.00    AX

YOUR WALLET
• Address           : 0x8a2e3f
• Balance           : 152.00    AX

═══════════════ MENU ═══════════════
1. 💸 Send AX
2. ⛏  Mine Reward
3. 📋 View Chain
4. 🚪 Exit
═══════════════════════════════════

Choice:
```

### Mining Screen

When mining a new block, you'll see the mining progress:

```
Mining now, please wait...

Finding hash with 5 leading zeros...

═══════════════════════════════════════
Hashes tried: 253716

Block mined!
Hash    : 00000a8d7c2351f7a932de853a4f53e13df901bc81c9f27f61964f61ffb24692

Successfully mined 50.00 AX!
```

### Transaction History View

When viewing the blockchain, you'll see all transactions:

```
═══════════════════════════════════════════════
             TRANSACTION HISTORY
═══════════════════════════════════════════════

Transaction #0
─────────────────────────────────────────────
⛏️  Mining Reward
Time     : 2023-09-08 14:32:18
From     : System Mining Reward
To       : 0x8a2e3f
Amount   : 50.00 AX

Hash     : 00000a8d7c2351f7a932de853a4f53e13df901bc81c9f27f61964f61ffb24692
Prev Hash: 0000000000000000000000000000000000000000000000000000000000000000

Transaction #1
─────────────────────────────────────────────
💸 Transfer
Time     : 2023-09-08 14:35:42
From     : 0x8a2e3f
To       : 0xabcdef
Amount   : 10.00 AX (+ 1.00 AX fee)

Hash     : 00000f91a8c25e7b2e144b418e2c6953f87f48ed01c3b6a9c217930c61595cb1
Prev Hash: 00000a8d7c2351f7a932de853a4f53e13df901bc81c9f27f61964f61ffb24692

═══════════════════════════════════════════════
Total Transactions: 2
Total Fees Burned: 1.00 AX
═══════════════════════════════════════════════
```

### Sending AX Tokens

When sending tokens, you'll see the transaction entry screen:

```
Enter recipient address: 0xabcdef
Enter amount in AX: 25.5

Debug: Validating transaction
  Sender: '0x8a2e3f' (len: 8)
  Recipient: '0xabcdef' (len: 8)

Finding hash with 5 leading zeros...

═══════════════════════════════════════
Hashes tried: 187293

Block mined!
Hash    : 00000d4e7b1c4521ae98f3e95a75321b6c4a9e54a3fc98b7e59ec4bf17a58d29

Transaction added successfully! Fee of 1.00 AX burned
```

## Project Architecture

### Modular Design

The project has been refactored into a modular architecture to improve readability and maintainability:

- **Core Blockchain Module**: Handles the main blockchain operations
- **Utilities Module**: Provides common functions to reduce code duplication
- **Cryptographic Module**: Manages all security and cryptographic operations
- **Testing Module**: Comprehensive test suite for verification

### Key Components

- **Transaction Structure**: Linked list of cryptographically secured transactions
- **Chain Validation**: Comprehensive integrity checks for transactions and chain state
- **Persistence**: Binary file storage with version control and checksums
- **User Interface**: Terminal-based interface with real-time updates
- **Multi-instance Support**: Handles concurrent access through file-based synchronization

## Educational Value

This project serves as an educational tool for understanding blockchain concepts:

1. **Blockchain Fundamentals**: Demonstrates the core concepts of blockchain technology
2. **Cryptographic Security**: Shows how cryptography secures transactions
3. **Proof-of-Work**: Implements the mining algorithm used by many cryptocurrencies
4. **Transaction Validation**: Illustrates how transactions are verified and processed
5. **Chain Integrity**: Demonstrates how blockchain maintains data integrity

### Blockchain Structure Diagram

The following diagram illustrates how transactions are linked together in the blockchain:

```
                      +---------------+                +---------------+                +---------------+
                      |  Transaction  |                |  Transaction  |                |  Transaction  |
                      |    (Block)    |                |    (Block)    |                |    (Block)    |
                      +---------------+                +---------------+                +---------------+
                      | Prev Hash: 0  |                | Prev Hash:    |                | Prev Hash:    |
                      |               | <------------- | [Hash of T1]  | <------------- | [Hash of T2]  |
                      | Data Hash: T1 |                | Data Hash: T2 |                | Data Hash: T3 |
                      | Sender: REWARD|                | Sender: 0x123 |                | Sender: 0x456 |
                      | Recipient: 0x |                | Recipient: 0x |                | Recipient: 0x |
                      | Amount: 50.0  |                | Amount: 10.0  |                | Amount: 5.0   |
                      +---------------+                +---------------+                +---------------+
                             |                                |                                |
                             v                                v                                v
                      +---------------+                +---------------+                +---------------+
                      |    Mining     |                | Transaction   |                | Transaction   |
                      |   Operation   |                |   Operation   |                |   Operation   |
                      +---------------+                +---------------+                +---------------+
                      | Find hash with|                | 1. Validate   |                | 1. Validate   |
                      | 5 leading     |                | 2. Sign       |                | 2. Sign       |
                      | zeros         |                | 3. Mine       |                | 3. Mine       |
                      +---------------+                +---------------+                +---------------+
```

Each transaction (block) contains:

- A reference to the previous block's hash (chain linking)
- A hash of its own data (for verification)
- Transaction details (sender, recipient, amount)
- Proof-of-work (mining difficulty)

This linked structure ensures that any modification to a past transaction would invalidate all subsequent transactions, providing the immutability property essential to blockchain technology.

## Cleaning Build Files

To clean all compiled files:

```
make clean
```

## Development

The project uses:

- C17 standard
- OpenSSL for cryptographic operations
- Modular architecture with separate crypto and blockchain components
- Comprehensive error handling and validation

## File Structure

```
.
├── Makefile              # Build configuration
├── blockchain.h/c        # Core blockchain implementation
├── blockchain_utils.h/c  # Utility functions for blockchain operations
├── crypto.h/c            # Cryptographic operations
├── main.c                # Program entry point
├── tests.c               # Test implementations
├── test_main.c           # Test runner
└── bin/
    └── axchain.dat       # Chain state persistence
```

## Author

Andres Antillon
