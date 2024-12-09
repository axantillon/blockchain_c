# AXChain

A blockchain implementation in C using OpenSSL for cryptographic operations.

## Project Structure

- `blockchain.c/h` - Core blockchain implementation
- `crypto.c/h` - Cryptographic utilities using OpenSSL
- `main.c` - Main program entry point
- `tests.c` - Test suite
- `test_main.c` - Test runner

## Prerequisites

- GCC compiler
- OpenSSL development libraries
- Homebrew (for macOS users)

### Installing OpenSSL on macOS

brew install openssl

## Features

- Transaction-based blockchain implementation
- Proof-of-work mining system with configurable difficulty
- Secure cryptographic operations using OpenSSL
- Deterministic address generation
- Transaction validation and verification
- Chain persistence and state management
- Real-time chain monitoring for updates
- Comprehensive test suite

## Building the Project

1. Build the main program:

`make clean && make`

The executable will be created at `bin/axchain`

## Running Tests

To build and run the test suite:

`make test`

The test suite verifies:
- Mining operations
- Transaction validation
- Chain integrity
- Account balance tracking
- Cryptographic functions

## Usage

After building, run the program:

`./bin/axchain`

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

## Project Architecture

- Transaction Structure: Linked list of cryptographically secured transactions
- Chain Validation: Comprehensive integrity checks for transactions and chain state
- Persistence: Binary file storage with version control and checksums
- User Interface: Terminal-based interface with real-time updates
- Multi-instance Support: Handles concurrent access through file-based synchronization

## Cleaning Build Files

To clean all compiled files:

`make clean`

## Development

The project uses:
- C17 standard
- OpenSSL for cryptographic operations
- Modular architecture with separate crypto and blockchain components
- Comprehensive error handling and validation

## File Structure

.
├── Makefile              # Build configuration
├── blockchain.c/h        # Core blockchain implementation
├── crypto.c/h           # Cryptographic operations
├── main.c               # Program entry point
├── tests.c              # Test implementations
├── test_main.c          # Test runner
└── bin/
    └── axchain.dat      # Chain state persistence

## Author

Andres Antillon