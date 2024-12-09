/**
 * main.c
 * 
 * Main entry point for the AxChain application.
 * Provides the user interface and command processing.
 * Handles:
 * - User authentication
 * - Menu display and interaction
 * - Chain file monitoring
 * - Command execution (mining, transactions, viewing)
 */

#include <stdio.h>
#include <stdlib.h>
#include "blockchain.h"
#include "crypto.h"

void print_account_info(void) {
    const char* address = get_current_user_address();
    double balance = get_account_balance(address);
    size_t total_txns = get_transaction_count();
    size_t active_accounts = get_active_accounts();
    double total_supply = get_total_supply();
    
    printf("\n        AXCHAIN STATUS\n");
    printf("═══════════════════════════════════════\n\n");
    printf("NETWORK STATISTICS\n");
    printf("• Total Transactions : %zu\n", total_txns);
    printf("• Active Accounts    : %zu\n", active_accounts);
    printf("• Total Supply       : %.2f    AX\n", total_supply);
    printf("\nYOUR WALLET\n");
    printf("• Address           : %s\n", address);
    printf("• Balance           : %.2f    AX\n", balance);
}

int main(void) {
    char password[100];
    char choice;
    char recipient[65];
    double amount;

    printf("\n        Welcome to AxChain!\n");
    printf("════════════════════════════════\n\n");
    
    printf("Please enter your password: ");
    scanf("%s", password);
    initialize_user(password);
    
    // Load existing chain at startup
    if (!load_chain()) {
        printf("\nStarting with a fresh blockchain...\n");
    }

    while (1) {
        // Check for chain updates
        if (has_chain_changed()) {
            printf("\nChain updated by another instance, reloading...\n");
            if (!load_chain()) {
                printf("Warning: Failed to reload chain\n");
            }
        }

        print_account_info();
        
        printf("\n═══════════════ MENU ═══════════════\n");
        printf("1. 💸 Send AX\n");
        printf("2. ⛏  Mine Reward\n");
        printf("3. 📋 View Chain\n");
        printf("4. 🚪 Exit\n");
        printf("═══════════════════════════════════\n");
        printf("\nChoice: ");
        scanf(" %c", &choice);

        switch (choice) {
            case '1':
                printf("\nEnter recipient address: ");
                scanf("%s", recipient);
                printf("Enter amount in AX: ");
                scanf("%lf", &amount);
                
                if (add_transaction(recipient, amount)) {
                    if (!save_chain()) {
                        printf("Warning: Failed to save blockchain\n");
                    }
                }
                break;
                
            case '2':
                mine_reward();
                if (!save_chain()) {
                    printf("Warning: Failed to save blockchain\n");
                }
                break;
                
            case '3':
                print_chain();
                break;
                
            case '4':
                printf("\nSaving AxChain...\n");
                if (!save_chain()) {
                    printf("Warning: Failed to save blockchain\n");
                }
                cleanup_chain();
                return 0;
                
            default:
                printf("\nInvalid choice\n");
        }
    }

    return 0;
}
