CC = gcc
# Add OpenSSL paths for macOS (Homebrew)
OPENSSL_PREFIX = $(shell brew --prefix openssl)
CFLAGS = -Wall -Wextra -I. -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib
LIBS = -lssl -lcrypto -lm

# Directory structure
BIN_DIR = bin
BUILD_DIR = build
SRC_DIR = .

# Core source files (excluding main.c)
CORE_SRCS = blockchain.c blockchain_utils.c crypto.c
CORE_OBJS = $(CORE_SRCS:%.c=$(BUILD_DIR)/%.o)

# Main program
MAIN_SRCS = main.c $(CORE_SRCS)
MAIN_OBJS = $(MAIN_SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = $(BIN_DIR)/axchain

# Test files
TEST_SRCS = test_main.c tests.c $(CORE_SRCS)
TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_TARGET = $(BIN_DIR)/test_axchain

.PHONY: all clean directories test

all: directories $(TARGET)

test: directories $(TEST_TARGET)
	@echo "Running tests..."
	@./$(TEST_TARGET)

directories:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BUILD_DIR)

$(TARGET): $(MAIN_OBJS)
	@echo "Linking $(TARGET)"
	@$(CC) $(MAIN_OBJS) $(LDFLAGS) $(LIBS) -o $(TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	@echo "Building tests..."
	@$(CC) $(TEST_OBJS) $(LDFLAGS) $(LIBS) -o $(TEST_TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Done!"
