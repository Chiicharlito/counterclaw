# CounterClaw — AI Agent Guardian
# Makefile for building, testing, and installing

BINARY_NAME := counterclaw
INSTALL_DIR := /usr/local/bin
PLIST_LABEL := io.counterclaw.daemon
PLIST_SRC := resources/$(PLIST_LABEL).plist
PLIST_DST := $(HOME)/Library/LaunchAgents/$(PLIST_LABEL).plist

.PHONY: help build test lint check install uninstall clean

## help: Show available targets
help:
	@echo "CounterClaw — Available targets:"
	@echo ""
	@echo "  make build      Build release binary"
	@echo "  make test       Run all tests"
	@echo "  make lint       Check formatting + clippy"
	@echo "  make check      Build + test + lint (full CI)"
	@echo "  make install    Install binary + plist + init config"
	@echo "  make uninstall  Unload daemon + remove binary + plist"
	@echo "  make clean      Remove build artifacts"
	@echo ""

## build: Build the release binary
build:
	cargo build --release

## test: Run all tests
test:
	cargo test

## lint: Check formatting and run clippy
lint:
	cargo fmt --check
	cargo clippy -- -D warnings

## check: Full CI pipeline (build + test + lint)
check: lint build test

## install: Install counterclaw on this machine
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp target/release/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installing launchd plist..."
	mkdir -p $(HOME)/Library/LaunchAgents
	cp $(PLIST_SRC) $(PLIST_DST)
	@echo "Initializing config..."
	$(INSTALL_DIR)/$(BINARY_NAME) config init
	@echo ""
	@echo "Done! Run 'counterclaw daemon start' to start the daemon."

## uninstall: Remove counterclaw from this machine
uninstall:
	@echo "Unloading daemon..."
	-launchctl unload $(PLIST_DST) 2>/dev/null
	@echo "Removing plist..."
	-rm -f $(PLIST_DST)
	@echo "Removing binary..."
	-rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Done. Config at ~/.counterclaw/ was preserved."

## clean: Remove build artifacts
clean:
	cargo clean
