# CounterClaw — AI Agent Guardian
# Makefile for building, testing, and installing

BINARY_NAME := counterclaw
INSTALL_DIR := /usr/local/bin
PLIST_LABEL := io.counterclaw.daemon
PLIST_SRC := resources/$(PLIST_LABEL).plist
PLIST_DST := $(HOME)/Library/LaunchAgents/$(PLIST_LABEL).plist

.PHONY: help build test lint check install uninstall clean install-daemon uninstall-daemon

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

## install-daemon: Install as root LaunchDaemon (requires sudo)
install-daemon: build
	@echo "Installing $(BINARY_NAME) as LaunchDaemon (requires root)..."
	sudo mkdir -p /etc/counterclaw /var/log/counterclaw
	sudo cp target/release/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chown root:wheel $(INSTALL_DIR)/$(BINARY_NAME)
	sudo chmod 755 $(INSTALL_DIR)/$(BINARY_NAME)
	sudo cp $(PLIST_SRC) /Library/LaunchDaemons/$(PLIST_LABEL).plist
	sudo chown root:wheel /Library/LaunchDaemons/$(PLIST_LABEL).plist
	sudo chmod 644 /Library/LaunchDaemons/$(PLIST_LABEL).plist
	sudo $(INSTALL_DIR)/$(BINARY_NAME) config init
	sudo chown -R root:wheel /etc/counterclaw
	sudo chmod 700 /etc/counterclaw
	sudo chmod 600 /etc/counterclaw/config.yaml
	sudo chown root:wheel /var/log/counterclaw
	sudo chmod 700 /var/log/counterclaw
	@echo ""
	@echo "Done! Run 'sudo launchctl load /Library/LaunchDaemons/$(PLIST_LABEL).plist' to start."

## uninstall-daemon: Remove root LaunchDaemon
uninstall-daemon:
	@echo "Unloading daemon..."
	-sudo launchctl unload /Library/LaunchDaemons/$(PLIST_LABEL).plist 2>/dev/null
	@echo "Removing plist..."
	-sudo rm -f /Library/LaunchDaemons/$(PLIST_LABEL).plist
	@echo "Removing binary..."
	-sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Done. Config at /etc/counterclaw/ was preserved."

## clean: Remove build artifacts
clean:
	cargo clean
