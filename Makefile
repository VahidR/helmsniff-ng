BINARY   := helmsniff-ng
BIN_DIR  := bin
DIST_DIR := dist
CARGO    := cargo
MUSL     := x86_64-unknown-linux-musl

.PHONY: all build clean fmt fmt-check lint test run dist dist-linux

all: build

## Compile an optimized binary into bin/
build:
	$(CARGO) build --release
	@mkdir -p $(BIN_DIR)
	cp target/release/$(BINARY) $(BIN_DIR)/$(BINARY)

clean:
	$(CARGO) clean
	rm -rf $(BIN_DIR) $(DIST_DIR)

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

## clippy with warnings as errors (same gate as CI)
lint: fmt-check
	$(CARGO) clippy --all-targets -- -D warnings

test:
	$(CARGO) test

run: build
	@echo "Usage: $(BIN_DIR)/$(BINARY) --root <rendered_dir|-> --out <path|-> [--format csv|json]"
	@echo "  Pipe mode: helm template mychart | $(BIN_DIR)/$(BINARY) --root - --out - --format json"

# --- Release archive (mirrors the GitHub Actions release matrix, Linux only) ---
# Windows and macOS archives are produced by CI on native runners.
dist: dist-linux

## Fully static Linux binary (needs: rustup target add $(MUSL))
dist-linux:
	@mkdir -p $(DIST_DIR)
	$(CARGO) build --release --target $(MUSL)
	cp target/$(MUSL)/release/$(BINARY) $(DIST_DIR)/$(BINARY)
	tar czf $(DIST_DIR)/$(BINARY)-linux-amd64.tar.gz -C $(DIST_DIR) $(BINARY) -C $(CURDIR) README.md LICENSE
	rm -f $(DIST_DIR)/$(BINARY)
