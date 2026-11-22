# Project task runner — run `just --list` for available recipes

# Run all tests
test:
    cargo test --locked --no-fail-fast

# Run clippy lints
lint:
    cargo clippy --locked --all-targets -- -D warnings

# Check formatting
fmt:
    cargo fmt --all -- --check

# Fix formatting
fmt-fix:
    cargo fmt --all

# Run cargo-deny checks (licenses, advisories, bans, sources)
deny:
    cargo deny check

# Run all checks (lint, fmt, test, deny)
check-all: lint fmt test deny
