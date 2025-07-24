# Run clippy on all targets and features, treating warnings as errors
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

fmt:
    cargo fmt

test:
    cargo test --all-targets --all-features
