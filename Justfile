# Run clippy on all targets and features, treating warnings as errors
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

fmt:
    cargo fmt