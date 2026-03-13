# Contributing to covguard

Thank you for your interest in contributing to covguard! This document provides guidelines and expectations for contributions.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## How to Contribute

### Reporting Issues

1. Check if the issue has already been reported
2. Use a clear, descriptive title
3. Include steps to reproduce
4. Include expected vs actual behavior

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests: `cargo test --all`
5. Check formatting: `cargo fmt --check`
6. Check clippy: `cargo clippy --all-targets`
7. Push and create a PR

### Development Setup

```bash
git clone https://github.com/EffortlessMetrics/covguard.git
cd covguard
cargo build
cargo test --all
```

## Coding Standards

### Formatting
- Use `cargo fmt` before committing
- Maximum line length: 100 characters

### Linting
- Address all clippy warnings
- Use `cargo clippy --all-targets` to check

### Testing
- Unit tests for new functionality
- Integration tests for CLI changes
- BDD tests for user-facing features

### Documentation
- Update doc comments for public APIs
- Update README if behavior changes
- Add ADRs for architectural decisions

## Commit Messages

Format: `<type>: <description>`

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Testing
- `refactor`: Code refactoring
- `chore`: Maintenance

Example: `feat: add support for Jacoco coverage format`

## Questions?

Open an issue or start a discussion on GitHub.
