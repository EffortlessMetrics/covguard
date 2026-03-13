# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported |
| ------- | --------- |
| 0.x.x   | Yes       |
| < 0.1.0 | No        |

## Reporting a Vulnerability

We take the security of covguard seriously. If you believe you have found a security vulnerability, please report it to us.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's private vulnerability reporting feature:

1. Go to the [Security Advisories](https://github.com/EffortlessMetrics/covguard/security/advisories) page
2. Click "Report a vulnerability"
3. Fill out the form with details about the vulnerability

Alternatively, you can email us at: security@effortlessmetrics.com

### What to Include

Please include the following information:

- **Description**: A clear description of the vulnerability
- **Steps to reproduce**: Detailed steps to reproduce the issue
- **Impact**: What an attacker could accomplish by exploiting this
- **Proof of concept**: If available, a minimal example demonstrating the issue
- **Suggested fix**: If you have ideas for how to fix the issue

### Response Timeline

- **Initial response**: Within 48 hours
- **Triage**: Within 5 business days
- **Fix development**: Depends on severity and complexity
- **Disclosure**: After fix is released

### Disclosure Policy

- We follow responsible disclosure practices
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We request that you do not disclose the vulnerability publicly until we have released a fix

## Security Best Practices

When using covguard:

### Input Validation

covguard processes diff files and LCOV reports. While we strive to handle all input safely:

- Only process diff files from trusted sources
- Be cautious with LCOV files from untrusted sources
- Review any code that uses the `--diff-file` or `--lcov` flags with user-provided input

### CI/CD Integration

When integrating covguard into your CI/CD pipeline:

- Use pinned versions of covguard in your workflows
- Review workflow permissions carefully
- Store sensitive credentials (like GitHub tokens) securely using your CI provider's secrets management

### Configuration

- Review your `covguard.toml` configuration before committing
- Be cautious with ignore directives that might mask real coverage issues
- Use appropriate thresholds for your project's security requirements

## Security Features

covguard includes several security-conscious design decisions:

### Memory Safety

- Written in Rust, providing memory safety guarantees
- No unsafe code in the core parsing logic
- Fuzz testing for diff and LCOV parsers

### Input Handling

- All parsers are designed to handle malformed input gracefully
- No arbitrary code execution from input files
- Bounded resource consumption for large inputs

### Output Safety

- JSON output is properly escaped
- No shell injection vectors in generated output
- SARIF output follows the OASIS standard

## Known Security Considerations

### Denial of Service

Large diff files or LCOV reports could consume significant memory or CPU. We recommend:

- Setting appropriate resource limits in CI environments
- Validating file sizes before processing untrusted inputs

### Path Traversal

covguard normalizes paths to prevent directory traversal attacks. All paths in output are repo-relative.

## Security Updates

Security updates will be announced via:

- [GitHub Security Advisories](https://github.com/EffortlessMetrics/covguard/security/advisories)
- [GitHub Releases](https://github.com/EffortlessMetrics/covguard/releases)
- Changelog entries marked with `[security]`

## Contact

For security-related questions or concerns:

- **Security Advisories**: https://github.com/EffortlessMetrics/covguard/security/advisories
- **Email**: security@effortlessmetrics.com

Thank you for helping keep covguard and its users safe!
