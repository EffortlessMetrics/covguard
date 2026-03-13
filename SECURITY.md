# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ |
| < 0.1.0 | ❌ |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please report it responsibly.

### How to Report

**Do NOT** open a public issue for security vulnerabilities.

Instead, please:

1. Email: security@effortlessmetrics.com
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Time

- Initial response: within 48 hours
- Status update: within 7 days
- Resolution timeline: depends on severity

## Security Best Practices

When using covguard:

1. **Diff files**: Don't include sensitive data in diff files
2. **Coverage files**: Review LCOV files before processing
3. **Output files**: Be cautious with report output in CI logs
4. **Configuration**: Don't commit secrets in covguard.toml

## Scope

This policy applies to:
- The covguard CLI tool
- All crates in the workspace
- Documentation and examples

## Attribution

This security policy is based on the [GitHub Security Policy](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities).
