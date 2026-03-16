# covguard GitLab CI Templates

This directory contains reusable GitLab CI/CD templates for integrating [covguard](https://github.com/EffortlessMetrics/covguard) into your pipelines. covguard is a diff-scoped coverage gate that ensures new code changes are properly covered by tests.

## Quick Start

### Basic Usage

Add the following to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/EffortlessMetrics/covguard/main/templates/gitlab/covguard-base.yml'

variables:
  COVERAGE_FILE: "coverage/lcov.info"

covguard:mr:
  extends: .covguard_base
```

### Language-Specific Templates

#### Rust

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/EffortlessMetrics/covguard/main/templates/gitlab/covguard-rust.yml'

covguard:rust:
  extends: .covguard_rust
```

#### Python

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/EffortlessMetrics/covguard/main/templates/gitlab/covguard-python.yml'

covguard:python:
  extends: .covguard_python
  variables:
    COVERAGE_SOURCE: "src"
    PYTEST_ARGS: "--ignore=tests/integration"
```

#### Java

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/EffortlessMetrics/covguard/main/templates/gitlab/covguard-java.yml'

covguard:java:
  extends: .covguard_java
  variables:
    JACOCO_REPORT_PATH: "target/site/jacoco/jacoco.xml"
```

## Templates

### [`covguard-base.yml`](./covguard-base.yml)

The base template provides the core job definition for running covguard. Use this when:
- You already have coverage generation set up
- You need maximum flexibility
- You're using a language not covered by the specific templates

### [`covguard-rust.yml`](./covguard-rust.yml)

Complete setup for Rust projects using `cargo-llvm-cov`:
- Installs `cargo-llvm-cov` and `covguard`
- Generates LCOV coverage report
- Runs covguard on merge requests and main branch

### [`covguard-python.yml`](./covguard-python.yml)

Complete setup for Python projects using `coverage.py`:
- Installs `coverage`, `pytest`, and `pytest-cov`
- Generates LCOV coverage report
- Supports poetry and tox configurations

### [`covguard-java.yml`](./covguard-java.yml)

Complete setup for Java projects using JaCoCo:
- Works with Maven and Gradle
- Supports multi-module projects
- Includes Spring Boot optimized configuration

## Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `COVGUARD_VERSION` | Version of covguard to use | `latest` |
| `COVERAGE_FILE` | Path to the coverage report file | Required for base template |
| `COVERAGE_FORMAT` | Format: `lcov`, `jacoco`, `coverage-py` | `lcov` |
| `FAIL_THRESHOLD` | Minimum coverage % to pass | `0` |
| `WARN_THRESHOLD` | Minimum coverage % to warn | `0` |
| `POST_MR_COMMENT` | Post MR comment with results | `true` |
| `FAIL_ON_UNCOVERED` | Fail if uncovered lines found | `true` |
| `BASE_REF` | Base ref for diff (auto-detected for MRs) | `$CI_MERGE_REQUEST_DIFF_BASE_SHA` |
| `HEAD_REF` | Head ref for diff | `$CI_COMMIT_SHA` |

### Language-Specific Variables

#### Rust

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_TOOLCHAIN` | Rust toolchain version | `stable` |
| `CARGO_LLVM_COV_VERSION` | cargo-llvm-cov version | `latest` |
| `EXTRA_TEST_ARGS` | Extra arguments for cargo test | `""` |

#### Python

| Variable | Description | Default |
|----------|-------------|---------|
| `PYTHON_VERSION` | Python version | `3.11` |
| `COVERAGE_SOURCE` | Source directories to measure | `.` |
| `PYTEST_ARGS` | Extra arguments for pytest | `""` |
| `REQUIREMENTS_FILE` | Path to requirements.txt | `requirements.txt` |

#### Java

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_VERSION` | Java version | `17` |
| `MAVEN_VERSION` | Maven version | `3.9` |
| `BUILD_TOOL` | Build tool: `maven` or `gradle` | `maven` |
| `JACOCO_REPORT_PATH` | Path to JaCoCo XML report | `target/site/jacoco/jacoco.xml` |
| `EXTRA_BUILD_ARGS` | Extra arguments for build | `""` |

## Examples

See the [`examples/`](./examples/) directory for complete pipeline examples:

- [`basic-usage.yml`](./examples/basic-usage.yml) - Minimal configuration
- [`with-threshold.yml`](./examples/with-threshold.yml) - Coverage thresholds
- [`full-pipeline.yml`](./examples/full-pipeline.yml) - Complete pipeline with stages

## Features

### Merge Request Comments

When `POST_MR_COMMENT: "true"`, covguard will post a comment on merge requests with:
- Coverage summary
- List of uncovered lines
- Pass/fail status

### Code Quality Reports

covguard generates GitLab Code Quality reports that appear in:
- Merge request widget
- Pipeline details
- Code Quality dashboard

### Coverage Visualization

The templates configure GitLab's coverage visualization features:
- Inline coverage indicators in merge request diffs
- Coverage percentage in pipeline badges
- Coverage trend graphs

### Exit Codes

- `0` - Pass (all changed lines are covered or threshold met)
- `2` - Policy fail (uncovered lines or threshold not met)
- `1` - Tool/runtime error (I/O, parse failure)

## Advanced Usage

### Custom Rules

Override the default rules to customize when covguard runs:

```yaml
covguard:custom:
  extends: .covguard_base
  rules:
    # Only run on MRs with specific labels
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      if: $CI_MERGE_REQUEST_LABELS =~ /needs-coverage/
    # Always run on release branches
    - if: $CI_COMMIT_BRANCH =~ /^release\//
```

### Multiple Coverage Reports

For monorepos or multi-language projects:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/EffortlessMetrics/covguard/main/templates/gitlab/covguard-base.yml'

covguard:backend:
  extends: .covguard_base
  variables:
    COVERAGE_FILE: "backend/coverage/lcov.info"
    BASE_REF: "${CI_MERGE_REQUEST_DIFF_BASE_SHA}"
    HEAD_REF: "${CI_COMMIT_SHA}"

covguard:frontend:
  extends: .covguard_base
  variables:
    COVERAGE_FILE: "frontend/coverage/lcov.info"
    COVERAGE_FORMAT: "lcov"
```

### Conditional Failure

Allow coverage failures on feature branches but not on main:

```yaml
covguard:mr:
  extends: .covguard_base
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: on_success
  allow_failure:
    exit_codes:
      - 2

covguard:main:
  extends: .covguard_base
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  allow_failure: false
```

### Using with GitLab Pages

Publish coverage reports to GitLab Pages:

```yaml
pages:
  stage: deploy
  needs:
    - covguard:mr
  script:
    - mkdir -p public/coverage
    - cp -r htmlcov/ public/coverage/
  artifacts:
    paths:
      - public
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## Troubleshooting

### Coverage File Not Found

Ensure your coverage file path is correct relative to the project root:

```yaml
variables:
  COVERAGE_FILE: "path/to/coverage/lcov.info"
```

### MR Comments Not Posting

1. Ensure `CI_JOB_TOKEN` has access to post notes
2. Check that `POST_MR_COMMENT: "true"`
3. Verify you're running in a merge request pipeline

### Git Depth Issues

If you see errors about missing commits, increase git depth:

```yaml
variables:
  GIT_DEPTH: 0  # Fetch all history
```

### Coverage Format Errors

Make sure the coverage format matches your file:

```yaml
variables:
  COVERAGE_FORMAT: "jacoco"  # For JaCoCo XML
  # or
  COVERAGE_FORMAT: "lcov"    # For LCOV
  # or
  COVERAGE_FORMAT: "coverage-py"  # For coverage.py JSON
```

## Contributing

Contributions are welcome! Please see the [contributing guidelines](../../CONTRIBUTING.md) for details.

## License

These templates are part of covguard and are licensed under the same terms as the main project.
