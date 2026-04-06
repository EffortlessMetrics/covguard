Feature: Output format and rendering edge cases
  As a user viewing covguard output
  I want all output formats to handle edge cases correctly
  So that I can integrate with different tools reliably

  # ============================================================================
  # Markdown output edge cases
  # ============================================================================

  Scenario: Markdown output with no findings
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then markdown output exists
    And markdown contains "pass" or "100%"

  Scenario: Markdown output with findings includes details
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    When covguard checks coverage
    Then markdown output exists
    And markdown contains "src/lib.rs"
    And markdown contains "uncovered"

  Scenario: Markdown truncation marker present when truncated
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And max markdown lines of 20
    When covguard checks coverage
    Then markdown contains truncation indicator

  Scenario: Markdown output with custom max lines
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And max markdown lines of 10
    When covguard checks coverage
    Then markdown contains "Showing 10 of"

  # ============================================================================
  # SARIF output edge cases
  # ============================================================================

  Scenario: SARIF output is valid JSON
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    When covguard checks coverage with SARIF output
    Then SARIF output is valid JSON
    And SARIF contains "version" field
    And SARIF contains "results" array

  Scenario: SARIF output with no findings
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage with SARIF output
    Then SARIF output is valid JSON
    And SARIF results array is empty

  Scenario: SARIF output respects max results
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And max SARIF results of 5
    When covguard checks coverage with SARIF output
    Then SARIF results count is at most 5

  Scenario: SARIF output includes rule information
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    When covguard checks coverage with SARIF output
    Then SARIF contains rules section
    And SARIF rules include "covguard.diff.uncovered_line"

  # ============================================================================
  # GitHub annotations edge cases
  # ============================================================================

  Scenario: Annotations output uses workflow commands
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    When covguard checks coverage
    Then annotation output contains "::error"

  Scenario: Annotations include file and line
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage for line 5
    When covguard checks coverage
    Then annotation contains "src/lib.rs"
    And annotation contains "line=5"

  Scenario: Annotations respect max limit
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And max annotations of 10
    When covguard checks coverage
    Then annotation error count is at most 10

  # ============================================================================
  # JSON report edge cases
  # ============================================================================

  Scenario: JSON report is valid JSON
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then report JSON is valid
    And report contains "verdict" field

  Scenario: JSON report includes all required fields
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then report contains "schema" field
    And report contains "tool" field
    And report contains "run" field
    And report contains "verdict" field
    And report contains "findings" array

  Scenario: JSON report includes data section
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 80% coverage
    When covguard checks coverage
    Then report contains "data" section
    And data contains "diff_coverage_pct"

  Scenario: Empty findings array for pass
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then findings array is empty

