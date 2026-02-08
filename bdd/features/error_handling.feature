Feature: Error handling and input validation
  As a developer using covguard
  I want clear error messages for invalid inputs
  So that I can diagnose and fix issues quickly

  Background:
    Given ignore directives are disabled

  # ============================================================================
  # Malformed Input Handling
  # ============================================================================

  Scenario: Invalid diff format is handled gracefully
    Given an invalid diff text "not a valid diff"
    And an LCOV report with any values
    When covguard checks coverage
    Then the verdict is "fail"
    And the exit code is 1
    And findings include code "covguard.input.invalid_diff"
    And findings include code "tool.runtime_error"

  Scenario: Empty LCOV is handled gracefully
    Given a diff with added lines in "src/lib.rs"
    And an empty LCOV report
    When covguard checks coverage
    # Empty LCOV means no coverage data, lines counted as missing
    Then missing_lines is greater than 0

  Scenario: Invalid LCOV format is handled gracefully
    Given a diff with added lines in "src/lib.rs"
    And an invalid LCOV text "not valid lcov"
    When covguard checks coverage
    Then the verdict is "fail"
    And the exit code is 1
    And findings include code "covguard.input.invalid_lcov"
    And findings include code "tool.runtime_error"

  # ============================================================================
  # Edge Case Inputs
  # ============================================================================

  Scenario: Very large line numbers are handled
    Given a diff adding line 999999 to "src/lib.rs"
    And an LCOV report where line 999999 has 0 hits
    When covguard checks coverage
    Then a finding exists for file "src/lib.rs" at line 999999

  Scenario: Unicode in file paths is handled
    Given a diff with added lines in "src/日本語.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then findings exist for file "src/日本語.rs"

  Scenario: Spaces in file paths are handled
    Given a diff with added lines in "src/my file.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then findings exist for file "src/my file.rs"

  # ============================================================================
  # Boundary Conditions
  # ============================================================================

  Scenario: Single line diff
    Given a diff adding 1 lines to "src/lib.rs"
    And an LCOV report where line 1 has 0 hits
    When covguard checks coverage
    Then uncovered_lines is 1
    And changed_lines_total is 1

  Scenario: Coverage with zero hits explicitly reported
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report with explicit zero hits
    When covguard checks coverage
    Then the verdict is "fail"
    And findings include code "covguard.diff.uncovered_line"

  # ============================================================================
  # Output Format Verification
  # ============================================================================

  Scenario: Markdown output contains coverage summary
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then the markdown output contains "covguard"
    And the markdown output contains "fail"

  Scenario: SARIF output is valid JSON
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then the SARIF output is valid JSON
    And the SARIF output contains "covguard"

  Scenario: Annotations output contains error markers
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then the annotations output contains "::error"
    And the annotations output contains "src/lib.rs"

  # ============================================================================
  # Multiple LCOV Scenarios
  # ============================================================================

  Scenario: Multiple files with separate LCOV entries
    Given a diff adding lines to "src/a.rs" and "src/b.rs"
    And an LCOV report with separate entries for both files fully covered
    When covguard checks coverage
    Then the verdict is "pass"
    And changed_lines_total is 4

  # ============================================================================
  # Extreme Values
  # ============================================================================

  Scenario: Very high hit count is handled
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where all lines have 999999 hits
    When covguard checks coverage
    Then covered_lines is 3

  Scenario: Coverage percentage precision
    Given a diff adding 3 lines to "src/lib.rs"
    And an LCOV report where 1 line is covered and 2 are not
    When covguard checks coverage
    Then coverage_pct is approximately 33.33
    And uncovered_lines is 2
