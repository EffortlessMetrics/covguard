Feature: Configuration and policy edge cases
  As a user configuring covguard
  I want edge cases to be handled correctly
  So that the tool behaves predictably in all scenarios

  Background:
    Given ignore directives are disabled

  # ============================================================================
  # Config file scenarios
  # ============================================================================

  Scenario: Missing config file is not an error
    Given no config file exists
    And a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then the verdict is "pass"
    And the exit code is 0

  Scenario: Empty config file uses defaults
    Given an empty config file exists
    And a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then the verdict is "pass"

  Scenario: Config file with unknown keys is ignored
    Given a config file with unknown keys
    And a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    When covguard checks coverage
    Then the verdict is "pass"

  # ============================================================================
  # Include/Exclude pattern scenarios
  # ============================================================================

  Scenario: Exclude pattern removes file from evaluation
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage for that file
    And exclude pattern "src/lib.rs"
    When covguard checks coverage
    Then the verdict is "pass"
    And findings count is 0

  Scenario: Include pattern restricts evaluation scope
    Given a diff adding 10 lines to "src/lib.rs"
    And a diff adding 10 lines to "tests/test.rs"
    And an LCOV report with 0% coverage for both files
    And include pattern "src/*.rs"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"
    And findings do not exist for file "tests/test.rs"

  Scenario: Both include and exclude patterns
    Given a diff adding 10 lines to "src/lib.rs"
    And a diff adding 10 lines to "src/utils.rs"
    And an LCOV report with 0% coverage for both files
    And include pattern "src/*.rs"
    And exclude pattern "src/utils.rs"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"
    And findings do not exist for file "src/utils.rs"

  Scenario: Exclude pattern with wildcard
    Given a diff adding 10 lines to "src/lib.rs"
    And a diff adding 10 lines to "tests/integration.rs"
    And an LCOV report with 0% coverage for both files
    And exclude pattern "tests/**"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"
    And findings do not exist for file "tests/integration.rs"

  # ============================================================================
  # Edge case: Empty and minimal inputs
  # ============================================================================

  Scenario: Empty LCOV with non-empty diff produces warning
    Given a diff adding 10 lines to "src/lib.rs"
    And an empty LCOV report
    When covguard checks coverage
    Then missing_lines is greater than 0

  Scenario: Very small diff (single line)
    Given a diff adding 1 line to "src/lib.rs"
    And an LCOV report with 0% coverage for that line
    When covguard checks coverage
    Then the verdict is "fail"
    And uncovered_lines is 1

  Scenario: Diff with no LCOV produces fail
    Given a diff adding 10 lines to "src/lib.rs"
    And no LCOV report provided
    When covguard checks coverage
    Then the verdict is "fail"

  # ============================================================================
  # Path handling edge cases
  # ============================================================================

  Scenario: Absolute LCOV path with strip prefix
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with absolute path "/build/src/lib.rs"
    And path strip prefix "/build/"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"

  Scenario: LCOV path with Windows absolute path
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with Windows absolute path "C:/build/src/lib.rs"
    And path strip prefix "C:/build/"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"

  Scenario: Different casing in paths (case-sensitive filesystem)
    Given a diff adding 10 lines to "src/Lib.rs"
    And an LCOV report for "src/lib.rs" (different case)
    When covguard checks coverage
    Then findings include code "covguard.diff.missing_coverage_for_file"

  # ============================================================================
  # Threshold edge cases
  # ============================================================================

  Scenario: Threshold above 100 always fails
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 100% coverage
    And a coverage threshold of 150%
    When covguard checks coverage
    Then the verdict is "fail"
    And findings include code "covguard.diff.coverage_below_threshold"

  Scenario: Negative threshold always passes threshold check
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And a coverage threshold of -10%
    When covguard checks coverage
    Then the verdict is "fail"

  Scenario: Fractional threshold works correctly
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report where 7 of 10 lines are covered
    And a coverage threshold of 70%
    When covguard checks with fail_on "never"
    Then the verdict is "warn"

  Scenario: Threshold exactly at boundary passes
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report where 8 of 10 lines are covered
    And a coverage threshold of 80%
    When covguard checks with fail_on "never"
    Then the verdict is "warn"

  # ============================================================================
  # Max findings/truncation edge cases
  # ============================================================================

  Scenario: Max findings truncates output
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage for all lines
    And max findings of 5
    When covguard checks coverage
    Then findings count is 5
    And the report includes truncation indicator

  Scenario: Max annotations truncates GitHub annotations
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage for all lines
    And max annotations of 10
    When covguard checks coverage
    Then the annotation output contains at most 10 errors

  # ============================================================================
  # Composite coverage format edge cases
  # ============================================================================

  Scenario: Multiple LCOV files merged correctly
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with line 1-5 covered
    And another LCOV report with line 6-10 covered
    When covguard checks coverage
    Then covered_lines is 10

  Scenario: JaCoCo and LCOV merged correctly
    Given a diff adding 10 lines to "src/Java.java"
    And a JaCoCo report with line 1-5 covered
    And an LCOV report with line 6-10 covered
    When covguard checks coverage
    Then covered_lines is 10

