Feature: Large-scale edge cases
  As a user with large diffs and coverage files
  I want covguard to handle scale gracefully
  So that it remains performant for real-world PRs

  # ============================================================================
  # Large diff handling
  # ============================================================================

  Scenario: Large diff with many uncovered lines is truncated
    Given a diff adding 100 lines to "src/lib.rs"
    And an LCOV report with 0% coverage
    And max findings of 25
    When covguard checks coverage
    Then findings count is 25

  # ============================================================================
  # Time and date handling
  # ============================================================================

  Scenario: Report includes timestamp
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report where all lines are covered
    When covguard checks coverage
    Then the report has valid tool info
