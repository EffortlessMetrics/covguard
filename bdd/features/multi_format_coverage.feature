Feature: Multi-format coverage support
  As a developer in a multi-language project
  I want to use JaCoCo and coverage.py reports
  So that I can ensure coverage across Java and Python files

  Background:
    Given ignore directives are disabled

  # ============================================================================
  # JaCoCo XML Support
  # ============================================================================

  Scenario: Uncovered Java lines in JaCoCo fail
    Given a diff adding 3 lines to "com/example/Foo.java"
    And a JaCoCo report where those lines have 0 hits
    When covguard checks coverage with format "jacoco"
    Then the verdict is "fail"
    And uncovered_lines is 3
    And findings include code "covguard.diff.uncovered_line"

  Scenario: Fully covered Java lines in JaCoCo pass
    Given a diff adding lines to "com/example/Foo.java"
    And a JaCoCo report where all lines are covered
    When covguard checks coverage with format "jacoco"
    Then the verdict is "pass"
    And findings count is 0

  Scenario: Mixed coverage in JaCoCo report
    Given a diff adding 3 lines to "com/example/Foo.java"
    And a JaCoCo report where line 1 is covered and lines 2 and 3 are not
    When covguard checks coverage with format "jacoco"
    Then the verdict is "fail"
    And covered_lines is 1
    And uncovered_lines is 2

  # ============================================================================
  # coverage.py JSON Support
  # ============================================================================

  Scenario: Uncovered Python lines in coverage.py fail
    Given a diff adding 3 lines to "src/main.py"
    And a coverage.py report where those lines are missing
    When covguard checks coverage with format "coverage-py"
    Then the verdict is "fail"
    And uncovered_lines is 3

  Scenario: Fully covered Python lines in coverage.py pass
    Given a diff adding lines to "src/main.py"
    And a coverage.py report where all lines are executed
    When covguard checks coverage with format "coverage-py"
    Then the verdict is "pass"
    And findings count is 0

  # ============================================================================
  # Format Auto-detection (Planned/Future)
  # ============================================================================

  Scenario: Auto-detect JaCoCo format
    Given a diff adding lines to "com/example/Foo.java"
    And a JaCoCo report where all lines are covered
    When covguard checks coverage with auto-detected format
    Then the verdict is "pass"

  Scenario: Auto-detect coverage.py format
    Given a diff adding lines to "src/main.py"
    And a coverage.py report where all lines are executed
    When covguard checks coverage with auto-detected format
    Then the verdict is "pass"

  # ============================================================================
  # Mixed Multi-format Merging
  # ============================================================================

  Scenario: Merge JaCoCo and LCOV reports
    Given a diff adding 2 lines to "com/example/Foo.java" and 2 lines to "src/lib.rs"
    And a JaCoCo report where "com/example/Foo.java" is covered
    And an LCOV report where "src/lib.rs" is covered
    When covguard checks coverage with both reports
    Then the verdict is "pass"
    And covered_lines is 4
    And uncovered_lines is 0
