Feature: Diff coverage ratchet
  As a developer
  I want to ensure my PR changes are covered by tests
  So that I don't introduce untested code

  Background:
    Given ignore directives are disabled

  # ============================================================================
  # Core Uncovered Line Detection
  # ============================================================================

  Scenario: Uncovered added lines fail in strict mode
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% line coverage
    When covguard checks coverage with profile "strict"
    Then the verdict is "fail"
    And findings include code "covguard.diff.uncovered_line"
    And the exit code is 2

  Scenario: Fully covered added lines pass
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where all lines are covered
    When covguard checks coverage with profile "strict"
    Then the verdict is "pass"
    And findings count is 0
    And the exit code is 0

  Scenario: Partially covered lines produce findings
    Given a diff adding 3 lines to "src/lib.rs"
    And an LCOV report where line 2 is covered but lines 1 and 3 are not
    When covguard checks coverage
    Then the verdict is "fail"
    And uncovered_lines is 2
    And covered_lines is 1
    And coverage_pct is approximately 33.33

  # ============================================================================
  # Scope: Added vs Touched
  # ============================================================================

  Scenario: Added-only scope does not punish pure deletions
    Given a diff that only deletes lines from "src/lib.rs"
    And an LCOV report with any values
    When covguard checks coverage with scope "added"
    Then the verdict is "pass"
    And changed_lines_total is 0

  Scenario: Touched scope includes modified lines
    Given a diff that modifies existing lines in "src/lib.rs"
    And an LCOV report where modified lines have 0 hits
    When covguard checks coverage with scope "touched"
    Then the verdict is "fail"
    And findings include code "covguard.diff.uncovered_line"

  # Note: The "added" scope with modified lines scenario depends on how the
  # diff parser classifies modified lines. A modified line (delete + add) is
  # typically still considered an "added" line in unified diff format.

  # ============================================================================
  # Threshold Enforcement
  # ============================================================================

  # Note: Threshold only controls the coverage_below_threshold finding.
  # Uncovered lines produce error findings unless within max_uncovered_lines buffer.
  # To allow uncovered lines without failing, use fail_on "never".

  Scenario: Coverage below threshold adds threshold finding
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 70% line coverage
    And a coverage threshold of 80%
    When covguard checks coverage
    Then the verdict is "fail"
    And findings include code "covguard.diff.coverage_below_threshold"

  Scenario: Coverage at threshold does not add threshold finding
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 80% line coverage
    And a coverage threshold of 80%
    When covguard checks coverage
    # Still fails because uncovered lines produce error findings
    Then the verdict is "fail"
    And uncovered_lines is 2

  Scenario: Fully covered meets any threshold
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where all lines are covered
    And a coverage threshold of 100%
    When covguard checks coverage
    Then the verdict is "pass"
    And findings count is 0

  # ============================================================================
  # FailOn Policy Modes
  # ============================================================================

  Scenario: FailOn error mode fails on uncovered lines
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks with fail_on "error"
    Then the verdict is "fail"
    And the exit code is 2

  Scenario: FailOn warn mode fails on warnings too
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 70% line coverage
    And a coverage threshold of 80%
    When covguard checks with fail_on "warn"
    Then the verdict is "fail"

  Scenario: FailOn never mode only warns on uncovered lines
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks with fail_on "never"
    Then the verdict is "warn"
    And the exit code is 0

  Scenario: Lenient profile uses fail_on never
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage with profile "lenient"
    Then the verdict is "warn"
    And the exit code is 0

  # ============================================================================
  # Ignore Directives
  # ============================================================================

  Scenario: Ignore directive excludes an uncovered line
    Given ignore directives are enabled
    And a file where an added line contains "covguard: ignore"
    And LCOV reports that line has 0 hits
    When covguard checks coverage
    Then the ignored line is excluded from evaluation
    And ignored_lines_count is 1

  Scenario: Ignore directive with hyphen syntax
    Given ignore directives are enabled
    And a file where an added line contains "covguard-ignore"
    And LCOV reports that line has 0 hits
    When covguard checks coverage
    Then the ignored line is excluded from evaluation

  Scenario: Ignore directive in block comment
    Given ignore directives are enabled
    And a file where an added line contains "/* covguard: ignore */"
    And LCOV reports that line has 0 hits
    When covguard checks coverage
    Then the ignored line is excluded from evaluation

  Scenario: Disabled ignore directives are not honored
    Given ignore directives are disabled
    And a diff with added lines containing "covguard: ignore" in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage with profile "strict"
    Then the verdict is "fail"
    And ignored_lines_count is 0

  # ============================================================================
  # Multiple Files
  # ============================================================================

  Scenario: Multiple files with mixed coverage
    Given a diff adding lines to multiple files
    And an LCOV report where "src/a.rs" is covered and "src/b.rs" is not
    When covguard checks coverage
    Then findings exist for file "src/b.rs"
    And no findings exist for file "src/a.rs"

  Scenario: One file missing coverage data counted as missing
    Given a diff adding lines to "src/lib.rs" and "src/other.rs"
    And an LCOV report that only covers "src/lib.rs"
    When covguard checks coverage
    # Missing lines are counted but don't produce uncovered_line findings
    Then missing_lines is greater than 0

  # ============================================================================
  # Edge Cases
  # ============================================================================

  Scenario: Empty diff produces pass verdict
    Given an empty diff
    And an LCOV report with any values
    When covguard checks coverage
    Then the verdict is "pass"
    And changed_lines_total is 0

  Scenario: Diff with only context lines (no additions)
    Given a diff with only context changes in "src/lib.rs"
    And an LCOV report with any values
    When covguard checks coverage with scope "added"
    Then the verdict is "pass"
    And changed_lines_total is 0

  Scenario: Binary file changes are ignored
    Given a diff that modifies a binary file
    And an LCOV report with any values
    When covguard checks coverage
    Then the verdict is "pass"
    And changed_lines_total is 0

  # ============================================================================
  # Metrics Calculation
  # ============================================================================

  Scenario: Coverage percentage is calculated correctly
    Given a diff adding 5 lines to "src/lib.rs"
    And an LCOV report where 3 lines are covered and 2 are not
    When covguard checks coverage
    Then coverage_pct is 60.0
    And covered_lines is 3
    And uncovered_lines is 2

  Scenario: Zero total lines yields 100% coverage
    Given a diff that only deletes lines from "src/lib.rs"
    And an LCOV report with any values
    When covguard checks coverage
    Then coverage_pct is 100.0

  # ============================================================================
  # Finding Details
  # ============================================================================

  Scenario: Findings have correct severity
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% line coverage
    When covguard checks coverage with profile "strict"
    Then all findings have severity "error"

  Scenario: Findings have correct location info
    Given a diff adding line 42 to "src/lib.rs"
    And an LCOV report where line 42 has 0 hits
    When covguard checks coverage
    Then a finding exists for file "src/lib.rs" at line 42

  Scenario: Findings are deterministically sorted
    Given a diff adding uncovered lines to "src/b.rs", "src/a.rs", and "src/c.rs"
    And an LCOV report where all added lines have 0 hits
    When covguard checks coverage
    Then findings are sorted by path then line number

  # ============================================================================
  # Renamed Files
  # ============================================================================

  Scenario: Renamed file with changes is evaluated
    Given a diff that renames "src/old.rs" to "src/new.rs" with changes
    And an LCOV report for "src/new.rs" with 0 hits
    When covguard checks coverage
    Then the verdict is "fail"
    And findings exist for file "src/new.rs"

  Scenario: Renamed file without changes produces no findings
    Given a diff that renames "src/old.rs" to "src/new.rs" without changes
    And an LCOV report with any values
    When covguard checks coverage
    Then the verdict is "pass"
    And changed_lines_total is 0

  # ============================================================================
  # Path Normalization
  # ============================================================================

  Scenario: Paths with different separators are normalized
    Given a diff with added lines in "src/sub/file.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage
    Then findings exist for file "src/sub/file.rs"

  Scenario: Paths with leading dot-slash are normalized
    Given a diff with added lines in "./src/lib.rs"
    And an LCOV report for normalized path "src/lib.rs" with 0 hits
    When covguard checks coverage
    Then the verdict is "fail"

  # ============================================================================
  # Additional Threshold Scenarios
  # ============================================================================

  Scenario: Threshold at 0% always passes threshold check
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% line coverage
    And a coverage threshold of 0%
    When covguard checks coverage
    Then the verdict is "fail"
    And findings include code "covguard.diff.uncovered_line"

  Scenario: Threshold at 100% requires full coverage
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 90% line coverage
    And a coverage threshold of 100%
    When covguard checks coverage
    Then the verdict is "fail"
    And findings include code "covguard.diff.coverage_below_threshold"

  # ============================================================================
  # Report Metadata
  # ============================================================================

  Scenario: Report includes correct scope in data
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where all lines are covered
    When covguard checks coverage with scope "touched"
    Then the verdict is "pass"
    And the report scope is "touched"

  Scenario: Report includes input metadata
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where all lines are covered
    When covguard checks coverage
    Then the verdict is "pass"
    And the report has valid tool info
