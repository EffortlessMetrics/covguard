Feature: Implementation plan conformance
  As a maintainer
  I want implementation-plan capabilities verified through BDD
  So that regressions are caught at acceptance-test level

  Background:
    Given ignore directives are disabled

  Scenario: Multiple LCOV inputs are merged with max hits
    Given a diff adding 3 lines to "src/lib.rs"
    And multiple LCOV inputs are merged by max hits
    When covguard checks coverage
    Then covered_lines is 1
    And uncovered_lines is 2
    And the verdict is "fail"

  Scenario: Absolute LCOV paths are normalized via path_strip
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report with absolute SF paths under "/workspace/" where those lines have 0 hits
    And a path strip prefix "/workspace/"
    When covguard checks coverage
    Then findings exist for file "src/lib.rs"
    And the verdict is "fail"

  Scenario: Exclude patterns remove files from evaluation
    Given a diff adding lines to "src/a.rs" and "src/b.rs"
    And an LCOV report where all added lines have 0 hits
    And exclude patterns are "src/b.rs"
    When covguard checks coverage
    Then findings exist for file "src/a.rs"
    And no findings exist for file "src/b.rs"
    And excluded_files_count is 1

  Scenario: Findings are truncated when max findings is set
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% line coverage
    And a coverage threshold of 0%
    And max findings is 3
    When covguard checks coverage
    Then findings count is 3
    And truncation is present with shown 3
    And truncation total is greater than shown

  Scenario: Annotation rendering enforces entry limits
    Given a diff adding 10 lines to "src/lib.rs"
    And an LCOV report with 0% line coverage
    And a coverage threshold of 0%
    When covguard checks coverage
    Then annotations rendered with limit 2 contain at most 2 entries

  Scenario: OSS profile does not fail when coverage is missing for one file
    Given a diff adding lines to "src/lib.rs" and "src/other.rs"
    And an LCOV report that only covers "src/lib.rs"
    When covguard checks coverage with profile "oss"
    Then the verdict is "pass"
    And the exit code is 0

  Scenario: Empty diff reports explicit no_changed_lines reason
    Given an empty diff
    And an LCOV report with any values
    When covguard checks coverage
    Then the verdict is "pass"
    And the verdict reasons include "no_changed_lines"

  Scenario: Binary diff is skipped and reported in debug metadata
    Given a diff that modifies a binary file
    And an LCOV report with any values
    When covguard checks coverage
    Then changed_lines_total is 0
    And debug binary_files_count is 1
    And debug includes binary file "image.png"

  Scenario: Include patterns restrict evaluation scope
    Given a diff adding lines to "src/a.rs" and "src/b.rs"
    And an LCOV report where all added lines have 0 hits
    And include patterns are "src/a.rs"
    When covguard checks coverage
    Then findings exist for file "src/a.rs"
    And no findings exist for file "src/b.rs"
    And excluded_files_count is 1

  Scenario: Markdown includes truncation marker and repro command
    Given a diff adding 15 lines to "src/lib.rs"
    And an LCOV report with 15 uncovered lines
    And a coverage threshold of 0%
    When covguard checks coverage
    Then the markdown output contains "*Showing 10 of 15 uncovered lines*"
    And the markdown output contains "covguard check"

  Scenario: Re-running the same input is deterministic
    Given a diff adding uncovered lines to "src/b.rs", "src/a.rs", and "src/c.rs"
    And an LCOV report where all added lines have 0 hits
    When covguard checks coverage
    Then re-running the same check yields identical report JSON
