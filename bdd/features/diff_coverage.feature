Feature: Diff coverage ratchet

  Scenario: Uncovered added lines fail in strict mode
    Given a diff with added lines in "src/lib.rs"
    And an LCOV report where those lines have 0 hits
    When covguard checks coverage with profile "strict"
    Then the verdict is "fail"
    And findings include code "covguard.diff.uncovered_line"

  Scenario: Added-only scope does not punish pure deletions
    Given a diff that only deletes lines from "src/lib.rs"
    And an LCOV report with any values
    When covguard checks coverage with scope "added"
    Then the verdict is "pass"
    And changed_lines_total is 0

  Scenario: Ignore directive excludes an uncovered line
    Given a file where an added line contains "covguard: ignore"
    And LCOV reports that line has 0 hits
    When covguard checks coverage
    Then the ignored line is excluded from evaluation
    And ignored_lines_count is 1
