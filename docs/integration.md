# covguard — Integration Notes

covguard does not generate coverage. A typical CI flow is:

1) run tests + produce LCOV (upstream tool)
2) run covguard to map coverage onto diff
3) upload artifacts / ingest into cockpit

## GitHub Actions sketch (Rust + cargo llvm-cov)

```yaml
jobs:
  covguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # important for base/head diffs

      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov --locked

      - name: Generate coverage (LCOV)
        run: |
          cargo llvm-cov --lcov --output-path artifacts/coverage/lcov.info

      - name: Run covguard
        run: |
          covguard check             --base "${{ github.event.pull_request.base.sha }}"             --head "${{ github.sha }}"             --lcov artifacts/coverage/lcov.info             --out artifacts/covguard/report.json             --md artifacts/covguard/comment.md             --annotations github

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: cockpit-artifacts
          path: artifacts/
```

Notes:
- If you already have a coverage step, covguard is cheap.
- If you do not, covguard can only be as cheap as your coverage generation.

## Cockpit policy defaults
In `cockpit.toml` (composition policy, not covguard behavior):

```toml
[sensors.covguard]
blocking = true
missing = "warn"     # during rollout; can become fail once adopted
highlights = 5
annotations = 10
```

## Local debugging
- Save the exact patch used:
  - `git diff --unified=0 base..head > artifacts/raw/patch.diff`
- Save the exact LCOV used:
  - copy `lcov.info` into artifacts/raw/
- Run:
  - `covguard check --diff-file artifacts/raw/patch.diff --lcov artifacts/raw/lcov.info ...`
