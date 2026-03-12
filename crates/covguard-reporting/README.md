# covguard-reporting

Report assembly and output metadata construction for `covguard`.

This crate owns responsibilities that sit above renderer output and below orchestration:

- Convert evaluation output into domain (`covguard.report.v1`) and cockpit (`sensor.report.v1`) reports.
- Build skip/error report pairs.
- Derive report reasons and debug metadata.
- Provide the diff-format heuristic used by orchestration validation.
