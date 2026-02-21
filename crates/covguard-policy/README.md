# covguard-policy

Shared policy enums, profile variants, and preset settings used by covguard core
services.

## Built-in profiles

- `oss`: threshold 70%, scope `added`, fail on `never`, missing `warn`
- `moderate`: threshold 75%, scope `added`, fail on `error`, missing file `warn`
- `team`: threshold 80%, scope `added`, fail on `error`
- `strict`: threshold 90%, scope `touched`, fail on `error`, missing `fail`
- `lenient`: threshold 0%, scope `added`, fail on `never`
