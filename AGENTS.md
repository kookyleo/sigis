# Repository execution rules

- Communicate in Chinese. Code, documentation, reports and commit messages use English.
- For round 3, follow `docs/lanes/round3/README.md`, the assigned brief and
  `ownership.json`. Respect exclusive file ownership and route shared API changes to L.
- Every Cargo invocation goes through `tools/cargo-locked.sh`; it injects
  `rust-target-env` and holds the common repository lock for the entire command.
  Do not run raw or remote Cargo, use another target, change speed-related Rust
  flags/profiles/features, or clean the shared target. The wrapper controls jobs.
- Port exact upstream tests before implementation. Compare against pyHanko 0.38.1
  in `/tmp/pyhanko-oracle/venv`; trust decisions must fail closed.
- Count unique upstream functions, not parameter wrappers or oracle calls.
- Local English commits only; no push, `pkill`, service restart or interference
  with other sessions. Preserve the old lane sessions unchanged.
- Save progress, logs and handoffs to files throughout long tasks.
