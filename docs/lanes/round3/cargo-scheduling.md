# Cargo scheduling and compiler cache

The lead removed the repository flock, RUST_SLOTS_LOCAL export and fixed
job counts at the coordinator's request. System rust-slots owns placement,
per-host worktree locks and concurrency. Its automatic rust-remote dispatch
selects worker targets; callers continue to inject rust-target-env and must
not choose targets manually. Existing slot jobs are left running.

The recorded compiler probe failure was caused by nested wrappers:
sccache-rustc received rustc-ws-threads as its compiler, then probed it with
-E. The workspace wrapper expects an actual rustc executable as argument 1
and attempted to exec -E. Both workers have the same configuration.

The reviewed tools/sccache-rustc.sh retains system cache environment
normalization. It unwraps only the audited rustc-ws-threads version and
passes the actual compiler and exactly the original nightly -Zthreads=8
condition to sccache. It changes no Rust flags, profiles or features. An
unknown workspace-wrapper version executes its own policy without caching
workspace members; dependency compilation remains cached. No blanket empty
RUSTC_WRAPPER export remains in the repository launcher.

Installation and probe/cache/slot evidence are recorded under
/home/l/.codex/artifacts/sigis/round3-launch/urgent-wrapper/.
The installed system cache adapter is backed up before replacement; no
cache server, active build or service is stopped. Installation is limited
to s7, vm2064 and vm2065 after verifying the old adapter and workspace
wrapper contents. The repository contains the reviewed repair source.
