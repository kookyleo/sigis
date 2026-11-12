# Historical repository lock audit

The pre-db8a75c repository launcher acquired .git/round3-cargo.lock on FD 9
and exec'd the system Cargo wrapper. rust-slots uses FD 9 for its own slot:
its acquire function executes `exec 9>>"$D/$h.$i.lock"` before trying flock.
That replaces the inherited repository descriptor and releases its lock
once no other descriptor refers to it. The repository lock can cover queue
waiting, but cannot guarantee serialization of the subsequent Cargo build.
The scheduler's runchild also explicitly closes FD 9 and FD 7 in the Cargo
child, retaining the slot lock in the scheduler parent. The old repository
FD 9 scheme was therefore incorrect for whole-command serialization.

A reproduction using private temporary files, without running Cargo or
touching real locks, confirms the repository lock becomes available when
FD 9 is replaced, while the slot file stays locked. Evidence is saved in
/home/l/.codex/artifacts/sigis/round3-launch/context-clone-api/.

Main db8a75c removed the repository lock entirely. All four R3 worktree
launchers were checked for absence of the obsolete lock and local pin.
System rust-slots now exclusively owns slot acquisition, placement and
per-host worktree scheduling. Automatic rust-remote builds may run on the
VMs. New callers must not rely on the obsolete repository lock report.
No active slot, queue, process or service was changed by this audit.

The old reported PIDs are historical evidence, not proof that a current
process is still the same build. No process termination is part of this
repair. Package cache and target waits must be identified separately from
scheduler waits using current process/log evidence.

A live lslocks snapshot additionally found legacy Cargo PID 679912 holding
both the obsolete repository lock and the canonical target build lock,
with PID 703042 waiting for the target. This does not establish that its
execution path used the scheduler acquisition above: bypass paths and
other descriptor references can retain an inherited lock. The statement
proven here is that FD 9 cannot guarantee whole-command serialization,
not that every historical invocation necessarily released the lock.
The user-reported PIDs 266931 and 272804 were absent at inspection time.
Current process/descriptor observations are recorded separately from the
isolated reproduction; no historical PID is used as a termination target.

Lane session inspection also found PATH beginning with ~/.cargo/bin before
/usr/local/bin. A bare `exec cargo` can therefore invoke rustup Cargo without
ever entering rust-slots; such a path can retain the old FD 9, as the legacy
Cargo snapshot showed. The repository launcher now executes the installed
/usr/local/lib/rust-slots/bin/cargo by absolute path and fails if unavailable.
This preserves the system scheduler's concurrency and placement policy,
without restoring the obsolete repository-wide lock or local job limit.
