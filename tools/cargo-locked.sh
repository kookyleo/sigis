#!/usr/bin/env bash
# Serialize every round-3 Cargo invocation across this repository's worktrees.
set -euo pipefail

if (($# == 0)); then
    echo 'Usage: tools/cargo-locked.sh <cargo subcommand> [arguments...]' >&2
    exit 2
fi
if [[ -n ${RUST_TARGET_OWNER:-} ]]; then
    echo 'RUST_TARGET_OWNER must be unset: all lanes share the canonical target.' >&2
    exit 2
fi
for arg in "$@"; do
    case "$arg" in
        --target-dir|--target-dir=*)
            echo 'Target selection belongs to rust-target-env.' >&2
            exit 2
            ;;
    esac
done

common=$(git rev-parse --path-format=absolute --git-common-dir)
lock="$common/round3-cargo.lock"
exec 9>"$lock"
if ! flock -n 9; then
    echo "Waiting for the shared Cargo lock: $lock" >&2
    flock 9
fi

# Run in the caller's worktree; the system helper resolves its common repo.
eval "$(/usr/local/bin/rust-target-env)"
: "${CARGO_TARGET_DIR:?rust-target-env did not select a canonical target}"
# Keep the system slot limit, but avoid dispatching different worktrees to VMs.
export RUST_SLOTS_LOCAL=1
# The installed sccache cannot probe rustc-workspace-wrapper reliably. Keep
# the workspace wrapper (and its Rust flags); bypass only the cache frontend.
export RUSTC_WRAPPER=

subcommand=$1
shift
case "$subcommand" in
    build|check|clippy|test|run|rustc|doc)
        jobs=2
        [[ $subcommand != doc ]] || jobs=1
        # The wrapper owns compile concurrency; everything after -- belongs
        # to the test binary or application and must remain untouched.
        for arg in "$@"; do
            [[ $arg != -- ]] || break
            case "$arg" in
                -j|-j[0-9]*|--jobs|--jobs=*)
                    echo 'The shared wrapper supplies --jobs (2; docs 1).' >&2
                    exit 2
                    ;;
            esac
        done
        exec cargo "$subcommand" --jobs "$jobs" "$@"
        ;;
    clean)
        echo 'Shared target cleanup requires a lead-coordinated maintenance window.' >&2
        exit 2
        ;;
    nextest|bench|b|c|t|r|d|rustdoc|fix|install)
        echo 'Use build/check/test/clippy/doc/run/rustc through this wrapper; it owns build concurrency.' >&2
        exit 2
        ;;
    *) exec cargo "$subcommand" "$@" ;;
esac
