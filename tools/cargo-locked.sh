#!/usr/bin/env bash
# Use the system Cargo scheduler and canonical target selection.
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

# Run in the caller's worktree; the system helper resolves its common repo.
eval "$(/usr/local/bin/rust-target-env)"
: "${CARGO_TARGET_DIR:?rust-target-env did not select a canonical target}"
# rust-slots owns host placement, worktree locks and compile concurrency.
# Preserve the caller's compiler cache configuration for local and VM builds.
# Lane shells may put rustup's Cargo before the scheduler on PATH.
cargo_launcher=/usr/local/lib/rust-slots/bin/cargo
if [[ ! -x $cargo_launcher ]]; then
    echo 'The system rust-slots Cargo launcher is required.' >&2
    exit 2
fi

subcommand=$1
shift
case "$subcommand" in
    build|check|clippy|test|run|rustc|doc)
        exec "$cargo_launcher" "$subcommand" "$@"
        ;;
    clean)
        echo 'Shared target cleanup requires a lead-coordinated maintenance window.' >&2
        exit 2
        ;;
    nextest|bench|b|c|t|r|d|rustdoc|fix|install)
        echo 'Use build/check/test/clippy/doc/run/rustc through this wrapper.' >&2
        exit 2
        ;;
    *) exec "$cargo_launcher" "$subcommand" "$@" ;;
esac
