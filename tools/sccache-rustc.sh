#!/bin/sh
# Keep the system cache key normalization and recognize its workspace wrapper.
# Cargo nests RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER rustc. sccache otherwise
# probes rustc-ws-threads as a C compiler, causing its exec of -E to fail.
# Translate only the audited wrapper version, preserving exactly its flags.
if [ "${1:-}" = /usr/local/bin/rustc-ws-threads ]; then
    actual=$(sha256sum "$1" 2>/dev/null) || actual=
    actual=${actual%% *}
    if [ "$actual" != 9c25bb2fc7da39f259fa777fe19039af3a9f78b7ebf4c3f6e7d7c5f6e4c41c05 ]; then
        # An unknown wrapper must execute its own policy; dependencies still
        # use sccache. Never silently replace new compiler flags with old ones.
        exec "$@"
    fi
    shift
    rustc=$1
    shift
    case "$rustc" in
        *nightly*)
            case " $* " in
                *" --crate-name "*) set -- "$@" -Zthreads=8 ;;
            esac
            ;;
    esac
    set -- "$rustc" "$@"
fi
exec env -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET_DIR -u CARGO_BUILD_JOBS -u RUST_SLOTS_HELD /usr/local/bin/sccache "$@"
