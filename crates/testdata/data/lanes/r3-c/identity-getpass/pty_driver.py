"""Drive an actual native controlling terminal, without a product password hook."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import sys
import termios
import time

if sys.flags.optimize:
    raise RuntimeError("PTY driver assertions must remain enabled")
p = argparse.ArgumentParser()
p.add_argument("--bin", required=True)
p.add_argument("--child-receipt", required=True)
p.add_argument("argv", nargs=argparse.REMAINDER)
a = p.parse_args()
argv = a.argv[1:] if a.argv[:1] == ["--"] else a.argv

def snap(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}

binary = snap(a.bin)
pid, master = pty.fork()
if pid == 0:
    child = {"pid": os.getpid(), "stdin_isatty": os.isatty(0),
             "stdout_isatty": os.isatty(1), "stderr_isatty": os.isatty(2),
             "intended_executable": binary, "argv": [a.bin, *argv]}
    Path(a.child_receipt).write_text(json.dumps(child, indent=2) + "\n")
    os.execv(a.bin, [a.bin, *argv])
transcript = bytearray()
sent = False
observed = None
before_send_lflag = None
deadline = time.monotonic() + 45
status = None
timed_out = False
try:
    while True:
        try:
            proc = Path(f"/proc/{pid}/exe")
            if proc.resolve() == Path(binary["path"]):
                observed = snap(proc)
        except (OSError, RuntimeError):
            pass
        if time.monotonic() > deadline:
            timed_out = True
            os.kill(pid, signal.SIGTERM)  # this exact fixture-owned child only
            break
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                data = os.read(master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            transcript.extend(data)
        if not sent and b"passphrase" in transcript.lower():
            flags = termios.tcgetattr(master)[3]
            if not flags & termios.ECHO:
                before_send_lflag = flags
                os.write(master, b"secret\n")
                sent = True
        if status is None:
            ended, child_status = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = child_status
                # Drain the PTY until EOF/EIO before reporting its transcript.
finally:
    os.close(master)
if status is None or timed_out:
    _, status = os.waitpid(pid, 0)
assert snap(a.bin) == binary
record = {"optimize": sys.flags.optimize, "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"), "driver": snap(__file__), "python": snap(sys.executable),
          "child": json.loads(Path(a.child_receipt).read_text()),
          "binary_before_and_after": binary, "observed_executable": observed,
          "argv": argv, "exit_code": os.waitstatus_to_exitcode(status),
          "password_sent_after_echo_off": sent, "lflag_before_send": before_send_lflag,
          "timeout": timed_out, "transcript": transcript.decode(errors="replace"),
          "secret_present_in_transcript": b"secret" in transcript}
print(json.dumps(record))
