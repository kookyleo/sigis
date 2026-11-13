"""Fresh pinned CLI signing on the exact current-clock live test inputs.

This is separate from original frozen-time pytest execution and separate from
validating the native output. No fake clock or HTTP interception is installed.
"""

import argparse
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pyhanko
import pyhanko_certvalidator
import yaml

CLI_SOURCE = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
pyhanko.__path__.append(str(CLI_SOURCE))
import pyhanko.cli
from click.testing import CliRunner
from pyhanko.cli import cli_root
from pyhanko.cli._ctx import CLIContext, PasswordPrompter, UXContext


def file_record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--password-file")
    parser.add_argument("--record", required=True)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    assert argv, "Pass the complete source-style CLI argv after --"
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    assert Path(pyhanko.cli.__file__).resolve().is_relative_to(CLI_SOURCE)
    password = (Path(args.password_file).read_bytes().rstrip(b"\r\n").decode("utf8")
                if args.password_file else "")

    class Prompter(PasswordPrompter):
        def prompt_for_password(self, prompt):
            return password

    candidates = [Path(args.input), Path(args.root)]
    for value in argv:
        path = Path(value)
        if path.is_file() and path.resolve() != Path(args.output).resolve():
            candidates.append(path)
    config_path = Path("pyhanko.yml")
    for index, value in enumerate(argv):
        if value in ["--config", "-c"] and index + 1 < len(argv):
            config_path = Path(argv[index + 1])
        elif value.startswith("--config="):
            config_path = Path(value.split("=", 1)[1])
    if config_path.is_file():
        candidates.append(config_path)
        config = yaml.safe_load(config_path.read_text())

        def configured_files(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ["pfx-file", "pfx_file", "trust", "other-certs", "other_certs"]:
                        values = value if isinstance(value, list) else [value]
                        for name in values:
                            if isinstance(name, str) and Path(name).is_file():
                                candidates.append(Path(name))
                    configured_files(value)
            elif isinstance(node, list):
                for value in node:
                    configured_files(value)

        configured_files(config)
    if args.password_file:
        candidates.append(Path(args.password_file))
    # These are caller snapshots, not a trace of every production file open.
    opened = {str(path.resolve()): file_record(path) for path in candidates}
    record = {
        "kind": "fresh pinned current-clock CLI on native test inputs",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "clock": "current UTC; no override", "argv": argv,
        "cwd": str(Path.cwd()), "sys_executable": sys.executable, "python": file_record(sys.executable),
        "driver": file_record(__file__),
        "cli_module": file_record(pyhanko.cli.__file__),
        "validator_module": file_record(pyhanko_certvalidator.__file__),
        "yaml_module": file_record(yaml.__file__),
        "pyhanko": importlib.metadata.version("pyhanko"),
        "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
        "input_candidates_before_use": opened,
        "new_unique_credit": 0,
    }
    result = CliRunner().invoke(
        cli_root, argv, obj=CLIContext(ux=UXContext(prompter=Prompter()))
    )
    record.update(
        exit_code=result.exit_code, output=result.output,
        exception=(None if result.exception is None else {
            "class": type(result.exception).__name__, "message": str(result.exception),
        }),
    )
    for name, before in opened.items():
        assert file_record(name) == before, f"Input changed: {name}"
    record["output_file"] = (file_record(args.output)
                             if Path(args.output).is_file() else None)
    record["finished_utc"] = datetime.now(timezone.utc).isoformat()
    Path(args.record).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
