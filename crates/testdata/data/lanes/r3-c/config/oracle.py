"""Fresh pinned-oracle configuration comparisons; no production dependency."""
import json
import sys
import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")

from pyhanko.cli.config import parse_cli_config
from pyhanko.config.logging import StdLogOutput

out = []
for text in json.load(sys.stdin):
    try:
        root = parse_cli_config(text)
        policy = root.config.get_signer_key_usages()
        log = root.log_config[None]
        output = (
            "stdout" if log.output == StdLogOutput.STDOUT
            else "stderr" if log.output == StdLogOutput.STDERR
            else log.output
        )
        out.append({
            "ok": True,
            "level": log.level,
            "output": output,
            "ku": None if policy.key_usage is None else sorted(policy.key_usage),
            "eku": None if policy.extd_key_usage is None else sorted(policy.extd_key_usage),
            "all": policy.match_all_key_usages,
            "explicit": policy.explicit_extd_key_usage_required,
        })
    except Exception:
        out.append({"ok": False})
json.dump(out, sys.stdout)
