"""Fresh unchanged-original fixture preparation for the eight AdES CLI tests."""
from pathlib import Path
import os
import shutil
import sys
import pytest

OUT = Path(os.environ['QUALIFIED_CASE_OUT'])
OUT.mkdir(parents=True, exist_ok=True)
CASE_NAMES = []

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    yield
    # Fixture teardown removes the isolated cwd, so copy the actual complete
    # signing/validation files after the original assertions, before teardown.
    index = len(CASE_NAMES)
    CASE_NAMES.append(item.name)
    dest = OUT / ('case-' + str(index))
    dest.mkdir(exist_ok=True)
    for path in Path.cwd().iterdir():
        if path.is_file():
            shutil.copy2(path, dest / path.name)
        elif path.name == 'cache':
            shutil.copytree(path, dest / path.name, dirs_exist_ok=True)
    from tests.conftest import FREEZE_DT
    (dest / 'moment.txt').write_text(str(int(FREEZE_DT.timestamp())) + '\n')
    (dest / 'original-clock.txt').write_text(FREEZE_DT.isoformat() + '\n')
    (OUT / 'cases.txt').write_text('\n'.join(CASE_NAMES) + '\n')

if __name__ == '__main__':
    assert __debug__ and sys.flags.optimize == 0
    source = '/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests/validation/test_cli_qualified_validation.py'
    raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', '-p', 'prepare', source, '-k', '_ades']))
