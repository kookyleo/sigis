"""Run unchanged original EUTL bodies and retain their actual input fixtures."""
from pathlib import Path
from datetime import datetime, timezone
import os
import shutil
import sys
import pytest

OUT=Path(os.environ['EUTL_BASIC_OUT'])
OUT.mkdir(parents=True, exist_ok=True)
CURRENT=None
NAMES=[]

def pytest_configure(config):
    from click.testing import CliRunner
    invoke=CliRunner.invoke
    def observed(self,*args,**kwargs):
        command=args[1] if len(args)>1 else kwargs.get('args',[])
        if CURRENT is not None and command[:2]==['sign','validate']:
            target=OUT/('case-'+str(CURRENT[0]))
            target.mkdir(exist_ok=True)
            for p in Path.cwd().iterdir():
                if p.is_file(): shutil.copy2(p,target/p.name)
                elif p.name=='cache': shutil.copytree(p,target/p.name,dirs_exist_ok=True)
            (target/'argv.txt').write_text('\n'.join(command)+'\n')
            arch=CURRENT[1].funcargs.get('pki_arch')
            if arch is not None:
                revinfo=target/'revinfo'; revinfo.mkdir(exist_ok=True)
                for index, repo in enumerate(arch.service_registry.list_crl_repos()):
                    data=arch.service_registry.get_crl(repo.label,at_time=datetime.now(timezone.utc)).dump()
                    (revinfo/('crl-'+str(index)+'.der')).write_bytes(data)
        return invoke(self,*args,**kwargs)
    CliRunner.invoke=observed

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    global CURRENT
    CURRENT=(len(NAMES),item)
    NAMES.append(item.name)
    (OUT/'cases.txt').write_text('\n'.join(NAMES)+'\n')
    yield
    CURRENT=None

if __name__=='__main__':
    assert __debug__ and sys.flags.optimize==0
    source='/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests/validation/test_cli_qualified_validation.py'
    raise SystemExit(pytest.main(['-q','-p','no:cacheprovider','-p','prepare',source,'-k','not _ades']))
