"""Controller death and uncertain daemon replies must not orphan authority."""

import os
import shutil
import signal
import subprocess
import sys
import time
from subprocess import CompletedProcess, TimeoutExpired

import pytest

from langgraph.prebuilt.security._container_guardian import Guardian
from langgraph.prebuilt.security.linux import _readline_json

IMAGE = "sha256:3bcfa1622e24814afee022c71236dadd92e31a5fff41ad99a23925bc98311504"
NAME = "slg-session-" + "a" * 32
OWNER = "b" * 64


def test_creation_is_registered_before_command_and_timeout_stays_uncertain(monkeypatch):
    guardian = Guardian(["docker", "--host", "unix:///fixture"])

    def command(arguments, timeout):
        assert guardian.owned[NAME] == OWNER
        raise TimeoutExpired(arguments, timeout)

    monkeypatch.setattr(guardian, "command", command)
    with pytest.raises(TimeoutExpired):
        guardian.execute(
            ["run", "--name", NAME, "--label", f"slg.lifecycle.owner={OWNER}"], 1
        )
    assert NAME in guardian.uncertain
    monkeypatch.setattr(
        guardian,
        "command",
        lambda arguments, timeout: CompletedProcess(arguments, 0, "", ""),
    )
    result = guardian.execute(["ps", "--filter", f"name=^/{NAME}$"], 1)
    assert result.returncode != 0
    assert NAME in guardian.owned


def test_foreign_container_is_never_removed(monkeypatch):
    guardian = Guardian(["docker", "--host", "unix:///fixture"])
    guardian.owned[NAME] = OWNER
    monkeypatch.setattr(guardian, "ownership", lambda name: False)
    with pytest.raises(ValueError, match="ownership"):
        guardian.execute(["rm", "-f", NAME], 1)


def test_observed_owned_creation_resolves_uncertainty_after_removal(monkeypatch):
    guardian = Guardian(["docker", "--host", "unix:///fixture"])
    guardian.owned[NAME] = OWNER
    guardian.uncertain.add(NAME)
    monkeypatch.setattr(guardian, "ownership", lambda name: True)
    monkeypatch.setattr(
        guardian,
        "command",
        lambda arguments, timeout: CompletedProcess(arguments, 0, "", ""),
    )
    guardian.execute(["rm", "-f", NAME], 1)
    assert NAME not in guardian.uncertain
    assert NAME in guardian.owned
    guardian.execute(["ps", "--filter", f"name=^/{NAME}$"], 1)
    assert NAME not in guardian.owned


def test_explicit_close_does_not_wait_for_inherited_pipe_writer():
    source = """
import os,signal,time
from langgraph.prebuilt.security._container_guardian_client import DockerGuardian
guardian=DockerGuardian(['/bin/false','--host','unix:///unused'])
child=os.fork()
if child==0:
    time.sleep(60)
    os._exit(0)
try:
    guardian.close()
    assert guardian.process.returncode==0
finally:
    os.kill(child,signal.SIGKILL)
    os.waitpid(child,0)
"""
    result = subprocess.run(
        [sys.executable, "-c", source], capture_output=True, text=True, timeout=15
    )
    assert result.returncode == 0, result.stderr


CONTROLLER = '''
import hashlib,json,os,signal,sys,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from langchain_core.tools import tool
from langgraph.prebuilt.security import LinuxToolSpec,Principal,Tool,ToolCall,ToolDac,cedar_security
from langgraph.prebuilt.security.container import DockerObjectDispatcher
root=Path(sys.argv[1])
source=root/'tool.py'
source.write_text("from pathlib import Path\\nimport time\\ndef work(path, slow=False):\\n    value=int(Path(path).read_text())+1\\n    Path('/tmp/started').write_text('active')\\n    if slow: time.sleep(60)\\n    return value\\n")
(root/'input').write_text('40')
@tool
def work(path:str,slow:bool=False)->int:
    """Compute inside the container."""
    raise AssertionError('unconfined callback')
dispatcher=DockerObjectDispatcher({'work':LinuxToolSpec('work:work',source,hashlib.sha256(source.read_bytes()).hexdigest())},image=sys.argv[3],private_roots=[root],wall_timeout_s=65)
security=cedar_security(work,manifest='runs linux\\nfs read @{path} need',policy='permit(principal,action,resource);',dispatcher=dispatcher)
principal=Principal('alice',frozenset(),frozenset(),'session')
def invoke(slow):
    call=ToolCall(Tool('work',ToolDac('owner',{'*':'x'}),frozenset(),()),{'path':str(root/'input'),'slow':slow},{},'active' if slow else 'control',0)
    return security.host_executor.invoke(principal,call,()).value
control=invoke(False)
assert control==41
cid=dispatcher.execution_records()[-1]['container_id']
control_cid=cid
descendant=None
if sys.argv[2]=='inherited_pipe':
    descendant=os.fork()
    if descendant==0:
        time.sleep(60)
        os._exit(0)
if sys.argv[2]=='active':
    dispatcher._docker('exec',cid,'/bin/rm','/tmp/started')
    pool=ThreadPoolExecutor()
    future=pool.submit(invoke,True)
    while True:
        try: dispatcher._docker('exec',cid,'/bin/test','-f','/tmp/started');break
        except RuntimeError: time.sleep(.01)
elif sys.argv[2]=='creating':
    principal=Principal('bob',frozenset(),frozenset(),'session')
    pool=ThreadPoolExecutor()
    future=pool.submit(invoke,False)
    while not (root/'creation-ready').exists(): time.sleep(.01)
    cid=(root/'creation-ready').read_text().strip()
print(json.dumps({'status':'ready','phase':sys.argv[2],'container_id':cid,'control_container_id':control_cid,'guardian_pid':dispatcher._guardian.process.pid,'descendant_pid':descendant,'control':control,'receipts':[r.canonical() for r in dispatcher.activation_receipts()]}),flush=True)
signal.pause()
'''


def delayed_client(root):
    """Delay the second real create reply without replacing Docker enforcement."""
    directory = root / "client"
    directory.mkdir()
    wrapper = directory / "docker"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import os,pathlib,subprocess,sys,time\n"
        f"root=pathlib.Path({str(root)!r})\n"
        f"if 'run' not in sys.argv[1:]: os.execv({shutil.which('docker')!r},[{shutil.which('docker')!r},*sys.argv[1:]])\n"
        f"result=subprocess.run([{shutil.which('docker')!r},*sys.argv[1:]],capture_output=True)\n"
        "if 'run' in sys.argv[1:] and result.returncode==0:\n"
        "    counter=root/'create-count'\n"
        "    count=int(counter.read_text())+1 if counter.exists() else 1\n"
        "    counter.write_text(str(count))\n"
        "    if count==2:\n"
        "        (root/'creation-ready').write_bytes(result.stdout)\n"
        "        time.sleep(4)\n"
        "sys.stdout.buffer.write(result.stdout)\n"
        "sys.stderr.buffer.write(result.stderr)\n"
        "sys.exit(result.returncode)\n"
    )
    wrapper.chmod(0o700)
    return {**os.environ, "PATH": str(directory) + os.pathsep + os.environ["PATH"]}


@pytest.mark.parametrize("phase", ["idle", "active", "creating", "inherited_pipe"])
def test_controller_sigkill_reclaims_real_container(tmp_path, phase):
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    if subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True
    ).returncode:
        pytest.skip("Pinned integration image unavailable")
    process = subprocess.Popen(
        [sys.executable, "-c", CONTROLLER, str(tmp_path), phase, IMAGE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=delayed_client(tmp_path) if phase == "creating" else None,
    )
    container_id = None
    descendant = None
    try:
        ready = _readline_json(process, 30)
        assert ready["status"] == "ready" and ready["control"] == 41
        container_id = ready["container_id"]
        descendant = ready["descendant_pid"]
        process.kill()
        assert process.wait(timeout=5) == -signal.SIGKILL
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    f"id={container_id}",
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and not result.stdout.strip():
                break
            time.sleep(0.1)
        else:
            pytest.fail("Guardian did not reclaim the controller's container")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if descendant is not None:
            try:
                os.kill(descendant, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if container_id is not None:
            subprocess.run(
                ["docker", "rm", "-f", "--volumes", container_id],
                capture_output=True,
                timeout=10,
            )
        process.stdout.close()
        process.stderr.close()
