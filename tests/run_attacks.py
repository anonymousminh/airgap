import sys, secrets, tempfile, pathlib
sys.path.insert(0, "/opt/airgap")
from runner.base import SandboxPolicy
from runner.docker_runner import DockerRunner
from runner.attacks import CARTRIDGES
rt = sys.argv[1] if len(sys.argv) > 1 else "runsc"
r = DockerRunner(); print("swept", r.sweep())
canary = "AIRGAP-CANARY-" + secrets.token_hex(8)
for c in CARTRIDGES:
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(c.csv)
    res = r.run(c.code, pathlib.Path(f.name), SandboxPolicy(runtime=rt))
    ok, ev = c.check(res, canary)
    print(f"[{'CONTAINED' if ok else 'FAIL     '}] {c.id:14s} {res.wall_ms:5d}ms exit={res.exit_code} oom={res.oom_killed} timeout={res.timed_out} destroyed={res.destroyed_verified}\n    evidence: {ev}")
    if not ok: print("    stdout:", res.stdout[:400], "\n    stderr:", res.stderr[:400])
print("policy observed:", res.policy_observed.model_dump())
