from __future__ import annotations
from pathlib import Path
from typing import Callable, Literal, Protocol
from pydantic import BaseModel


class SandboxPolicy(BaseModel):
    network: str = "none"
    read_only: bool = True
    cap_drop: list[str] = ["ALL"]
    no_new_privileges: bool = True
    user: str = "65534:65534"
    pids_limit: int = 256  # gVisor's sentry threads count against this cgroup; 64 crashes it
    memory_mb: int = 256
    cpu_millis: int = 1000
    wall_timeout_s: int = 20
    runtime: Literal["runc", "runsc"] = "runsc"


class OutFile(BaseModel):
    name: str
    size: int
    sha256: str
    b64: str  # PNG bytes, base64


class RunResult(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    oom_killed: bool
    timed_out: bool
    wall_ms: int
    policy_observed: SandboxPolicy
    image_digest: str
    out_files: list[OutFile]
    destroyed_verified: bool


class Runner(Protocol):
    def run(self, code: str, csv_path: Path | None, policy: SandboxPolicy,
            on_stdout: Callable[[str], None] | None = None) -> RunResult: ...
