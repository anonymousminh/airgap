"""DockerRunner: one throwaway, network-less container per execution.

The receipt is built from what `docker inspect` reports, not from what we asked for.
"""
from __future__ import annotations
import base64, hashlib, os, re, shutil, threading, time, uuid
from pathlib import Path
from typing import Callable

import docker
from docker.errors import NotFound

from .base import OutFile, RunResult, SandboxPolicy

IMAGE = os.environ.get("RUNNER_IMAGE", "airgap-runner:1")
RUNS_DIR = Path(os.environ.get("AIRGAP_RUNS_DIR", "/var/lib/airgap/runs"))
MAX_STREAM_BYTES = 64 * 1024
OUT_TMPFS = "size=8m,uid=65534,gid=65534,mode=0700"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}\.png$")


def _trunc(b: bytes) -> str:
    return b[:MAX_STREAM_BYTES].decode("utf-8", errors="replace")


class DockerRunner:
    def __init__(self) -> None:
        self.client = docker.from_env(timeout=60)

    def sweep(self) -> int:
        """Remove orphaned sandbox containers/volumes (crash recovery)."""
        n = 0
        for c in self.client.containers.list(all=True, filters={"label": "airgap=1"}):
            c.remove(force=True); n += 1
        for v in self.client.volumes.list(filters={"label": "airgap=1"}):
            try: v.remove(force=True)
            except Exception: pass
        return n

    def run(self, code: str, csv_path: Path | None, policy: SandboxPolicy,
            on_stdout: Callable[[str], None] | None = None) -> RunResult:
        rid = uuid.uuid4().hex[:12]
        name = f"airgap-{rid}"
        job_dir = RUNS_DIR / f"job-{rid}"
        job_dir.mkdir(parents=True, mode=0o755)
        os.chmod(job_dir, 0o755)
        (job_dir / "main.py").write_text(code)
        os.chmod(job_dir / "main.py", 0o644)
        if csv_path is not None:
            shutil.copyfile(csv_path, job_dir / "data.csv")
            os.chmod(job_dir / "data.csv", 0o644)

        vol = self.client.volumes.create(
            name=f"{name}-out", driver="local", labels={"airgap": "1"},
            driver_opts={"type": "tmpfs", "device": "tmpfs", "o": OUT_TMPFS})

        kwargs = dict(
            image=IMAGE, command=["sh", "-c", "cp -r /opt/mplcache /tmp/mpl && exec python /job/main.py"], name=name,
            detach=True, labels={"airgap": "1"},
            network_mode="none", read_only=policy.read_only,
            cap_drop=policy.cap_drop, security_opt=["no-new-privileges"],
            pids_limit=policy.pids_limit,
            mem_limit=f"{policy.memory_mb}m", memswap_limit=f"{policy.memory_mb}m",
            nano_cpus=policy.cpu_millis * 1_000_000, user=policy.user,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
            environment={"HOME": "/tmp", "MPLCONFIGDIR": "/tmp/mpl", "PYTHONDONTWRITEBYTECODE": "1"},
            volumes={str(job_dir): {"bind": "/job", "mode": "ro"},
                     vol.name: {"bind": "/out", "mode": "rw"}},
            working_dir="/job",
        )
        if policy.runtime != "runc":
            kwargs["runtime"] = policy.runtime

        t0 = time.monotonic()
        timed_out = False
        out_buf = bytearray()
        container = None
        out_files: list[OutFile] = []
        try:
            container = self.client.containers.create(**kwargs)
            container.start()

            def pump():
                try:
                    pending = b""
                    for chunk in container.logs(stream=True, follow=True, stdout=True, stderr=False):
                        out_buf.extend(chunk)
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            if on_stdout and len(out_buf) <= MAX_STREAM_BYTES:
                                on_stdout(line.decode("utf-8", errors="replace"))
                        if len(out_buf) > MAX_STREAM_BYTES * 4:
                            break
                except Exception:
                    pass
            th = threading.Thread(target=pump, daemon=True); th.start()

            try:
                container.wait(timeout=policy.wall_timeout_s)
            except Exception:
                timed_out = True
                try: container.kill()
                except Exception: pass
                try: container.wait(timeout=10)
                except Exception: pass
            th.join(timeout=3)
            wall_ms = int((time.monotonic() - t0) * 1000)

            container.reload()
            insp = self.client.api.inspect_container(container.id)
            st, hc = insp["State"], insp["HostConfig"]
            stderr = _trunc(container.logs(stdout=False, stderr=True))
            stdout = _trunc(bytes(out_buf))
            observed = SandboxPolicy(
                network=hc["NetworkMode"], read_only=bool(hc["ReadonlyRootfs"]),
                cap_drop=list(hc.get("CapDrop") or []),
                no_new_privileges="no-new-privileges" in (hc.get("SecurityOpt") or [])
                    or "no-new-privileges:true" in (hc.get("SecurityOpt") or []),
                user=insp["Config"].get("User", ""), pids_limit=int(hc.get("PidsLimit") or 0),
                memory_mb=int(hc.get("Memory", 0) // (1024 * 1024)),
                cpu_millis=int(hc.get("NanoCpus", 0) // 1_000_000),
                wall_timeout_s=policy.wall_timeout_s, runtime=hc.get("Runtime") or "runc")
            image_digest = insp.get("Image", "")
            exit_code, oom = int(st.get("ExitCode", -1)), bool(st.get("OOMKilled"))
            out_files = self._collect_out(Path(vol.attrs["Mountpoint"]))
        finally:
            destroyed = True
            if container is not None:
                try: container.remove(force=True, v=True)
                except Exception: pass
                try:
                    self.client.containers.get(name); destroyed = False
                except NotFound:
                    pass
            try: vol.remove(force=True)
            except Exception: destroyed = False
            shutil.rmtree(job_dir, ignore_errors=True)
            if job_dir.exists(): destroyed = False

        return RunResult(
            stdout=stdout, stderr=stderr, exit_code=exit_code, oom_killed=oom,
            timed_out=timed_out, wall_ms=wall_ms, policy_observed=observed,
            image_digest=image_digest, out_files=out_files, destroyed_verified=destroyed)

    @staticmethod
    def _collect_out(mount: Path) -> list[OutFile]:
        files: list[OutFile] = []
        try:
            entries = list(os.scandir(mount))
        except OSError:
            return files
        for e in entries[:20]:
            if len(files) >= 5 or not NAME_RE.match(e.name):
                continue
            try:
                if not e.is_file(follow_symlinks=False):
                    continue
                fd = os.open(e.path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as f:
                    data = f.read(2 * 1024 * 1024 + 1)
            except OSError:
                continue
            if len(data) > 2 * 1024 * 1024 or not data.startswith(PNG_MAGIC):
                continue
            files.append(OutFile(name=e.name, size=len(data),
                                 sha256=hashlib.sha256(data).hexdigest(),
                                 b64=base64.b64encode(data).decode()))
        return files
