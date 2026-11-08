# AIRGAP — the AI data analyst that shows its receipts

> **Vultr Agent Rush · Challenge 1 "Blast Radius Zero"**
> Upload a spreadsheet, ask a question, get an answer — plus a **signed Containment Receipt** showing what the agent was never able to do. Then attack it yourself with six real-world exfiltration and escape techniques and watch them fail.

**Live demo:** https://96-30-195-46.sslip.io  ·  **License:** MIT

*Sandboxes keep agents contained. Airgap makes containment visible, testable and verifiable.*

---

## What it does

1. **Ask.** Upload a CSV and ask a question in plain English.
2. **Plan → Dispatch → Verify.** A coder model (Vultr Serverless Inference) writes one Python script. It runs in a throwaway, network-less sandbox. A second, different model explains the real output. **Number Guard** checks that every figure in the answer appears in the sandbox's actual stdout (green = matched, red = not).
3. **Prove.** Every run ends with an Ed25519-signed, hash-chained **Containment Receipt**: the sandbox policy as *observed* from `docker inspect`, measured usage, canary results, and proof the container was destroyed. The browser verifies the signature itself.
4. **Attack Lab.** Six attack "cartridges" — HTTP exfiltration, cloud-metadata SSRF, DNS tunnelling, secret harvesting, fork/memory bomb, host escape — run live against the sandbox, each judged from observed evidence and each producing its own signed receipt.
5. **Tamper test.** Edit one field of any receipt and verify: the signature check fails.

## Architecture

```
 Browser ──HTTPS──► Caddy ──► FastAPI orchestrator (control plane, Vultr Cloud Compute VM)
                              │  holds ALL secrets: inference key, signing key, canary token
                              │  planner / explainer ──► Vultr Serverless Inference (OpenAI-compatible)
                              │  Number Guard · receipt builder · Ed25519 signer · SQLite hash-chained ledger
 ═════════════ TRUST BOUNDARY (docker.sock) ═══════════════════════════════════════════
                              ▼
        one throwaway container per run  (gVisor runsc, falls back to runc)
        network=none · read-only rootfs · cap-drop ALL · no-new-privileges · non-root
        pids / memory / cpu / wall-clock caps · /out is a size-capped tmpfs
        IN: main.py + data.csv (read-only)      OUT: stdout (capped) + PNG files only
```

**The one rule:** the LLM is called by the control plane, never from inside the sandbox. The sandbox has no network, no secrets and no Docker socket. Only code goes in; only stdout and PNGs come out.

Run lifecycle: `UPLOAD → PROFILE → PLAN → DISPATCH → EXECUTE → VERIFY → DESTROY → SIGN`. The CSV is never parsed by the control plane: a fixed profiler script parses it *inside* a sandbox run, and only its size-capped JSON output is read back.

## Vultr services used

| Vultr service | Used for |
|---|---|
| **Cloud Compute VM** (Ubuntu 24.04, 2 vCPU / 4 GB) | Control plane, sandbox host (Docker + gVisor), Caddy, public web app |
| **Serverless Inference** (`https://api.vultrinference.com/v1`) | *All* agent LLM calls: planner `qwen3.8-27b` (writes the Python), explainer `glm-5.3` (writes the answer from real output) — two different model families on purpose |
| Firewall / `ufw` | Only 22, 80, 443 open inbound |

The OpenAI-compatible endpoint is used through the standard `openai` Python SDK with `base_url` set to Vultr. The inference key lives only in the orchestrator's environment file (`chmod 600`), never in the repo and never in the sandbox.

## How the agent executes real tasks

The model never executes anything. It returns code; the orchestrator dispatches that code to a fresh container and returns the *observed* result. If the script fails, stderr is fed back to the planner (up to 3 attempts). Each attempt, and the profiler run, gets its own container, each destroyed and verified gone (`containers.get(name)` must raise `NotFound`).

## The Containment Receipt

Canonical JSON (sorted keys, no whitespace, **integers only** so Python and JavaScript agree byte-for-byte) → Ed25519 signature → SHA-256 hash chained to the previous receipt in an append-only SQLite ledger. Fields include the policy re-read from `docker inspect`, `exit_code`, `oom_killed`, `timed_out`, wall time, stdout hash, canary scan results, destroy verification, model IDs and token counts, and Number Guard results.

Verification: `POST /api/verify`, or in the browser with WebCrypto Ed25519 against `GET /api/pubkey`. A cross-language test (`tests/verify_canon.mjs`) checks that a Python-signed receipt verifies in JavaScript and that a tampered copy fails.

> **Be clear about what a receipt proves.** The signature proves the receipt was not altered after the orchestrator issued it. It is **not** hardware attestation — you are trusting the orchestrator's measurements. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Attack Lab (assume breach)

LLMs don't reliably obey injected instructions, so a live injection can fizzle. Each cartridge therefore ships (a) a poisoned CSV containing an injection cell and (b) the payload a **fully hijacked** model would write, which we execute deterministically. These are *classes* of attack inspired by public incidents (ChatGPT code interpreter exfiltration, Flowise CSV agent, AWS Bedrock Code Interpreter DNS bypass) — not reproductions of any vendor's exact exploit.

| Cartridge | Attempts | Stopped by |
|---|---|---|
| `EXFIL-HTTP` | POST the CSV to an attacker host | `network=none` |
| `METADATA-SSRF` | GET `169.254.169.254` | no network at all |
| `DNS-EXFIL` | data in a DNS lookup | no resolver / interface |
| `SECRET-HARVEST` | dump env, `/proc/1/environ`, `~/.aws`, docker.sock | nothing was ever provided |
| `RESOURCE-BOMB` | fork 300 processes, allocate memory forever | memory cap (`oom_killed`, exit 137) |
| `HOST-ESCAPE` | write `/etc`, `setuid(0)`, `mount`, `ptrace`, docker.sock | ro rootfs, cap-drop ALL, non-root, gVisor |

The service also **fails closed**: at boot it runs `EXFIL-HTTP` and `RESOURCE-BOMB`; if either is not contained it refuses to serve runs (`/healthz` reports it).

## Run it yourself

Requires a **Linux host** with Docker (the runner reads the `/out` tmpfs volume from the host; Docker Desktop on macOS will not work). gVisor is optional.

```bash
git clone <this repo> && cd airgap
docker build -t airgap-runner:1 runner/image                 # pandas/numpy/matplotlib baked in
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo mkdir -p /var/lib/airgap/runs && sudo chown $USER /var/lib/airgap -R
cp .env.example .env && $EDITOR .env                         # add your Vultr inference key
set -a; . ./.env; set +a
SANDBOX_RUNTIME=runc .venv/bin/uvicorn server.main:app --host 127.0.0.1 --port 8000
```

gVisor on Ubuntu: add the apt repo from gvisor.dev, `apt install runsc`, `runsc install`, restart Docker, set `SANDBOX_RUNTIME=runsc`. `deploy/` holds the systemd unit and Caddyfile used for the demo.

Tests (need the image and Docker):
```bash
.venv/bin/python tests/run_attacks.py runsc            # all six cartridges, prints evidence
node tests/verify_canon.mjs http://127.0.0.1:8000      # Python-signed receipt verifies in JS; tamper fails
python3 tests/ui_journey.py http://127.0.0.1:8000 /tmp/shots   # Playwright end-to-end UI run
```

## Repo layout

```
runner/   DockerRunner (policy → inspect → destroy), six attack cartridges, sandbox image
server/   FastAPI app, run state machine, Vultr inference client, Number Guard, receipts + ledger
web/      dependency-free single-page UI (no build step)
deploy/   systemd unit, Caddyfile
tests/    attack suite, cross-language receipt check, UI journey
demo/     sales_q3.csv (includes a poisoned cell)
```

## Known limitations (honest list)

- **Not hardware attestation.** Receipts are signed by the same host that produced them.
- **`docker.sock` is root-equivalent** and the orchestrator holds it. Mitigation: no user-controlled Docker arguments, and the sandbox never sees the socket. A broker process or a separate sandbox VM is the next step.
- **gVisor is a user-space kernel, not a microVM.** The VM has no `/dev/kvm`, so Firecracker/Microsandbox were not an option here.
- **Pids limit is 256, not lower:** gVisor's own threads count against the pids cgroup and a limit of 64 crashes it. The fork bomb is therefore stopped by the memory cap.
- **Number Guard catches numbers the model made up, not wrong logic** in a script whose output is faithfully reported.
- The sandbox image inherits public, non-secret variables (e.g. `GPG_KEY` from the Python base image); the secret-harvest check allowlists exactly those.
- Run state and SSE history are in memory (single worker); receipts persist in SQLite.
- Public demo is rate-limited and capped (5 MB uploads, 2 concurrent sandboxes).

MIT licensed. See [LICENSE](LICENSE).
