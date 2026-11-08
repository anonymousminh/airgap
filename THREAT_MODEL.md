# Airgap threat model

Scope: the public demo and the code in this repository. Written to be checked, not admired: each control names where to verify it.

## Assets
| Asset | Where it lives |
|---|---|
| Vultr inference API key | orchestrator environment file (`chmod 600`), process memory |
| Ed25519 signing key | `/var/lib/airgap/signing.key` (`chmod 600`) on the control-plane host |
| Canary token | orchestrator process memory only; generated at start |
| User uploads | `/var/lib/airgap/uploads`, deleted when the run ends; only SHA-256 kept in receipts |
| Host / VM | the Vultr Cloud Compute instance |

## Actors and assumptions
- **Untrusted:** uploaded CSV content (including cell text), the LLM's output (code *and* prose), anything the sandbox emits.
- **Assume breach of the model.** The Attack Lab runs the code a fully hijacked planner would write. The design must hold even when the model is malicious.
- **Trusted:** the orchestrator process, the Docker daemon, the host kernel. If these are compromised, receipts are meaningless.
- Out of scope: physical access, compromise of the Vultr control plane or the inference provider, and kernel/gVisor zero-days (see residual risks).

## Trust boundary
Control plane (trusted) ⟷ one throwaway container per run (untrusted code + untrusted data). The only channels across it:

| Channel | Direction | Bounding |
|---|---|---|
| `main.py`, `data.csv` | in | bind-mounted **read-only** at `/job` |
| stdout / stderr | out | streamed; truncated at 64 KB; decoded with `errors="replace"`; never interpreted as instructions |
| `/out/*.png` | out | size-capped tmpfs volume (8 MB); only regular files, name regex `^[A-Za-z0-9_.-]{1,64}\.png$`, PNG magic bytes, ≤5 files, ≤2 MB each, opened with `O_NOFOLLOW`; no SVG (XSS) |
| exit code, OOM flag, timing | out | read from `docker inspect`, not from the container |

## Threats and controls

| # | Threat | Control | Verify |
|---|---|---|---|
| T1 | Prompt injection in a CSV cell makes the model exfiltrate data | Model has no tools and no network. Code runs in a sandbox with `network=none`. Cell text is passed to the planner marked as untrusted data and the explainer never sees raw cells | `EXFIL-HTTP`, `METADATA-SSRF`, `DNS-EXFIL` cartridges |
| T2 | Sandbox reaches cloud metadata / internal services | No interface other than `lo` | `METADATA-SSRF` → `ENETUNREACH` captured inside the sandbox |
| T3 | Secret theft from the sandbox environment | No secret is ever passed in; the key, signing key and canary exist only in the orchestrator | `SECRET-HARVEST` (env + `/proc/1/environ` keys ⊆ allowlist, canary absent in outputs) |
| T4 | Resource exhaustion (fork/memory/CPU) | `pids_limit`, `mem_limit` = `memswap_limit`, `nano_cpus`, 20 s wall-clock kill, 2-slot semaphore | `RESOURCE-BOMB` → `oom_killed=true`, exit 137 |
| T5 | Container escape / host tampering | gVisor `runsc` (user-space kernel), read-only rootfs, `cap-drop ALL`, `no-new-privileges`, non-root `65534`, no Docker socket in the container | `HOST-ESCAPE` (7 attempts all blocked) |
| T6 | Persisting state between runs | Fresh container and tmpfs volume per run; both removed; removal verified (`NotFound`); host job dir deleted | `destroyed_verified` in each receipt |
| T7 | Malicious file output attacks the browser/host | Output allowlist above; answers rendered as escaped text; no raw HTML | `web/app.js` `esc()`; no `innerHTML` of unescaped model text |
| T8 | Model lies about numbers | **Number Guard** requires each number in the answer to appear in real stdout | red highlighting + receipt `number_guard` |
| T9 | Receipt forged or edited after issuance | Ed25519 signature over canonical JSON; SHA-256 hash chain in an append-only ledger; browser-side verification | Tamper test; `tests/verify_canon.mjs` |
| T10 | Abuse of the public demo | Per-IP rate limit (12 runs / 10 min), 5 MB upload cap, row cap, 2 concurrent sandboxes, 90 s LLM timeout | `server/main.py` |
| T11 | Containment silently broken on a host | Boot self-test runs two cartridges; **fails closed** (HTTP 503 on `/api/run`) | `GET /healthz` |
| T12 | Crash leaves orphaned containers | Startup sweep removes containers/volumes labelled `airgap=1` | `swept_orphans` in `/healthz` |

## Residual risks (what could still go wrong)

1. **`docker.sock` is root-equivalent and the internet-facing process holds it.** An RCE in the FastAPI app or its dependencies is host compromise. Mitigations in place: no user-controlled Docker arguments; the sandbox never sees the socket. Next step: a small broker process on a unix socket exposing one `run(job)` call, or a dedicated sandbox VM reached over SSH so the web tier holds nothing.
2. **gVisor is not a hardware boundary.** It reduces the host-kernel attack surface but a sentry/kernel bug could still allow escape. This VM has no `/dev/kvm`, so microVMs (Firecracker/Microsandbox) weren't available.
3. **The signature is not attestation.** The same host issues the measurements and the signature. A compromised orchestrator can sign false receipts. Production path: signing key in a KMS/HSM, receipts published to a transparency log, and a confidential VM with remote attestation.
4. **Single signing key, no rotation or revocation.** Losing the key invalidates trust in past receipts.
5. **Canary is a witness, not proof.** With `network=none`, zero listener hits is guaranteed by construction. The stronger evidence is the error raised *inside* the sandbox and the observed policy.
6. **Number Guard checks provenance of numbers, not correctness of logic.** A wrong script that faithfully prints wrong figures passes. It also can miss claims phrased without numbers.
7. **Pids limit is 256.** gVisor's own threads count against the cgroup and a limit of 64 crashes it, so fork storms are bounded by memory rather than by a tight pids cap.
8. **Public base-image variables** (e.g. `GPG_KEY` from `python:3.12-slim`) are visible in the sandbox; they are not secrets and are allowlisted in the secret-harvest check.
9. **Side channels and timing** (CPU, cache, wall-time) are not addressed.
10. **Availability:** the demo is single-VM, single-worker, with in-memory run state. A restart loses in-flight runs; receipts persist.
11. **LLM provider trust:** uploaded data summaries (schema and five sample rows) are sent to Vultr Serverless Inference as part of the planner prompt. Don't upload sensitive data to the public demo.

## Not claimed
Airgap does not claim to be "unhackable", does not reproduce any vendor's exact exploit, and does not provide hardware-backed attestation.
