# lablab.ai submission copy — Airgap

Paste each block into the matching field. Limits on lablab's form were not verifiable; trim if a field is capped.

## Project title
Airgap — the AI data analyst that shows its receipts

## Short description
Upload a spreadsheet, ask a question. Airgap answers from inside a network-less sandbox and issues a signed Containment Receipt proving what the agent was never able to do — then lets you attack it live with six real-world exfiltration techniques.

## Long description

**The problem.** Teams in finance, healthcare, legal and operations want AI analysts, but their security teams block them. The fear is concrete: a poisoned cell in a spreadsheet can carry a prompt injection that turns a data-analysis agent into an exfiltration tool. Public incidents have involved code-interpreter style tools being steered into leaking uploaded files, and into bypassing sandbox network limits through DNS. "Trust us, it's sandboxed" isn't an answer a reviewer or auditor can check.

**What Airgap does.** You upload a CSV and ask a question in plain English. Airgap plans, runs and verifies the analysis, then hands back the answer together with a **Containment Receipt**: an Ed25519-signed, hash-chained record of what the sandbox looked like (re-read from `docker inspect`, not from our intent), what it measured, and proof the container was destroyed. Your browser verifies the signature itself. Edit one field of the receipt and verification fails.

**How it works.**
1. A fixed profiler script reads the CSV **inside** a sandbox; the control plane never parses untrusted bytes.
2. A coder model on **Vultr Serverless Inference** writes one Python script (planner `qwen3.8-27b`).
3. The script runs in a fresh, throwaway container: gVisor (`runsc`), `network=none`, read-only rootfs, all capabilities dropped, non-root, no-new-privileges, pids/memory/CPU/wall-clock caps. Only stdout and PNG files come back out.
4. A **different** model (`glm-5.3`) writes the answer from the real output only. **Number Guard** checks that every figure in the answer appears in the sandbox's actual stdout: green if matched, red if not.
5. The container is destroyed and verified gone, and the receipt is signed and chained.

The one rule: the LLM is called by the control plane and never from inside the sandbox. The sandbox has no network, no secrets and no Docker socket.

**The Attack Lab (the containment moment).** Assume the model is fully compromised. Six cartridges replay classes of attack against our own sandbox, live: HTTP exfiltration, cloud-metadata SSRF, DNS tunnelling, secret harvesting, a fork-and-memory bomb, and host-escape attempts. Each is judged from observed evidence — the error raised inside the sandbox, `oom_killed`/exit 137, canary scans — and each produces its own signed receipt. The fork/memory bomb is killed by its resource cap on camera. The service also fails closed: at boot it runs two cartridges and refuses to serve runs if containment doesn't hold.

**Built on Vultr.** Cloud Compute VM (control plane, sandbox host, public web app) and **Serverless Inference for every agent LLM call**, through the OpenAI-compatible endpoint.

**Honest about limits.** The signature proves a receipt wasn't altered after the orchestrator issued it; it is not hardware attestation. gVisor is a user-space kernel, not a microVM (this VM has no KVM). The orchestrator holds `docker.sock`. Attack payloads are the code a hijacked model would write, executed deterministically — classes of attack inspired by public incidents, not reproductions of any vendor's exploit. The full list is in `THREAT_MODEL.md`.

**Business value.** A per-answer evidence packet is something a security reviewer or auditor can actually check, which is the missing piece between "we built an AI analyst" and "we're allowed to deploy it". Next steps: signing key in a KMS, receipts in a transparency log, confidential VMs with remote attestation, and a dedicated sandbox host pool so the web tier holds no Docker socket.

## Architecture / use-case explanation (short form)
Browser → Caddy (TLS) → FastAPI orchestrator on a Vultr Cloud Compute VM (holds all secrets; calls Vultr Serverless Inference; runs Number Guard; signs receipts into a SQLite hash-chained ledger). Across a trust boundary (Docker socket), each run gets one throwaway gVisor container with no network, no secrets, read-only rootfs, dropped capabilities and resource caps; code and CSV go in read-only, stdout and PNGs come out. Lifecycle: UPLOAD → PROFILE → PLAN → DISPATCH → EXECUTE → VERIFY → DESTROY → SIGN.

## Tags
**Technologies:** Vultr Cloud Compute, Vultr Serverless Inference, gVisor, Docker, FastAPI, Python, Caddy, SQLite, Ed25519 (PyNaCl), WebCrypto, Qwen, GLM
**Categories:** AI agents, AI security, data analytics, sandboxing

## Links
- Public demo: https://96-30-195-46.sslip.io
- GitHub: https://github.com/anonymousminh/airgap
- Cover image: `assets/cover.png` (1280×720)
- Video: **TODO — add link after recording (must show a containment moment)**
- Slides: **TODO if the form requires them**

## Pre-submit checklist
- [ ] Fresh-browser test of the demo URL (incognito, not your own Chrome profile)
- [ ] Video recorded, uploaded, link added; shows the Attack Lab and the fork/memory bomb being killed
- [ ] Repo public, README renders, MIT LICENSE present
- [ ] Cover image uploaded
- [ ] Re-check the deadline on the lablab page (22:00 vs 23:00 UTC): submit with an hour to spare
- [ ] Public demo still shows "containment verified" in the header right before you submit
