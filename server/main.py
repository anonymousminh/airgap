from __future__ import annotations
import asyncio, json, secrets, time, uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from runner.attacks import BY_ID, CARTRIDGES
from runner.docker_runner import DockerRunner
from . import settings
from .receipts import Ledger
from .runs import Run, run_analysis, run_attack


class Canary:
    """Host-side TCP listener used as a *witness*; token lives only in this process."""
    def __init__(self):
        self.token = "AIRGAP-CANARY-" + secrets.token_hex(12)
        self.hits = 0
        self.port = 0

    async def start(self):
        async def handle(r, w):
            self.hits += 1; w.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.port = srv.sockets[0].getsockname()[1]


state = {"selftest": "pending", "selftest_detail": []}
runs: dict[str, Run] = {}
hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request, cost: int = 1):
    ip = (request.headers.get("x-forwarded-for") or request.client.host).split(",")[0].strip()
    now, q = time.time(), hits[ip]
    while q and now - q[0] > settings.WINDOW_S: q.popleft()
    if len(q) + cost > settings.RUNS_PER_WINDOW:
        raise HTTPException(429, "Rate limit: too many runs, try again in a few minutes.")
    q.extend([now] * cost)


async def selftest(app):
    """Fail closed: if basic containment doesn't hold on this host, refuse to serve runs."""
    try:
        results = []
        for cid in ("EXFIL-HTTP", "RESOURCE-BOMB"):
            r = await run_attack(BY_ID[cid], app.state.runner, app.state.ledger, app.state.canary, app.state.sem)
            results.append({"id": cid, "contained": r["contained"]})
        state["selftest_detail"] = results
        state["selftest"] = "ok" if all(x["contained"] for x in results) else "FAILED"
    except Exception as e:
        state["selftest"] = "FAILED"; state["selftest_detail"] = [{"error": str(e)[:200]}]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    app.state.runner = DockerRunner()
    swept = app.state.runner.sweep()
    app.state.ledger = Ledger()
    app.state.canary = Canary(); await app.state.canary.start()
    app.state.sem = asyncio.Semaphore(settings.SANDBOX_SLOTS)
    state["swept"] = swept
    asyncio.create_task(selftest(app))
    yield


app = FastAPI(title="AIRGAP", lifespan=lifespan)


@app.get("/healthz")
async def healthz():
    return {"status": state["selftest"], "detail": state["selftest_detail"], "runtime": settings.RUNTIME,
            "swept_orphans": state.get("swept", 0), "ledger_head": app.state.ledger.head()}


@app.get("/api/pubkey")
async def pubkey():
    return {"alg": "Ed25519", "public_key_b64": app.state.ledger.pub_b64}


@app.get("/api/ledger/head")
async def ledger_head():
    return app.state.ledger.head()


@app.get("/api/attacks")
async def attacks():
    return [{"id": c.id, "name": c.name, "tries": c.tries, "stops": c.stops,
             "poisoned_csv": c.csv, "payload": c.code} for c in CARTRIDGES]


@app.post("/api/run")
async def start_run(request: Request, file: UploadFile = File(...), question: str = Form(...)):
    if state["selftest"] == "FAILED":
        raise HTTPException(503, "Containment self-test failed on this host; refusing to run (fail closed).")
    rate_limit(request)
    question = question.strip()
    if not question or len(question) > 500:
        raise HTTPException(400, "Question must be 1-500 characters.")
    data = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(data) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (max 5 MB).")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 text (CSV).")
    if text.count("\n") > settings.MAX_ROWS:
        raise HTTPException(400, f"Too many rows (max {settings.MAX_ROWS}).")
    path = settings.UPLOAD_DIR / f"{uuid.uuid4().hex}.csv"
    path.write_bytes(data)
    for k in [k for k, r in runs.items() if time.time() - r.created > 3600]: runs.pop(k, None)
    run = Run(asyncio.get_running_loop()); runs[run.id] = run
    asyncio.create_task(run_analysis(run, path, question, app.state.runner, app.state.ledger,
                                     app.state.canary, app.state.sem))
    return {"run_id": run.id}


@app.get("/api/run/{run_id}/events")
async def events(run_id: str, request: Request):
    run = runs.get(run_id)
    if not run: raise HTTPException(404, "unknown run")
    last = int(request.headers.get("last-event-id", "0") or 0)

    async def gen():
        i = last
        while True:
            while i < len(run.events):
                ev = run.events[i]; i += 1
                yield f"id: {ev['id']}\nevent: {ev['type']}\ndata: {json.dumps(ev)}\n\n"
            if run.done and i >= len(run.events): return
            async with run.cond:
                try: await asyncio.wait_for(run.cond.wait(), timeout=15)
                except asyncio.TimeoutError: yield ": keepalive\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/attacks/{attack_id}/run")
async def run_attack_ep(attack_id: str, request: Request):
    cart = BY_ID.get(attack_id)
    if not cart: raise HTTPException(404, "unknown attack")
    rate_limit(request)
    return await run_attack(cart, app.state.runner, app.state.ledger, app.state.canary, app.state.sem)


@app.get("/api/receipts/{run_id}")
async def get_receipt(run_id: str):
    r = app.state.ledger.get(run_id)
    if not r: raise HTTPException(404, "no receipt")
    return r


@app.post("/api/verify")
async def verify(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON")
    return app.state.ledger.verify(body)


web_dir = Path(__file__).resolve().parent.parent / "web"
if web_dir.exists():
    app.mount("/", StaticFiles(directory=web_dir, html=True), name="web")
