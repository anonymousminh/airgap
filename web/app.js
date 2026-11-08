"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

function toast(msg) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = msg;
  $("#toasts").append(t); setTimeout(() => t.remove(), 6000);
}

/* ---------- nav, scroll spy, pointer glow ---------- */
addEventListener("scroll", () => $("#nav").classList.toggle("scrolled", scrollY > 8), { passive: true });
const spy = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting) $$(".links a").forEach(a => a.classList.toggle("active", a.dataset.nav === e.target.dataset.sec));
}), { rootMargin: "-45% 0px -50% 0px" });
$$("[data-sec]").forEach(s => spy.observe(s));
document.addEventListener("pointermove", e => {
  const g = e.target.closest && e.target.closest(".glow");
  if (!g) return;
  const r = g.getBoundingClientRect();
  g.style.setProperty("--mx", (e.clientX - r.left) + "px"); g.style.setProperty("--my", (e.clientY - r.top) + "px");
}, { passive: true });

/* ---------- animated counters ---------- */
function countTo(el, to, suffix = "") {
  if (reduce || to === 0) { el.textContent = to + suffix; return; }
  const t0 = performance.now(), D = 1100;
  (function tick(t) {
    const p = Math.min(1, (t - t0) / D), v = Math.round(to * (1 - Math.pow(1 - p, 3)));
    el.textContent = v + suffix; if (p < 1) requestAnimationFrame(tick);
  })(t0);
}
const counted = new WeakSet();
const cio = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting && !counted.has(e.target)) { counted.add(e.target); countTo(e.target, +e.target.dataset.count, e.target.dataset.suffix || ""); }
}));
$$("[data-count]").forEach(el => cio.observe(el));
fetch("/api/ledger/head").then(r => r.json()).then(h => { const el = $("#statReceipts"); el.dataset.count = h.seq; if (counted.has(el)) countTo(el, h.seq); }).catch(() => {});

/* ---------- health ---------- */
async function health() {
  const el = $("#health"), label = $("span", el);
  try {
    const h = await (await fetch("/healthz")).json();
    label.textContent = h.status === "ok" ? `containment verified · ${h.runtime}` : h.status === "pending" ? "running self-test…" : "self-test failed";
    el.className = "status " + (h.status === "ok" ? "ok" : h.status === "pending" ? "" : "bad");
    if (h.status === "pending") setTimeout(health, 2000);
  } catch { label.textContent = "offline"; el.className = "status bad"; }
}
health();

/* ---------- canonical JSON + browser-side Ed25519 verification ---------- */
function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
let pubkeyPromise;
async function verifyInBrowser(receipt) {
  const { signature_ed25519, receipt_hash, ...body } = receipt;
  pubkeyPromise ||= fetch("/api/pubkey").then(r => r.json());
  const pk = await pubkeyPromise;
  try {
    const key = await crypto.subtle.importKey("raw", b64(pk.public_key_b64), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64(signature_ed25519), new TextEncoder().encode(canonical(body)));
  } catch (e) { return null; }
}
async function verifyAll(receipt) {
  let ok = await verifyInBrowser(receipt), where = "in your browser", server = null;
  try { server = await (await fetch("/api/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(receipt) })).json(); } catch {}
  if (ok === null) { ok = server ? server.signature_ok : false; where = "on the server (this browser lacks Ed25519)"; }
  return { ok, where, server };
}

/* ---------- receipt certificate ---------- */
let currentReceipt = null;
const SEAL = ok => `<svg viewBox="0 0 120 120" aria-hidden="true"><defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${ok ? "#2dd4bf" : "#fb7185"}"/><stop offset="1" stop-color="${ok ? "#7dd3fc" : "#fda4af"}"/></linearGradient></defs>
  <circle cx="60" cy="60" r="56" fill="rgba(45,212,191,.06)" stroke="url(#sg)" stroke-width="2" stroke-dasharray="3 5"/>
  <path d="M60 18l30 11v23c0 20-13 34-30 42-17-8-30-22-30-42V29z" fill="rgba(255,255,255,.04)" stroke="url(#sg)" stroke-width="3.5" stroke-linejoin="round"/>
  ${ok ? '<path d="M44 60l12 12 21-24" fill="none" stroke="url(#sg)" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>' : '<path d="M46 46l28 28M74 46L46 74" stroke="url(#sg)" stroke-width="6" stroke-linecap="round"/>'}</svg>`;
function renderReceipt(r, into) {
  const c = r.containment || {}, p = (r.sandbox || {}).policy || {}, m = r.measured || {};
  const bad = !!(c.canary_hits_on_listener || c.canary_token_found_in_outputs || !c.destroyed_verified);
  const rows = [
    ["run", `${r.run_id} · ${r.kind}`], ["issued", r.issued_at],
    ["runtime", `${(r.sandbox || {}).runtime} · ${String((r.sandbox || {}).image_digest || "").slice(0, 19)}…`],
    ["network", p.network], ["rootfs read-only", p.read_only], ["capabilities dropped", (p.cap_drop || []).join(",")],
    ["no-new-privileges", p.no_new_privileges], ["user", p.user],
    ["limits", `pids ${p.pids_limit} · mem ${p.memory_mb} MB · cpu ${p.cpu_millis}m · wall ${p.wall_timeout_s}s`],
    ["measured", `wall ${m.wall_ms} ms · exit ${m.exit_code} · oom_killed ${m.oom_killed} · timed_out ${m.timed_out}`],
    ["sandbox runs destroyed", `${c.sandbox_runs} (verified gone: ${c.destroyed_verified})`],
    ["canary token in outputs", c.canary_token_found_in_outputs], ["secrets given to sandbox", c.secrets_provided_to_sandbox],
  ];
  if (r.number_guard) rows.push(["number guard", `${r.number_guard.matched_in_stdout}/${r.number_guard.numbers_in_answer} matched`]);
  if (r.models) rows.push(["models", `${r.models.planner} → ${r.models.explainer} · ${r.models.tokens_in}/${r.models.tokens_out} tok`]);
  if (c.evidence) rows.push(["evidence", c.evidence]);
  rows.push(["prev receipt", String(r.prev_receipt_hash).slice(0, 34)], ["receipt hash", String(r.receipt_hash).slice(0, 34)]);
  into.innerHTML = `<div class="cert">
    <div class="seal-col">
      <div class="seal ${bad ? "bad" : ""}">${SEAL(!bad)}</div>
      <div class="radius ${bad ? "bad" : ""}">${bad ? "!" : "0"}</div><div class="rl">blast radius</div>
      <div class="mini">
        <div><b>${c.canary_hits_on_listener ?? "–"}</b><span>canary hits</span></div>
        <div><b>${c.secrets_provided_to_sandbox ?? "–"}</b><span>secrets in sandbox</span></div>
        <div><b class="${c.destroyed_verified ? "" : "bad"}">${c.destroyed_verified ? "gone" : "LEFT"}</b><span>container</span></div>
        <div><b>${esc(p.network)}</b><span>network</span></div>
      </div>
    </div>
    <div>
      <table class="kv">${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table>
      <p class="sig">Ed25519 · ${esc(r.signature_ed25519)}</p>
      <div class="row" style="margin-top:12px"><button class="btn primary sm verify1">Verify signature</button><button class="btn ghost sm tamper1">Try to tamper with it…</button><span class="vr verdict"></span></div>
      <details><summary>Raw receipt JSON</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>
    </div></div>`;
  $(".verify1", into).onclick = async () => {
    const v = await verifyAll(r), el = $(".vr", into), chain = v.server ? (v.server.chain_ok ? " · chain intact" : " · chain BROKEN") : "";
    el.className = "vr verdict " + (v.ok ? "ok" : "bad");
    el.textContent = v.ok ? `✔ signature valid (checked ${v.where})${chain}` : `✖ SIGNATURE INVALID (checked ${v.where})`;
  };
  $(".tamper1", into).onclick = () => openTamper(r);
}

/* ---------- tamper drawer ---------- */
function setStamp(v) {
  const st = $("#stamp"), el = $("#verifyResult");
  if (!v) { st.hidden = true; el.textContent = ""; el.className = "verdict"; return; }
  st.hidden = false; st.className = "stamp " + (v.ok ? "ok" : "bad"); st.textContent = v.ok ? "VERIFIED" : "TAMPERED";
  const chain = v.server && v.ok ? (v.server.chain_ok ? " · chain intact" : " · chain broken") : "";
  el.className = "verdict " + (v.ok ? "ok" : "bad");
  el.textContent = v.ok ? `Signature valid (checked ${v.where})${chain}` : `Signature does NOT match the contents (checked ${v.where}). The receipt was altered after it was issued.`;
}
function openTamper(r) {
  currentReceipt = r; $("#tamperText").value = JSON.stringify(r, null, 2); setStamp(null);
  $("#tamper").classList.add("open"); $("#tamper").setAttribute("aria-hidden", "false"); $("#scrim").hidden = false;
}
function closeTamper() { $("#tamper").classList.remove("open"); $("#tamper").setAttribute("aria-hidden", "true"); $("#scrim").hidden = true; }
$("#closeTamper").onclick = closeTamper; $("#scrim").onclick = closeTamper;
addEventListener("keydown", e => { if (e.key === "Escape") closeTamper(); });
$("#resetTamper").onclick = () => currentReceipt && openTamper(currentReceipt);
$("#verifyBtn").onclick = async () => {
  let r; try { r = JSON.parse($("#tamperText").value); } catch { return setStamp({ ok: false, where: "— not valid JSON" }); }
  setStamp(await verifyAll(r));
};
$("#dlReceipt").onclick = () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([$("#tamperText").value], { type: "application/json" }));
  a.download = `${(currentReceipt && currentReceipt.run_id) || "receipt"}.json`; a.click();
};

/* ---------- analyst ---------- */
const STAGES = ["PROFILE", "PLAN", "DISPATCH", "EXECUTE", "VERIFY", "DESTROY", "SIGN"];
let chosen = null, es = null, timer = null;
const fileEl = $("#file");
function setFile(f, label) { chosen = f; $("#fileName").textContent = label || f.name; $("#drop").classList.add("has"); }
fileEl.onchange = () => fileEl.files[0] && setFile(fileEl.files[0]);
["dragenter", "dragover"].forEach(t => $("#drop").addEventListener(t, e => { e.preventDefault(); $("#drop").classList.add("over"); }));
["dragleave", "drop"].forEach(t => $("#drop").addEventListener(t, e => { e.preventDefault(); $("#drop").classList.remove("over"); }));
$("#drop").addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) setFile(f); });
async function loadDemo() {
  const blob = await (await fetch("/demo/sales_q3.csv")).blob();
  setFile(new File([blob], "sales_q3.csv", { type: "text/csv" }), "sales_q3.csv · demo (contains a poisoned cell)");
  if (!$("#question").value.trim()) $("#question").value = "Which region had the biggest Q3 revenue drop vs Q2, and by how much?";
}
$("#useDemo").onclick = async () => { await loadDemo(); $("#runForm").requestSubmit(); };
$("#heroDemo").addEventListener("click", loadDemo);
function setProgress(stage, status) {
  const i = STAGES.indexOf(stage); if (i < 0) return;
  $("#timeline").style.setProperty("--p", String(Math.min(1, (status === "done" ? i : Math.max(0, i - 0.0)) / (STAGES.length - 1))));
}
function resetRun() {
  $("#timeline").innerHTML = STAGES.map(s => `<li data-s="${s}"><i></i><span>${s}</span></li>`).join("");
  $("#timeline").style.setProperty("--p", "0");
  ["#answerCard", "#receiptCard", "#codeBox"].forEach(s => $(s).hidden = true);
  $("#stdout").innerHTML = '<span class="mute">$ waiting for a question…</span>'; $("#charts").innerHTML = ""; $("#elapsed").textContent = "";
}
function highlight(text, numbers) {
  let out = "", cur = 0;
  for (const n of numbers) {
    const i = text.indexOf(n.value, cur); if (i < 0) continue;
    out += esc(text.slice(cur, i)) + `<span class="num ${n.matched ? "ok" : "bad"}">${esc(n.value)}</span>`; cur = i + n.value.length;
  }
  return (out + esc(text.slice(cur))).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\n/g, "<br>");
}
let firstOut = true;
$("#runForm").onsubmit = async ev => {
  ev.preventDefault();
  const q = $("#question").value.trim();
  if (!chosen || !q) return toast("Choose a CSV (or press One-click demo) and type a question.");
  resetRun(); firstOut = true; $("#runBtn").disabled = $("#useDemo").disabled = true;
  const t0 = performance.now(); clearInterval(timer);
  timer = setInterval(() => $("#elapsed").textContent = ((performance.now() - t0) / 1000).toFixed(1) + "s", 100);
  const fd = new FormData(); fd.append("file", chosen); fd.append("question", q);
  let res; try { res = await fetch("/api/run", { method: "POST", body: fd }); } catch { return fail("Network error — is the server reachable?"); }
  if (!res.ok) return fail((await res.json().catch(() => ({}))).detail || res.statusText);
  const { run_id } = await res.json();
  es = new EventSource(`/api/run/${run_id}/events`);
  const on = (t, f) => es.addEventListener(t, e => f(JSON.parse(e.data)));
  on("stage", e => { const li = $(`#timeline li[data-s="${e.stage}"]`); if (li) li.className = e.status; setProgress(e.stage, e.status); });
  on("code", e => { $("#codeBox").hidden = false; $("#code").textContent = e.code; $("#stdout").textContent = ""; firstOut = false; });
  on("stdout", e => { if (firstOut) { $("#stdout").textContent = ""; firstOut = false; } $("#stdout").textContent += "$ " + e.text + "\n"; $("#stdout").scrollTop = 1e6; });
  on("retry", e => { $("#stdout").textContent += `! attempt ${e.attempt} failed — asking the planner to fix it\n`; });
  on("charts", e => { $("#charts").innerHTML = e.files.map(f => `<img alt="Chart produced inside the sandbox" src="data:image/png;base64,${f.b64}">`).join(""); });
  on("answer", e => {
    const c = $("#answerCard"); c.hidden = false; c.classList.remove("reveal"); void c.offsetWidth; c.classList.add("reveal");
    $("#answer").innerHTML = highlight(e.text, e.numbers);
    const tot = e.numbers.length, ok = e.numbers.filter(n => n.matched).length, g = $("#guardChip");
    g.className = "guard " + (ok === tot ? "ok" : "bad"); g.textContent = tot ? `${ok}/${tot} numbers verified against sandbox output` : "no figures to verify";
  });
  on("receipt", e => {
    const c = $("#receiptCard"); c.hidden = false; c.classList.remove("reveal"); void c.offsetWidth; c.classList.add("reveal");
    renderReceipt(e.receipt, $("#receiptView")); finish(); setTimeout(() => c.scrollIntoView({ behavior: "smooth", block: "center" }), 350);
  });
  on("error", e => fail(e.message));
  es.onerror = () => { if (es && es.readyState === 2) finish(); };
};
function finish() { if (es) es.close(); es = null; clearInterval(timer); $("#runBtn").disabled = $("#useDemo").disabled = false; }
function fail(msg) { finish(); toast(msg); const c = $("#answerCard"); c.hidden = false; $("#answer").innerHTML = `<span class="num bad">Run failed</span> ${esc(msg)}`; $("#guardChip").textContent = ""; $("#guardChip").className = "guard"; }
resetRun();

/* ---------- attack lab ---------- */
const ICONS = {
  "EXFIL-HTTP": '<path d="M7 17L17 7M9 7h8v8"/>',
  "METADATA-SSRF": '<path d="M7 18a4 4 0 010-8 5 5 0 019.6-1A4.500 4.500 0 0117 18H7z"/>',
  "DNS-EXFIL": '<path d="M5 12a7 7 0 0114 0M8 12a4 4 0 018 0M12 12h.01"/>',
  "SECRET-HARVEST": '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
  "RESOURCE-BOMB": '<path d="M12 3c1 4 5 5 5 10a5 5 0 01-10 0c0-2 1-3 2-4 0 2 1 3 2 3 0-3-1-5 1-9z"/>',
  "HOST-ESCAPE": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 017.5-2"/>',
};
const icon = id => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[id] || ""}</svg>`;
let attacks = [], results = {};
(async function loadAttacks() {
  try { attacks = await (await fetch("/api/attacks")).json(); } catch { return toast("Could not load attack cartridges."); }
  $("#tiles").innerHTML = attacks.map(a => `
    <div class="tile glow" id="t-${a.id}">
      <i class="scan"></i>
      <div class="tile-h"><span class="ico">${icon(a.id)}</span><div><h3>${esc(a.id)}</h3><span class="nm">${esc(a.name)}</span></div><span class="badge">READY</span></div>
      <p><b>Tries:</b> ${esc(a.tries)}</p><p><b>Stopped by:</b> ${esc(a.stops)}</p>
      <div class="extra"></div><div class="ev" hidden></div>
      <div class="tile-btns"><button class="btn ghost peek">Show poisoned CSV + payload</button><button class="btn ghost rcpt" hidden>View signed receipt</button></div>
      <pre hidden>${esc("# poisoned CSV (what the attacker planted)\n" + a.poisoned_csv + "\n# payload a hijacked model would write\n" + a.payload)}</pre>
    </div>`).join("");
  attacks.forEach(a => {
    const t = $("#t-" + a.id);
    $(".peek", t).onclick = () => { const p = $("pre", t); p.hidden = !p.hidden; };
    $(".rcpt", t).onclick = () => openTamper(results[a.id].receipt);
  });
})();
async function runAttack(a) {
  const t = $("#t-" + a.id); t.className = "tile glow running"; $(".badge", t).textContent = "ATTACKING…";
  $(".extra", t).innerHTML = ""; $(".ev", t).hidden = true;
  let r;
  try {
    const res = await fetch(`/api/attacks/${a.id}/run`, { method: "POST" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    r = await res.json();
  } catch (e) { t.className = "tile glow failed"; $(".badge", t).textContent = "ERROR"; toast(e.message); return; }
  results[a.id] = r;
  t.className = "tile glow flip " + (r.contained ? "contained" : "failed") + (a.id === "RESOURCE-BOMB" ? " bomb" : "");
  $(".badge", t).textContent = r.contained ? "✓ CONTAINED" : "✕ NOT CONTAINED";
  if (a.id === "RESOURCE-BOMB") {
    $(".extra", t).innerHTML = `<div class="meter"><div class="lbl"><span>memory cap 256 MB</span><span>${r.oom_killed ? "OOM-KILLED · exit " + r.exit_code : r.timed_out ? "KILLED at wall timeout" : "exit " + r.exit_code}</span></div><div class="bar kill"><i></i></div></div>`;
    requestAnimationFrame(() => requestAnimationFrame(() => { const i = $(".bar i", t); if (i) i.style.width = "100%"; }));
  }
  const ev = $(".ev", t); ev.hidden = false;
  ev.textContent = `${r.evidence}\nexit ${r.exit_code}${r.oom_killed ? " · oom_killed" : ""}${r.timed_out ? " · timed out" : ""} · ${r.wall_ms} ms · container destroyed ✔`;
  $(".rcpt", t).hidden = false; scoreboard();
}
function setScore(el, text, bad) { el.textContent = text; el.classList.toggle("bad", !!bad); }
function scoreboard() {
  const n = Object.values(results).filter(r => r.contained).length, total = attacks.length;
  setScore($("#sbContained"), `${n} / ${total}`, Object.keys(results).length && n < Object.keys(results).length);
  const net = ["EXFIL-HTTP", "METADATA-SSRF", "DNS-EXFIL"], haveNet = net.every(id => results[id]), netOk = haveNet && net.every(id => results[id].contained);
  setScore($("#sbBytes"), haveNet ? (netOk ? "0" : "≥ 1") : "–", haveNet && !netOk);
  const s = results["SECRET-HARVEST"];
  setScore($("#sbSecrets"), s ? (s.contained ? "0" : "≥ 1") : "–", s && !s.contained);
}
$("#runAll").onclick = async () => {
  $("#runAll").disabled = true; results = {};
  attacks.forEach(a => { const t = $("#t-" + a.id); t.className = "tile glow"; $(".badge", t).textContent = "QUEUED"; $(".ev", t).hidden = true; $(".extra", t).innerHTML = ""; $(".rcpt", t).hidden = true; });
  scoreboard();
  for (const a of attacks) await runAttack(a);
  $("#runAll").disabled = false;
};
