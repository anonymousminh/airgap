"use strict";
/* Airgap workspace. Shared helpers ($, esc, toast, verifyAll, icon, store…) come from /shared.js. */

/* ---------- routing ---------- */
const VIEWS = { analyst: ["Analyst", "Ask a question about a spreadsheet and get an answer you can audit."], lab: ["Attack Lab", ""], ledger: ["Ledger", ""] };
function route() {
  const v = (location.hash.match(/^#\/(\w+)/) || [])[1]; const view = VIEWS[v] ? v : "analyst";
  $$(".view").forEach(s => s.hidden = s.id !== "view-" + view);
  $$(".snav a").forEach(a => a.classList.toggle("on", a.dataset.view === view));
  $("#viewTitle").textContent = VIEWS[view][0]; $("#viewSub").textContent = VIEWS[view][1];
  document.title = `${VIEWS[view][0]} — Airgap`;
  if (view === "ledger") loadLedger();
}
addEventListener("hashchange", route);

/* ---------- receipt certificate ---------- */
let currentReceipt = null;
const SEAL = ok => `<svg viewBox="0 0 120 120" aria-hidden="true"><defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${ok ? "#3ddc97" : "#fb7185"}"/><stop offset="1" stop-color="${ok ? "#9af2c8" : "#fda4af"}"/></linearGradient></defs>
  <circle cx="60" cy="60" r="56" fill="rgba(61,220,151,.06)" stroke="url(#sg)" stroke-width="2" stroke-dasharray="3 5"/>
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
    </div></div>`;
  $(".verify1", into).onclick = async () => {
    const v = await verifyAll(r), el = $(".vr", into), chain = v.server ? (v.server.chain_ok ? " · chain intact" : " · chain BROKEN") : "";
    el.className = "vr verdict " + (v.ok ? "ok" : "bad");
    el.textContent = v.ok ? `✔ signature valid (checked ${v.where})${chain}` : `✖ SIGNATURE INVALID (checked ${v.where})`;
  };
  $(".tamper1", into).onclick = () => openTamper(r);
}

/* ---------- verification drawer ---------- */
function setStamp(v) {
  const st = $("#stamp"), el = $("#verifyResult");
  if (!v) { st.hidden = true; el.textContent = ""; el.className = "verdict"; return; }
  st.hidden = false; st.className = "stamp " + (v.ok ? "ok" : "bad"); st.textContent = v.ok ? "VERIFIED" : "TAMPERED";
  const chain = v.server && v.ok ? (v.server.chain_ok ? " · chain intact" : " · chain broken") : "";
  el.className = "verdict " + (v.ok ? "ok" : "bad");
  el.textContent = v.ok ? `Signature valid (checked ${v.where})${chain}` : `Signature does NOT match the contents (checked ${v.where}). The receipt was altered after it was issued.`;
}
function openTamper(r) {
  currentReceipt = r || null; $("#tamperText").value = r ? JSON.stringify(r, null, 2) : ""; setStamp(null);
  $("#tamper").classList.add("open"); $("#tamper").setAttribute("aria-hidden", "false"); $("#scrim").hidden = false;
}
function closeTamper() { $("#tamper").classList.remove("open"); $("#tamper").setAttribute("aria-hidden", "true"); $("#scrim").hidden = true; }
$("#closeTamper").onclick = closeTamper; $("#scrim").onclick = closeTamper;
addEventListener("keydown", e => { if (e.key === "Escape") closeTamper(); });
$("#resetTamper").onclick = () => currentReceipt && openTamper(currentReceipt);
$("#verifyBtn").onclick = async () => {
  let r; try { r = JSON.parse($("#tamperText").value); } catch { return setStamp({ ok: false, where: "— not valid JSON" }); }
  if (!r.signature_ed25519) return setStamp({ ok: false, where: "— no signature field" });
  setStamp(await verifyAll(r));
};
$("#dlReceipt").onclick = () => {
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([$("#tamperText").value], { type: "application/json" }));
  a.download = `${(currentReceipt && currentReceipt.run_id) || "receipt"}.json`; a.click();
};

/* ---------- history (browser-local convenience only) ---------- */
const HKEY = "airgap.history.v1"; let activeHist = null;
function history() { return store.get(HKEY, []); }
function addHistory(item) { store.set(HKEY, [item, ...history().filter(h => h.id !== item.id)].slice(0, 20)); renderHistory(); }
function ago(ts) { const s = (Date.now() - ts) / 1000; return s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + "m ago" : s < 86400 ? Math.floor(s / 3600) + "h ago" : Math.floor(s / 86400) + "d ago"; }
function renderHistory() {
  const h = history(); $("#histEmpty").hidden = h.length > 0; $("#clearHist").hidden = h.length === 0;
  $("#history").innerHTML = h.map(i => `<li><button data-id="${esc(i.id)}" class="${i.id === activeHist ? "on" : ""}"><span class="q">${esc(i.q)}</span><span class="m">${esc(i.id)} · ${ago(i.ts)}</span></button></li>`).join("");
  $$("#history button").forEach(b => b.onclick = () => openHistory(b.dataset.id));
}
$("#clearHist").onclick = () => { store.set(HKEY, []); activeHist = null; renderHistory(); };
async function openHistory(id) {
  const it = history().find(h => h.id === id); if (!it) return;
  location.hash = "#/analyst"; activeHist = id; renderHistory();
  $("#question").value = it.q; showAnswer(it.answer, it.numbers, null); $("#code").textContent = it.code || "";
  $("#stdout").textContent = it.stdout || ""; resetSteps(true);
  $("#receiptView").innerHTML = '<p class="hint">Loading receipt from the ledger…</p>'; $("#rcDot").hidden = true;
  try { const r = await (await fetch(`/api/receipts/${id}`)).json(); renderReceipt(r, $("#receiptView")); $("#rcDot").hidden = false; }
  catch { $("#receiptView").innerHTML = '<p class="hint">Could not load this receipt.</p>'; }
}

/* ---------- dataset + preview ---------- */
const SUSPICIOUS = /ignore (all |any )?(previous|prior) instructions|system prompt|exfiltrat|send (this|the|all|every)\b.{0,60}(to|http)|https?:\/\//i;
function parseLine(l) {
  const out = []; let cur = "", q = false;
  for (let i = 0; i < l.length; i++) { const c = l[i];
    if (q) { if (c === '"') { if (l[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c; }
  out.push(cur); return out;
}
async function showPreview(file) {
  const box = $("#preview");
  try {
    const text = (await file.slice(0, 300000).text()).replace(/^﻿/, "");
    const lines = text.split(/\r?\n/).filter(Boolean).slice(0, 2000); if (!lines.length) throw 0;
    const head = parseLine(lines[0]), rows = lines.slice(1).map(parseLine);
    const sus = rows.reduce((n, r) => n + r.filter(c => SUSPICIOUS.test(c)).length, 0);
    box.hidden = false;
    box.innerHTML = `<div class="pv-h"><span>${head.length} columns · preview of first ${Math.min(6, rows.length)} rows</span>${sus ? `<span class="pv-warn">⚠ ${sus} suspicious cell${sus > 1 ? "s" : ""} — treated as data, never as instructions</span>` : `<span>no injection patterns spotted</span>`}</div>
      <div class="pv-scroll"><table><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.slice(0, 6).map(r => `<tr>${head.map((_, i) => { const v = r[i] ?? ""; return `<td class="${SUSPICIOUS.test(v) ? "sus" : ""}" title="${esc(v)}">${esc(v)}</td>`; }).join("")}</tr>`).join("")}</tbody></table></div>`;
  } catch { box.hidden = true; }
}
let chosen = null;
function setFile(f, label, demo) {
  chosen = f; $("#fileName").textContent = label || f.name; $("#drop").classList.toggle("has", !demo);
  $("#useDemo").classList.toggle("on", !!demo); showPreview(f);
}
$("#file").onchange = () => $("#file").files[0] && setFile($("#file").files[0]);
["dragenter", "dragover"].forEach(t => $("#drop").addEventListener(t, e => { e.preventDefault(); $("#drop").classList.add("over"); }));
["dragleave", "drop"].forEach(t => $("#drop").addEventListener(t, e => { e.preventDefault(); $("#drop").classList.remove("over"); }));
$("#drop").addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) setFile(f); });
async function loadDemo() {
  const blob = await (await fetch("/demo/sales_q3.csv")).blob();
  setFile(new File([blob], "sales_q3.csv", { type: "text/csv" }), "Choose a different CSV…", true);
  if (!$("#question").value.trim()) $("#question").value = SUGGEST[0];
}
$("#useDemo").onclick = loadDemo;
const SUGGEST = ["Which region had the biggest Q3 revenue drop vs Q2, and by how much?", "Which product grew the most from Q2 to Q3?", "What was total Q3 revenue by region?"];
$("#suggest").innerHTML = SUGGEST.map((s, i) => `<button type="button" data-i="${i}">${esc(s.replace(/, and by how much\?$/, "?"))}</button>`).join("");
$$("#suggest button").forEach(b => b.onclick = () => { $("#question").value = SUGGEST[+b.dataset.i]; $("#question").focus(); });

/* ---------- run ---------- */
const STAGES = ["PROFILE", "PLAN", "DISPATCH", "EXECUTE", "VERIFY", "DESTROY", "SIGN"];
let es = null, timer = null, firstOut = true;
function resetSteps(allDone) {
  $("#timeline").innerHTML = STAGES.map(s => `<li data-s="${s}" class="${allDone ? "done" : ""}"><i></i><span>${s}</span></li>`).join("");
  $("#timeline").style.setProperty("--p", allDone ? "1" : "0"); $("#elapsed").textContent = "";
}
function setProgress(stage, status) {
  const i = STAGES.indexOf(stage); if (i < 0) return;
  $("#timeline").style.setProperty("--p", String(Math.min(1, i / (STAGES.length - 1)) + (status === "done" && i === STAGES.length - 1 ? 0 : 0)));
}
function showTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("on", t.dataset.tab === name));
  $$(".pane").forEach(p => p.hidden = p.id !== "pane-" + name);
  $("#resultEmpty").hidden = true;
}
$$(".tab").forEach(t => t.onclick = () => showTab(t.dataset.tab));
function highlight(text, numbers) {
  let out = "", cur = 0;
  for (const n of numbers || []) { const i = text.indexOf(n.value, cur); if (i < 0) continue;
    out += esc(text.slice(cur, i)) + `<span class="num ${n.matched ? "ok" : "bad"}">${esc(n.value)}</span>`; cur = i + n.value.length; }
  return (out + esc(text.slice(cur))).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\n/g, "<br>");
}
function showAnswer(text, numbers) {
  showTab("answer"); $("#answer").innerHTML = highlight(text, numbers);
  const tot = (numbers || []).length, ok = (numbers || []).filter(n => n.matched).length, g = $("#guardChip");
  g.className = "guard " + (ok === tot ? "ok" : "bad"); g.textContent = tot ? `${ok}/${tot} numbers verified against sandbox output` : "no figures to verify";
}
function resetResult() {
  $$(".pane").forEach(p => p.hidden = true); $("#resultEmpty").hidden = false; $$(".tab").forEach(t => t.classList.toggle("on", t.dataset.tab === "answer"));
  $("#charts").innerHTML = ""; $("#code").textContent = ""; $("#receiptView").innerHTML = ""; $("#rcDot").hidden = true;
  $("#stdout").innerHTML = '<span class="mute">$ waiting for a question…</span>';
}
$("#runForm").onsubmit = async ev => {
  ev.preventDefault();
  const q = $("#question").value.trim();
  if (!chosen) return toast("Choose a CSV or use the demo dataset first.");
  if (!q) return toast("Type a question first.");
  location.hash = "#/analyst"; activeHist = null; resetResult(); resetSteps(false); firstOut = true;
  let codeTxt = "", outTxt = "", answerTxt = "", nums = [];
  $("#runBtn").disabled = true; fxBeam(true);
  const t0 = performance.now(); clearInterval(timer);
  timer = setInterval(() => $("#elapsed").textContent = ((performance.now() - t0) / 1000).toFixed(1) + "s", 100);
  const fd = new FormData(); fd.append("file", chosen); fd.append("question", q);
  let res; try { res = await fetch("/api/run", { method: "POST", body: fd }); } catch { return fail("Network error — is the server reachable?"); }
  if (!res.ok) return fail((await res.json().catch(() => ({}))).detail || res.statusText);
  const { run_id } = await res.json();
  es = new EventSource(`/api/run/${run_id}/events`);
  const on = (t, f) => es.addEventListener(t, e => f(JSON.parse(e.data)));
  on("stage", e => { fxStage(e.stage, e.status); const li = $(`#timeline li[data-s="${e.stage}"]`); if (li) li.className = e.status; setProgress(e.stage, e.status); });
  on("code", e => { codeTxt = e.code; $("#code").textContent = e.code; $("#stdout").textContent = ""; outTxt = ""; firstOut = false; });
  on("stdout", e => { if (firstOut) { $("#stdout").textContent = ""; firstOut = false; } outTxt += "$ " + e.text + "\n"; $("#stdout").textContent = outTxt; $("#stdout").scrollTop = 1e6; });
  on("retry", e => { $("#stdout").textContent += `! attempt ${e.attempt} failed — asking the planner to fix it\n`; });
  on("charts", e => { $("#charts").innerHTML = e.files.map(f => `<img alt="Chart produced inside the sandbox" src="data:image/png;base64,${f.b64}">`).join(""); });
  on("answer", e => { answerTxt = e.text; nums = e.numbers; showAnswer(e.text, e.numbers); });
  on("receipt", e => {
    renderReceipt(e.receipt, $("#receiptView")); $("#rcDot").hidden = false; finish();
    activeHist = run_id; addHistory({ id: run_id, q, ts: Date.now(), answer: answerTxt, numbers: nums, code: codeTxt, stdout: outTxt });
    if (!$("#view-ledger").hidden) loadLedger();
  });
  on("error", e => fail(e.message));
  es.onerror = () => { if (es && es.readyState === 2) finish(); };
};
function finish() { fxBeam(false); fxIdle(); if (es) es.close(); es = null; clearInterval(timer); $("#runBtn").disabled = false; }
function fail(msg) { finish(); toast(msg); showTab("answer"); $("#answer").innerHTML = `<span class="num bad">Run failed</span> ${esc(msg)}`; $("#guardChip").textContent = ""; $("#guardChip").className = "guard"; }

/* ---------- attack lab ---------- */
let attacks = [], results = {};
(async function loadAttacks() {
  try { attacks = await (await fetch("/api/attacks")).json(); } catch { return toast("Could not load attack cartridges."); }
  $("#tiles").innerHTML = attacks.map(a => `
    <div class="tile glow" id="t-${a.id}"><i class="scan"></i>
      <div class="tile-h"><span class="ico">${icon(a.id)}</span><div><h3>${esc(a.id)}</h3><span class="nm">${esc(a.name)}</span></div><span class="badge">READY</span></div>
      <p><b>Tries:</b> ${esc(a.tries)}</p><p><b>Stopped by:</b> ${esc(a.stops)}</p>
      <div class="extra"></div><div class="ev" hidden></div>
      <div class="tile-btns"><button class="btn ghost peek">Show poisoned CSV + payload</button><button class="btn ghost rcpt" hidden>View signed receipt</button></div>
      <pre hidden>${esc("# poisoned CSV (what the attacker planted)\n" + a.poisoned_csv + "\n# payload a hijacked model would write\n" + a.payload)}</pre>
    </div>`).join("");
  attacks.forEach(a => { const t = $("#t-" + a.id);
    $(".peek", t).onclick = () => { const p = $("pre", t); p.hidden = !p.hidden; };
    $(".rcpt", t).onclick = () => openTamper(results[a.id].receipt); });
})();
async function runAttack(a) {
  const t = $("#t-" + a.id); t.className = "tile glow running"; $(".badge", t).textContent = "ATTACKING…"; $(".extra", t).innerHTML = ""; $(".ev", t).hidden = true;
  let r;
  try { const res = await fetch(`/api/attacks/${a.id}/run`, { method: "POST" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText); r = await res.json(); }
  catch (e) { t.className = "tile glow failed"; $(".badge", t).textContent = "ERROR"; toast(e.message); return; }
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
  const n = Object.values(results).filter(r => r.contained).length, have = Object.keys(results).length;
  setScore($("#sbContained"), `${n} / ${attacks.length}`, have && n < have);
  const net = ["EXFIL-HTTP", "METADATA-SSRF", "DNS-EXFIL"], haveNet = net.every(id => results[id]), netOk = haveNet && net.every(id => results[id].contained);
  setScore($("#sbBytes"), haveNet ? (netOk ? "0" : "≥ 1") : "–", haveNet && !netOk);
  const s = results["SECRET-HARVEST"]; setScore($("#sbSecrets"), s ? (s.contained ? "0" : "≥ 1") : "–", s && !s.contained);
}
$("#runAll").onclick = async () => {
  $("#runAll").disabled = true; results = {};
  attacks.forEach(a => { const t = $("#t-" + a.id); t.className = "tile glow"; $(".badge", t).textContent = "QUEUED"; $(".ev", t).hidden = true; $(".extra", t).innerHTML = ""; $(".rcpt", t).hidden = true; });
  scoreboard(); for (const a of attacks) await runAttack(a);
  $("#runAll").disabled = false;
};

/* ---------- ledger ---------- */
async function loadLedger() {
  try {
    const [head, rec] = await Promise.all([fetch("/api/ledger/head").then(r => r.json()), fetch("/api/ledger/recent?limit=14").then(r => r.json())]);
    $("#ledgerHead").textContent = head.hash ? `#${head.seq} · ${head.hash.slice(0, 30)}…` : "empty";
    $("#chain").innerHTML = rec.map(b => {
      const bad = b.outcome === "NOT_CONTAINED", label = b.kind === "attack" ? (b.attack_id || "attack") : "analysis";
      return `<li class="${bad ? "bad" : ""}"><button class="blk" data-id="${esc(b.run_id)}"><span class="sq">#${b.seq}</span>
        <span class="t">${esc(label)}<span class="kind ${bad ? "bad" : "ok"}">${b.kind === "attack" ? (bad ? "NOT CONTAINED" : "CONTAINED") : "SIGNED"}</span><small>${esc(b.run_id)} · ${esc(b.issued_at || "")}</small></span>
        <span class="h"><b>${esc(b.hash.slice(0, 22))}…</b><br>← ${esc(String(b.prev_hash).slice(0, 18))}…</span></button></li>`;
    }).join("");
    $$("#chain .blk").forEach(b => b.onclick = async () => {
      try { openTamper(await (await fetch(`/api/receipts/${b.dataset.id}`)).json()); } catch { toast("Could not load that receipt."); }
    });
  } catch { toast("Could not load the ledger."); }
}
$("#refreshLedger").onclick = loadLedger; $("#pasteReceipt").onclick = () => openTamper(null);

/* ---------- init ---------- */
resetResult(); resetSteps(false); renderHistory(); route(); fxIdle();

/* ---------- libraries.dev components (MIT): border-beam, thinking-orbs, bot-avatars. All optional. ---------- */
function fx(fn) { try { if (window.AirgapFX) fn(window.AirgapFX); else addEventListener("load", () => window.AirgapFX && fn(window.AirgapFX), { once: true }); } catch (e) { /* app works without the effects */ } }
const ORB = { PROFILE: "searching", PLAN: "solving", DISPATCH: "connecting", EXECUTE: "working", VERIFY: "composing", DESTROY: "breathing", SIGN: "breathing" };
function fxIdle() { fx(F => { F.orb($("#runOrb"), { state: "breathing", size: 32, theme: "light" }); F.bot($("#botPlan"), { type: "clover", size: 32, state: "sleeping" }); F.bot($("#botExp"), { type: "ghost", size: 32, state: "sleeping" }); F.beam($("#composerBeam"), { active: false, radius: 24 }); }); }
function fxStage(stage, status) {
  if (status !== "start") return;
  fx(F => { F.orb($("#runOrb"), { state: ORB[stage] || "working", size: 32, theme: "light" });
    F.bot($("#botPlan"), { type: "clover", size: 32, state: stage === "PLAN" ? "working" : "sleeping" });
    F.bot($("#botExp"), { type: "ghost", size: 32, state: stage === "VERIFY" ? "working" : "sleeping" }); });
}
function fxBeam(active) { fx(F => F.beam($("#composerBeam"), { active, radius: 24, duration: 2.2, strength: 0.9, theme: "light" })); }
