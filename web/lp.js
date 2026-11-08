"use strict";
/* Landing v3: attack scenes, switcher (real attacks), live receipt count. Uses shared.js helpers. */
fetch("/api/ledger/head").then(r => r.json()).then(h => { const el = $("#statReceipts"); if (el) countTo(el, h.seq); }).catch(() => {});

const SCENES = {
  "EXFIL-HTTP": `<svg viewBox="0 0 72 72"><rect x="6" y="28" width="14" height="16" rx="3" class="s-st"/><line x1="52" y1="10" x2="52" y2="62" class="s-wall"/><circle cx="26" cy="36" r="3" class="s-dot"/><circle cx="26" cy="36" r="3" class="s-dot d2"/><circle cx="26" cy="36" r="3" class="s-dot d3"/><path class="s-x sx" d="M58 31l8 10M66 31l-8 10"/></svg>`,
  "DNS-EXFIL": `<svg viewBox="0 0 72 72"><defs><clipPath id="cpx"><rect x="0" y="0" width="52" height="72"/></clipPath></defs><circle cx="22" cy="36" r="3.5" class="s-fill"/><g clip-path="url(#cpx)"><circle cx="22" cy="36" r="30" class="s-ring"/><circle cx="22" cy="36" r="30" class="s-ring r2"/><circle cx="22" cy="36" r="30" class="s-ring r3"/></g><line x1="52" y1="10" x2="52" y2="62" class="s-wall"/><path class="s-x sx" d="M58 31l8 10M66 31l-8 10"/></svg>`,
  "METADATA-SSRF": `<svg viewBox="0 0 72 72"><path class="s-st" d="M20 44a8 8 0 010-16 10 10 0 0119-2 9 9 0 011 18H20z"/><path class="s-dim" stroke-dasharray="3 4" d="M8 36h8"/><circle cx="8" cy="36" r="2.5" class="s-fill"/><line x1="46" y1="52" x2="46" y2="64" class="s-wall"/><path class="s-x sx" d="M40 54l12 8M52 54l-12 8"/></svg>`,
  "SECRET-HARVEST": `<svg viewBox="0 0 72 72"><g class="s-dim"><path d="M14 20h44M14 30h34M14 40h40M14 50h28"/></g><rect x="12" y="16" width="48" height="6" rx="3" class="s-scan"/><circle cx="60" cy="52" r="8" fill="#0b0b0b" stroke="#3ddc97" stroke-width="2"/><path d="M56 52l3 3 5-6" fill="none" stroke="#3ddc97" stroke-width="2" stroke-linecap="round"/></svg>`,
  "RESOURCE-BOMB": `<svg viewBox="0 0 72 72"><rect x="22" y="12" width="28" height="48" rx="4" class="s-st"/><line x1="18" y1="18" x2="54" y2="18" class="s-cap"/><rect x="27" y="17" width="18" height="38" rx="2" class="s-bar"/></svg>`,
  "HOST-ESCAPE": `<svg viewBox="0 0 72 72"><g class="s-lock"><rect x="19" y="32" width="34" height="26" rx="5" class="s-st"/><path class="s-st" d="M26 32v-7a10 10 0 0120 0v7"/><circle cx="36" cy="44" r="3" class="s-fill"/><path d="M36 47v5" stroke="#cfcfcf" stroke-width="2" stroke-linecap="round"/></g></svg>`,
};
const ORDER = ["EXFIL-HTTP", "DNS-EXFIL", "METADATA-SSRF", "SECRET-HARVEST", "RESOURCE-BOMB", "HOST-ESCAPE"];
const DESC = { "EXFIL-HTTP": "Tries to POST your uploaded CSV to an attacker’s server.", "DNS-EXFIL": "Hides your data inside a DNS lookup, the side channel reported against a major code interpreter.", "METADATA-SSRF": "Reaches for the cloud metadata address to steal credentials.", "SECRET-HARVEST": "Hunts env vars, keys and the Docker socket.", "RESOURCE-BOMB": "Forks hundreds of processes, then eats all memory.", "HOST-ESCAPE": "Tries to write /etc, setuid, mount and ptrace." };
$("#heroScene").innerHTML = SCENES["EXFIL-HTTP"];

let attacks = {}, results = {}, current = "EXFIL-HTTP", busy = false;
const beamHost = () => $("#panelBeam");
function beam(active) { if (window.AirgapFX) window.AirgapFX.beam(beamHost(), { active, radius: 24, duration: 2.2, strength: 0.95, theme: "dark" }); }
addEventListener("load", () => beam(false));
function score() {
  const n = Object.values(results).filter(r => r.contained).length, bad = Object.values(results).some(r => !r.contained);
  $("#scN").textContent = n; $("#galScore").classList.toggle("bad", bad);
}
function paint(id) {
  const r = results[id], it = $("#it-" + id), st = $(".it-s", it);
  it.classList.remove("done", "bad", "run");
  if (it.dataset.state === "run") { it.classList.add("run"); st.textContent = "ATTACKING…"; }
  else if (r) { it.classList.add(r.contained ? "done" : "bad"); st.textContent = r.contained ? "✓ CONTAINED" : "✕ NOT CONTAINED"; }
  else st.textContent = "READY";
}
function show(id) {
  current = id;
  $$(".it").forEach(x => x.classList.toggle("on", x.id === "it-" + id));
  const r = results[id], running = $("#it-" + id).dataset.state === "run";
  $("#pName").textContent = id; $("#pScene").innerHTML = SCENES[id]; $("#pScene").classList.toggle("dim", !!r && !running);
  const ps = $("#pStat"); ps.className = "pstat" + (running ? " run" : r ? (r.contained ? " ok" : " bad") : "");
  ps.textContent = running ? "ATTACKING…" : r ? (r.contained ? "✓ CONTAINED" : "✕ NOT CONTAINED") : "READY";
  $("#pEvid").textContent = r ? `${r.evidence}\nexit ${r.exit_code}${r.oom_killed ? " · oom_killed" : ""}${r.timed_out ? " · timed out" : ""} · ${r.wall_ms} ms · container destroyed ✔` : "Select an attack, then run it. You’ll see the real error raised inside the sandbox.";
  $(".pmeter") && $(".pmeter").remove();
  if (r && id === "RESOURCE-BOMB") {
    $("#pEvid").insertAdjacentHTML("beforebegin", `<div class="pmeter"><div class="lbl"><span>memory cap 256 MB</span><span>${r.oom_killed ? "OOM-KILLED · exit " + r.exit_code : "exit " + r.exit_code}</span></div><div class="bar"><i></i></div></div>`);
    requestAnimationFrame(() => requestAnimationFrame(() => { const i = $(".pmeter .bar i"); if (i) i.style.width = "100%"; }));
  }
  $("#pVerify").hidden = !r; $("#pVr").textContent = "";
  $("#pRun").textContent = r ? "Run again" : "Run this attack"; $("#pRun").disabled = busy;
}
async function runOne(id) {
  busy = true; const it = $("#it-" + id); it.dataset.state = "run"; paint(id); show(id); beam(true); $("#pRun").disabled = true;
  try {
    const res = await fetch(`/api/attacks/${id}/run`, { method: "POST" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    results[id] = await res.json();
  } catch (e) { toast(e.message); }
  it.dataset.state = ""; busy = false; beam(false); paint(id); score(); if (current === id) show(id);
}
(async function () {
  let list = []; try { list = await (await fetch("/api/attacks")).json(); } catch { return; }
  list.forEach(a => attacks[a.id] = a);
  $("#swList").innerHTML = ORDER.filter(id => attacks[id]).map(id => `<div class="it" id="it-${id}"><button class="it-h"><span class="it-ic">${icon(id)}</span>${esc(attacks[id].name)}<span class="it-s">READY</span></button><div class="it-b"><p>${esc(DESC[id])}</p><p><b>Stopped by:</b> ${esc(attacks[id].stops)}</p></div></div>`).join("");
  ORDER.forEach(id => $("#it-" + id + " .it-h").onclick = () => show(id));
  show("EXFIL-HTTP");
})();
$("#pRun").onclick = () => !busy && runOne(current);
$("#pVerify").onclick = async () => { const v = await verifyAll(results[current].receipt), el = $("#pVr"); el.className = "vr " + (v.ok ? "ok" : "bad"); el.textContent = v.ok ? `✔ signature valid (${v.where})` : `✖ invalid (${v.where})`; };
$("#runAll").onclick = async () => { if (busy) return; const b = $("#runAll"); b.disabled = true; results = {}; score(); ORDER.forEach(id => paint(id)); for (const id of ORDER) await runOne(id); b.disabled = false; };
