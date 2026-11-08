"use strict";
/* Landing: floating attack-scene tiles, live attack gallery, filters, counters. */
fetch("/api/ledger/head").then(r => r.json()).then(h => { const el = $("#statReceipts"); el.dataset.count = h.seq; if (counted.has(el)) countTo(el, h.seq); }).catch(() => {});

/* ---- animated mini-scenes (72x72), reused for hero tiles and gallery previews ---- */
const SCENES = {
  "EXFIL-HTTP": `<svg viewBox="0 0 72 72"><rect x="6" y="28" width="14" height="16" rx="3" class="s-st"/><line x1="52" y1="10" x2="52" y2="62" class="s-wall"/><circle cx="26" cy="36" r="3" class="s-dot"/><circle cx="26" cy="36" r="3" class="s-dot d2"/><circle cx="26" cy="36" r="3" class="s-dot d3"/><path class="s-x sx" d="M58 31l8 10M66 31l-8 10"/></svg>`,
  "DNS-EXFIL": `<svg viewBox="0 0 72 72"><defs><clipPath id="cp"><rect x="0" y="0" width="52" height="72"/></clipPath></defs><circle cx="22" cy="36" r="3.5" class="s-fill"/><g clip-path="url(#cp)"><circle cx="22" cy="36" r="30" class="s-ring"/><circle cx="22" cy="36" r="30" class="s-ring r2"/><circle cx="22" cy="36" r="30" class="s-ring r3"/></g><line x1="52" y1="10" x2="52" y2="62" class="s-wall"/><path class="s-x sx" d="M58 31l8 10M66 31l-8 10"/></svg>`,
  "METADATA-SSRF": `<svg viewBox="0 0 72 72"><path class="s-st" d="M20 44a8 8 0 010-16 10 10 0 0119-2 9 9 0 011 18H20z"/><path class="s-dim" stroke-dasharray="3 4" d="M8 36h8"/><circle cx="8" cy="36" r="2.5" class="s-fill"/><line x1="46" y1="52" x2="46" y2="64" class="s-wall"/><path class="s-x sx" d="M40 54l12 8M52 54l-12 8"/></svg>`,
  "SECRET-HARVEST": `<svg viewBox="0 0 72 72"><g class="s-dim"><path d="M14 20h44M14 30h34M14 40h40M14 50h28"/></g><rect x="12" y="16" width="48" height="6" rx="3" class="s-scan"/><circle cx="60" cy="52" r="8" fill="#0b0b0b" stroke="#3ddc97" stroke-width="2"/><path d="M56 52l3 3 5-6" fill="none" stroke="#3ddc97" stroke-width="2" stroke-linecap="round"/></svg>`,
  "RESOURCE-BOMB": `<svg viewBox="0 0 72 72"><rect x="22" y="12" width="28" height="48" rx="4" class="s-st"/><line x1="18" y1="18" x2="54" y2="18" class="s-cap"/><rect x="27" y="17" width="18" height="38" rx="2" class="s-bar"/></svg>`,
  "HOST-ESCAPE": `<svg viewBox="0 0 72 72"><g class="s-lock"><rect x="19" y="32" width="34" height="26" rx="5" class="s-st"/><path class="s-st" d="M26 32v-7a10 10 0 0120 0v7"/><circle cx="36" cy="44" r="3" class="s-fill"/><path d="M36 47v5" stroke="#cfcfcf" stroke-width="2" stroke-linecap="round"/></g></svg>`,
};
$("#floatTiles").innerHTML = ["EXFIL-HTTP", "DNS-EXFIL", "RESOURCE-BOMB", "SECRET-HARVEST", "HOST-ESCAPE", "METADATA-SSRF"]
  .map((id, i) => `<div class="ft sc" style="--d:${(i * .7).toFixed(1)}s"><div class="ti">${SCENES[id]}</div></div>`).join("");

/* ---- gallery ---- */
const CAT = { "EXFIL-HTTP": "network", "METADATA-SSRF": "network", "DNS-EXFIL": "network", "SECRET-HARVEST": "host", "RESOURCE-BOMB": "resources", "HOST-ESCAPE": "host" };
const DESC = {
  "EXFIL-HTTP": "Tries to POST your uploaded CSV to an attacker’s server.",
  "METADATA-SSRF": "Reaches for the cloud metadata address for credentials.",
  "DNS-EXFIL": "Hides your data inside a DNS lookup.",
  "SECRET-HARVEST": "Hunts env vars, keys and the Docker socket.",
  "RESOURCE-BOMB": "Forks hundreds of processes, then eats all memory.",
  "HOST-ESCAPE": "Tries to write /etc, setuid, mount and ptrace.",
};
const ORDER = ["EXFIL-HTTP", "DNS-EXFIL", "METADATA-SSRF", "SECRET-HARVEST", "RESOURCE-BOMB", "HOST-ESCAPE"];
let attacks = [], results = {};
function score() {
  const n = Object.values(results).filter(r => r.contained).length, have = Object.keys(results).length, net = ["EXFIL-HTTP", "METADATA-SSRF", "DNS-EXFIL"];
  $("#scN").textContent = n; $("#galScore").classList.toggle("bad", have > n);
}
(async function () {
  try { attacks = await (await fetch("/api/attacks")).json(); } catch { return; }
  const list = ORDER.map(id => attacks.find(a => a.id === id)).filter(Boolean);
  $("#gal").innerHTML = list.map(a => `
    <div class="frame gcard rv" id="g-${a.id}" data-cat="${CAT[a.id]}">
      <div class="inner prev sc">${SCENES[a.id]}<span class="stat">READY</span><div class="meterslot"></div><div class="evid"></div></div>
      <div class="cap"><span class="ic">${icon(a.id)}</span><div><b>${esc(a.name)}</b><small>${esc(DESC[a.id] || a.tries)}</small></div><button class="btn sm go">Run</button></div>
      <div class="vwrap" hidden><button class="btn ghost sm vf">Verify receipt</button> <span class="vr verdict"></span></div>
    </div>`).join("");
  $$("#gal .rv").forEach(el => reduce ? el.classList.add("in") : rio.observe(el));
  list.forEach(a => { $(`#g-${a.id} .go`).onclick = () => runOne(a.id); });
})();
async function runOne(id) {
  const c = $("#g-" + id), btn = $(".go", c); btn.disabled = true; btn.textContent = "Running…";
  c.className = "frame gcard rv in running"; $(".stat", c).textContent = "ATTACKING…"; $(".vwrap", c).hidden = true; $(".meterslot", c).innerHTML = "";
  let r;
  try {
    const res = await fetch(`/api/attacks/${id}/run`, { method: "POST" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    r = await res.json();
  } catch (e) { c.className = "frame gcard rv in failed"; $(".stat", c).textContent = "ERROR"; toast(e.message); btn.disabled = false; btn.textContent = "Retry"; return; }
  results[id] = r; score();
  c.className = "frame gcard rv in flash done " + (r.contained ? "contained" : "failed");
  $(".stat", c).textContent = r.contained ? "✓ CONTAINED" : "✕ NOT CONTAINED";
  $(".evid", c).textContent = `${r.evidence}\nexit ${r.exit_code}${r.oom_killed ? " · oom_killed" : ""} · ${r.wall_ms} ms · destroyed ✔`;
  if (id === "RESOURCE-BOMB") {
    $(".meterslot", c).innerHTML = `<div class="meter"><div class="lbl"><span>memory cap 256 MB</span><span>${r.oom_killed ? "OOM-KILLED · exit " + r.exit_code : "exit " + r.exit_code}</span></div><div class="bar kill"><i></i></div></div>`;
    requestAnimationFrame(() => requestAnimationFrame(() => { const i = $(".bar i", c); if (i) i.style.width = "100%"; }));
  }
  const vw = $(".vwrap", c); vw.hidden = false; $(".vr", vw).textContent = "";
  $(".vf", vw).onclick = async () => { const v = await verifyAll(r.receipt), el = $(".vr", vw); el.className = "vr verdict " + (v.ok ? "ok" : "bad"); el.textContent = v.ok ? `✔ valid (${v.where})` : `✖ invalid (${v.where})`; };
  btn.disabled = false; btn.textContent = "Run again";
}
$("#runAll").onclick = async () => {
  const b = $("#runAll"); b.disabled = true; results = {}; score();
  $$("#gal .gcard").forEach(c => { c.classList.remove("done", "contained", "failed", "running"); $(".stat", c).textContent = "QUEUED"; $(".vwrap", c).hidden = true; $(".meterslot", c).innerHTML = ""; });
  $("#filters .pf[data-f=all]").click();
  for (const id of ORDER) await runOne(id);
  b.disabled = false;
};
$$("#filters .pf").forEach(p => p.onclick = () => {
  $$("#filters .pf").forEach(x => x.classList.toggle("on", x === p));
  $$("#gal .gcard").forEach(c => c.hidden = p.dataset.f !== "all" && c.dataset.cat !== p.dataset.f);
});
