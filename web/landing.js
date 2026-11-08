"use strict";
/* landing page behaviour: live ledger count + interactive attack cards */
fetch("/api/ledger/head").then(r => r.json()).then(h => {
  const el = $("#statReceipts"); el.dataset.count = h.seq; if (counted.has(el)) countTo(el, h.seq);
}).catch(() => {});

const TRY = ["EXFIL-HTTP", "DNS-EXFIL", "RESOURCE-BOMB"];
const COPY = {
  "EXFIL-HTTP": "A hijacked model tries to POST your uploaded CSV to an attacker’s server.",
  "DNS-EXFIL": "Hides your data inside a DNS lookup — the channel reported against a major code interpreter.",
  "RESOURCE-BOMB": "Forks hundreds of processes, then allocates memory forever. Watch the caps kill it.",
};
(async function () {
  let list = [];
  try { list = await (await fetch("/api/attacks")).json(); } catch { return; }
  const grid = $("#tryGrid");
  grid.innerHTML = TRY.map(id => list.find(a => a.id === id)).filter(Boolean).map(a => `
    <div class="tcard glow rv" id="tc-${a.id}">
      <i class="scan"></i>
      <div class="tile-h"><span class="ico">${icon(a.id)}</span><div><h3>${esc(a.id)}</h3><span class="nm">${esc(a.name)}</span></div><span class="badge">READY</span></div>
      <p>${esc(COPY[a.id] || a.tries)}</p>
      <p><b>Stopped by:</b> ${esc(a.stops)}</p>
      <button class="btn primary sm run">Run this attack</button>
      <div class="res" hidden></div>
    </div>`).join("");
  $$(".rv", grid).forEach(el => reduce ? el.classList.add("in") : rio.observe(el));
  $$(".tcard", grid).forEach(card => {
    const id = card.id.slice(3);
    $(".run", card).onclick = async () => {
      const btn = $(".run", card); btn.disabled = true; btn.textContent = "Attacking…";
      card.className = "tcard glow rv in running"; $(".badge", card).textContent = "ATTACKING…"; $(".res", card).hidden = true;
      let r;
      try {
        const res = await fetch(`/api/attacks/${id}/run`, { method: "POST" });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
        r = await res.json();
      } catch (e) { card.className = "tcard glow rv in failed"; $(".badge", card).textContent = "ERROR"; toast(e.message); btn.disabled = false; btn.textContent = "Try again"; return; }
      card.className = "tcard glow rv in " + (r.contained ? "contained" : "failed");
      $(".badge", card).textContent = r.contained ? "✓ CONTAINED" : "✕ NOT CONTAINED";
      const extra = id === "RESOURCE-BOMB" ? `<div class="meter"><div class="lbl"><span>memory cap 256 MB</span><span>${r.oom_killed ? "OOM-KILLED · exit " + r.exit_code : "exit " + r.exit_code}</span></div><div class="bar kill"><i></i></div></div>` : "";
      const res_ = $(".res", card); res_.hidden = false;
      res_.innerHTML = `${extra}<div class="ev">${esc(r.evidence)}\nexit ${r.exit_code}${r.oom_killed ? " · oom_killed" : ""} · ${r.wall_ms} ms · container destroyed ✔</div>
        <div class="row"><button class="btn ghost sm vf">Verify receipt</button><span class="vr verdict"></span></div>`;
      requestAnimationFrame(() => requestAnimationFrame(() => { const i = $(".bar i", res_); if (i) i.style.width = "100%"; }));
      $(".vf", res_).onclick = async () => {
        const v = await verifyAll(r.receipt), el = $(".vr", res_);
        el.className = "vr verdict " + (v.ok ? "ok" : "bad");
        el.textContent = v.ok ? `✔ valid (${v.where})` : `✖ invalid (${v.where})`;
      };
      btn.disabled = false; btn.textContent = "Run again";
    };
  });
})();
