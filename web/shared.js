"use strict";
/* Shared helpers for the landing page and the app workspace. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

function toast(msg) {
  let box = $("#toasts"); if (!box) { box = document.createElement("div"); box.id = "toasts"; box.className = "toasts"; document.body.append(box); }
  const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; box.append(t); setTimeout(() => t.remove(), 6000);
}

/* nav shadow + pointer glow + reveal-on-scroll */
addEventListener("scroll", () => { const n = $("#nav"); if (n) n.classList.toggle("scrolled", scrollY > 8); }, { passive: true });
document.addEventListener("pointermove", e => {
  const g = e.target.closest && e.target.closest(".glow"); if (!g) return;
  const r = g.getBoundingClientRect(); g.style.setProperty("--mx", (e.clientX - r.left) + "px"); g.style.setProperty("--my", (e.clientY - r.top) + "px");
}, { passive: true });
const rio = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { e.target.classList.add("in"); rio.unobserve(e.target); } }), { threshold: .12 });
$$(".rv").forEach(el => reduce ? el.classList.add("in") : rio.observe(el));

/* animated counters */
function countTo(el, to, suffix = "") {
  if (reduce || to === 0) { el.textContent = to + suffix; return; }
  const t0 = performance.now(), D = 1100;
  (function tick(t) { const p = Math.min(1, (t - t0) / D); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))) + suffix; if (p < 1) requestAnimationFrame(tick); })(t0);
}
const counted = new WeakSet();
const cio = new IntersectionObserver(es => es.forEach(e => {
  if (e.isIntersecting && !counted.has(e.target)) { counted.add(e.target); countTo(e.target, +e.target.dataset.count, e.target.dataset.suffix || ""); }
}));
$$("[data-count]").forEach(el => cio.observe(el));

/* service health pill */
async function health() {
  const el = $("#health"); if (!el) return; const label = $("span", el);
  try {
    const h = await (await fetch("/healthz")).json();
    label.textContent = h.status === "ok" ? `containment verified · ${h.runtime}` : h.status === "pending" ? "running self-test…" : "self-test failed";
    el.className = "status " + (h.status === "ok" ? "ok" : h.status === "pending" ? "" : "bad");
    if (h.status === "pending") setTimeout(health, 2000);
  } catch { label.textContent = "offline"; el.className = "status bad"; }
}
health();

/* canonical JSON + browser-side Ed25519 verification (matches server/receipts.py byte-for-byte) */
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

/* attack icons (shared by landing + lab) */
const ICONS = {
  "EXFIL-HTTP": '<path d="M7 17L17 7M9 7h8v8"/>',
  "METADATA-SSRF": '<path d="M7 18a4 4 0 010-8 5 5 0 019.6-1A4.5 4.5 0 0117 18H7z"/>',
  "DNS-EXFIL": '<path d="M5 12a7 7 0 0114 0M8 12a4 4 0 018 0M12 12h.01"/>',
  "SECRET-HARVEST": '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
  "RESOURCE-BOMB": '<path d="M12 3c1 4 5 5 5 10a5 5 0 01-10 0c0-2 1-3 2-4 0 2 1 3 2 3 0-3-1-5 1-9z"/>',
  "HOST-ESCAPE": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 017.5-2"/>',
};
const icon = id => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[id] || ""}</svg>`;
