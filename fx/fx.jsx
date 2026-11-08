// Bridge: mounts libraries.dev components (MIT: border-beam, thinking-orbs, bot-avatars) into our plain-JS pages.
import React from "react";
import { createRoot } from "react-dom/client";
import { BorderBeam } from "border-beam";
import { ThinkingOrb } from "thinking-orbs";
import { BotAvatar } from "bot-avatars";

const roots = new WeakMap();
function render(el, node) {
  let r = roots.get(el);
  if (!r) { r = createRoot(el); roots.set(el, r); }
  r.render(node);
}
const api = {
  orb(el, o = {}) { render(el, <ThinkingOrb state={o.state || "working"} size={o.size || 64} theme={o.theme || "dark"} />); },
  bot(el, o = {}) { render(el, <BotAvatar type={o.type || "clover"} size={o.size || 96} state={o.state || "default"} paused={!!o.paused} />); },
  // The beam rides the border of an empty, card-sized host element placed over the card.
  beam(el, o = {}) {
    render(el, (
      <BorderBeam active={o.active !== false} size={o.size || "md"} colorVariant={o.color || "colorful"} theme={o.theme || "dark"}
        borderRadius={o.radius || 24} duration={o.duration || 2.4} strength={o.strength ?? 0.9} style={{ width: "100%", height: "100%" }}>
        <div style={{ width: "100%", height: "100%", borderRadius: (o.radius || 24) + "px" }} />
      </BorderBeam>
    ));
  },
  mountAll(root = document) {
    root.querySelectorAll("[data-fx]").forEach(el => {
      if (el.dataset.fxDone) return; el.dataset.fxDone = "1";
      const k = el.dataset.fx, o = {};
      for (const [a, v] of Object.entries(el.dataset)) if (a.startsWith("fx") && a !== "fx" && a !== "fxDone") o[a[2].toLowerCase() + a.slice(3)] = isNaN(+v) || v === "" ? (v === "true" ? true : v === "false" ? false : v) : +v;
      api[k] && api[k](el, o);
    });
  },
};
window.AirgapFX = api;
document.readyState === "loading" ? addEventListener("DOMContentLoaded", () => api.mountAll()) : api.mountAll();
