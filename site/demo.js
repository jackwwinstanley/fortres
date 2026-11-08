/* Fortres presenter page. All results and on-screen sentences with numbers come from data/demo.json. This file holds only timings
   and layout, runs one requestAnimationFrame loop, uses no randomness, and draws every frame as a pure function of (scene, t). */
(() => {
  "use strict";
  /* scene table: edit timings here (milliseconds) */
  const SCENES = [
    { id: "hook", ms: 8000 }, { id: "what", ms: 12000 }, { id: "replay", ms: 15000 }, { id: "lookup", ms: 30000 },
    { id: "result", ms: 20000 }, { id: "found", ms: 20000 }, { id: "close", ms: 10000 },
  ];
  const TYPE_MS = 70; // per character, fixed
  const W = 1920, H = 1080;
  const $ = s => document.querySelector(s);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const stage = $("#stage");
  const fit = () => {
    const k = Math.min(innerWidth / W, innerHeight / H);
    stage.style.transform = `translate(${(innerWidth - W * k) / 2}px, ${(innerHeight - H * k) / 2}px) scale(${k})`;
  };
  addEventListener("resize", fit); fit();

  const clamp01 = x => Math.max(0, Math.min(1, x));
  const ease = x => 1 - Math.pow(1 - clamp01(x), 3);
  const reveal = (el, t, at, dur = 450, dy = 16) => {
    const p = ease((t - at) / dur);
    el.style.opacity = p;
    el.style.transform = `translateY(${(1 - p) * dy}px)`;
  };
  const make = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

  let D, draw = {};

  function build(d) {
    D = d; const c = d.copy;
    const text = { "hook-big": c.hook_big, "hook-line": c.hook_line, "hook-rate": c.hook_rate, "what-title": c.what_title, "replay-title": c.replay_title, "replay-label": c.replay_label,
      "replay-top": c.replay_top, "result-title": c.result_title, "result-range": c.result_range, "result-split": c.result_split, "result-workload": c.result_workload || "",
      "leak-big": c.leak_big, "leak-note": c.leak_note, "close-big": c.close_big, "close-links": c.close_links.join("   ·   "), "close-team": c.close_team, "close-built": c.close_built };
    for (const [id, v] of Object.entries(text)) $("#" + id).textContent = v;

    /* 1 hook */
    draw.hook = t => { reveal($("#hook-big"), t, 0, 600); reveal($("#hook-line"), t, 700); reveal($("#hook-rate"), t, 3200); };

    /* 2 what */
    const flow = c.flow.map(s => $("#flow").appendChild(make("li", "", s)));
    draw.what = t => { reveal($("#what-title"), t, 0); flow.forEach((el, i) => reveal(el, t, 2500 + i * 2000)); };

    /* 3 replay */
    const hist = d.hist, bars = hist.counts.map((_, i) => $("#hist").appendChild(make("i")));
    const FILL_MS = 10000, LIT_AT = 11000, cut = hist.top_counts.findIndex(x => x > 0);
    draw.replay = t => {
      reveal($("#replay-title"), t, 0); reveal($("#replay-label"), t, 300);
      const front = (t / FILL_MS) * bars.length;
      bars.forEach((b, i) => {
        const g = ease(front - i);
        b.style.transform = `scaleY(${g * hist.counts[i] / hist.max_count})`;
        b.classList.toggle("lit", t >= LIT_AT && i >= cut);
      });
      reveal($("#replay-top"), t, LIT_AT, 480);
    };

    /* 4 lookup: three cards, each in its own time window */
    const show = d.showcase;
    const windows = [{ k: "a", at: 0, end: 14000, badge: c.lookup_a_badge }, { k: "b", at: 14000, end: 22000, note: c.lookup_b_note }, { k: "d", at: 22000, end: 30000, note: c.lookup_d_note }];
    windows.forEach(w => {
      const s = show[w.k], el = $("#cards").appendChild(make("div", "card"));
      const line = make("div", "rankline");
      line.append(make("span", "rank" + (s.in_top ? " in" : ""), s.rank_text), make("span", "of", "of " + c.hook_big));
      const kind = make("p", "kind", s.kind), sig = make("ul", "signals");
      const sigs = s.signals.map(x => sig.appendChild(make("li", "", x)));
      el.append(line, kind, sig);
      w.reason = s.reason ? el.appendChild(make("p", "reason", s.reason)) : null;
      w.badgeEl = w.badge ? el.appendChild(make("span", "badge", w.badge)) : null;
      w.noteEl = w.note ? el.appendChild(make("p", "note", w.note)) : null;
      Object.assign(w, { el, line, kind, sigs, cve: s.cve });
    });
    const typed = $("#typed"), caret = $("#caret");
    draw.lookup = t => {
      const w = windows.find(x => t < x.end) || windows[windows.length - 1];
      const n = Math.floor(clamp01((t - w.at - 400) / (w.cve.length * TYPE_MS)) * w.cve.length);
      typed.textContent = w.cve.slice(0, n);
      caret.style.opacity = n < w.cve.length ? 1 : 0;
      windows.forEach(x => { x.el.style.opacity = x === w ? 1 : 0; });
      const r = t - w.at, step = w.k === "a" ? 1300 : 700, base = 400 + w.cve.length * TYPE_MS + 300;
      reveal(w.line, r, base); reveal(w.kind, r, base + step * 0.6);
      w.sigs.forEach((el, i) => reveal(el, r, base + step * (1.2 + i)));
      const after = base + step * (1.2 + w.sigs.length);
      if (w.reason) reveal(w.reason, r, after, 700);
      if (w.badgeEl) reveal(w.badgeEl, r, after + 2200);
      if (w.noteEl) reveal(w.noteEl, r, w.reason ? after + 1400 : after);
    };

    /* 5 result */
    const vmax = Math.max(...c.result_bars.map(b => b.v));
    const rows = c.result_bars.map(b => {
      const row = make("div", "bar" + (b.ours ? " ours" : "")), fill = make("div", "fill"), track = make("div", "track");
      track.append(fill); row.append(make("span", "", b.label), track, make("span", "val", b.v));
      $("#bars").append(row); return { row, fill, f: b.v / vmax };
    });
    draw.result = t => {
      reveal($("#result-title"), t, 0);
      rows.forEach((r, i) => { reveal(r.row, t, 800 + i * 900); r.fill.style.transform = `scaleX(${r.f * ease((t - 900 - i * 900) / 900)})`; });
      reveal($("#result-range"), t, 5500); reveal($("#result-split"), t, 7500); reveal($("#result-workload"), t, 8000);
      reveal($("#leak"), t, 12000, 600);
    };

    /* 6 found */
    const cards = c.cards.map(x => { const e = $("#found").appendChild(make("div", "fcard")); e.append(make("p", "fbig", x.big), make("p", "ftext", x.text), make("p", "fsmall", x.small)); return e; });
    draw.found = t => cards.forEach((e, i) => reveal(e, t, i * 6000, 600));

    /* 7 close */
    draw.close = t => { reveal($("#close-big"), t, 0, 600); reveal($("#close-links"), t, 2500); reveal($("#close-team"), t, 3500); reveal($("#close-built"), t, 4500); };
  }

  /* engine */
  const state = { i: -1, t0: 0, autoplay: false, playStart: null, playEnd: null, frozen: null };
  window.__demo = state;
  const show = i => {
    document.querySelectorAll(".scene").forEach(s => s.classList.remove("on"));
    (i < 0 ? $("#s-start") : $("#s-" + SCENES[i].id)).classList.add("on");
  };
  const go = i => { state.i = Math.max(-1, Math.min(SCENES.length - 1, i)); state.t0 = performance.now(); show(state.i); };
  const setAuto = on => { state.autoplay = on; document.body.classList.toggle("autoplay", on); if (on) { state.playEnd = null; state.playStart = performance.now(); if (state.i < 0) go(0); } };

  addEventListener("keydown", e => {
    if (!D) return;
    const k = e.key.toLowerCase();
    if (k === " " || k === "arrowright") { e.preventDefault(); go(state.i + 1); }
    else if (k === "arrowleft") go(state.i - 1);
    else if (k === "r") { setAuto(false); go(-1); }
    else if (k === "a") setAuto(!state.autoplay);
    else if (k === "h") document.body.classList.toggle("nohints");
  });

  const frame = now => {
    if (D && state.i >= 0) {
      const s = SCENES[state.i];
      const elapsed = state.frozen != null ? state.frozen : now - state.t0;
      draw[s.id](reduce ? s.ms : Math.min(elapsed, s.ms));
      if (state.autoplay && elapsed >= s.ms) {
        if (state.i < SCENES.length - 1) go(state.i + 1);
        else { state.playEnd = now; setAuto(false); state.playEnd = now; }
      }
      $("#hint-scene").textContent = `${state.i + 1}/${SCENES.length}`;
    }
    requestAnimationFrame(frame);
  };

  fetch("data/demo.json").then(r => r.json()).then(d => {
    build(d);
    const q = new URLSearchParams(location.search);          // for stills only: ?scene=<number>&t=<ms> freezes one frame
    if (q.has("scene")) { state.frozen = +(q.get("t") || 0); go(+q.get("scene") - 1); document.body.classList.add("nohints"); }
    else go(-1);
    requestAnimationFrame(frame);
  });
})();
