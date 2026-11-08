/* Fortres page script. Numbers come from data/story.json and data/picks.json (exported from outputs/). */
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const fmt = n => n.toLocaleString("en-US");
  const mk = (tag, attrs, parent) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (parent) parent.appendChild(e); return e; };
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  /* ---------- theme ---------- */
  const root = document.documentElement, themeBtn = $("#themeBtn");
  const setThemeLabel = () => themeBtn.setAttribute("aria-label", root.dataset.theme === "light" ? "Switch to dark theme" : "Switch to light theme");
  themeBtn.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("fortres-theme", root.dataset.theme); } catch (e) {}
    setThemeLabel();
  });
  setThemeLabel();

  /* ---------- hero wall: 855 bricks, one cracked (about 1 in 855 ended up on CISA's list) ---------- */
  (function wall() {
    const svg = $("#wall"); if (!svg) return;
    const cols = 45, rows = 19, w = 9, h = 12, gx = 1, gy = 1.6, top = 18;
    const hot = 9 * cols + 31; // a fixed brick, about two thirds across
    let i = 0;
    for (let r = 0; r < rows; r++) {
      const off = r % 2 ? (w + gx) / 2 : 0;
      for (let c = 0; c < cols; c++, i++) {
        mk("rect", { x: c * (w + gx) + off - (r % 2 ? 5 : 0), y: top + r * (h + gy), width: w, height: h, class: i === hot ? "hot" : "" }, svg);
      }
    }
    // battlements along the top (outline only, not counted as bricks)
    let d = "";
    for (let x = 0; x < 450; x += 30) d += `M${x} ${top - 2}h18v-14h-18z`;
    mk("path", { d, fill: "var(--layer-2)" }, svg);
  })();

  /* ---------- data ---------- */
  Promise.all([
    fetch("data/story.json").then(r => r.json()),
    fetch("data/picks.json").then(r => r.json()).catch(() => null),
  ]).then(([story, picks]) => {
    fan(story);
    traits(story);
    methods(story);
    if (picks) { picksTable(picks); guardian(picks); }
  }).catch(err => console.warn("Fortres data did not load", err));

  /* ---------- thread fan: 75 holes added to CISA's list in 2024 and 2025 ---------- */
  function fan(story) {
    const b = story.blind; // visible 31, blind 44, simple 19/0, ours 22/5
    const svg = $("#fan");
    const O = { x: 60, y: 320 }, EX = 600;
    const threads = [];
    for (let i = 0; i < b.visible; i++) threads.push({ grp: "warn", i, rule: i < b.simple_caught_visible, ours: i < b.ours_caught_visible });
    const caughtSlots = new Set(Array.from({ length: b.ours_caught_blind }, (_, k) => Math.round((k + 0.5) * b.blind / b.ours_caught_blind)));
    for (let i = 0; i < b.blind; i++) threads.push({ grp: "blind", i, rule: false, ours: caughtSlots.has(i) });
    const n = threads.length;
    threads.forEach((t, k) => { t.bend = 0.34 + ((k * 37) % 23) / 23 * 0.3; });
    const yFor = (t, s) => s === 0 ? 40 + threads.indexOf(t) * (560 / (n - 1))
      : t.grp === "warn" ? 40 + t.i * (210 / (b.visible - 1)) : 330 + t.i * (270 / (b.blind - 1));
    const path = (y, bend) => { const c1 = O.x + (EX - O.x) * bend, c2 = O.x + (EX - O.x) * (bend + 0.15); return `M${O.x},${O.y} C${c1},${O.y} ${c2},${y} ${EX},${y}`; };
    const gT = mk("g", {}, svg), gE = mk("g", {}, svg), gL = mk("g", {}, svg);
    mk("circle", { cx: O.x, cy: O.y, r: 7, fill: "var(--ink)" }, svg);
    mk("text", { x: O.x, y: O.y + 38, "text-anchor": "middle", class: "lbl" }, svg).textContent = "made public";
    threads.forEach(t => { t.y = yFor(t, 0); t.p = mk("path", { class: "thread", d: path(t.y, t.bend) }, gT); t.d = mk("circle", { class: "end", cx: EX, cy: t.y, r: 3.2 }, gE); });
    const T = (x, y, cls, s, fill) => { const e = mk("text", { x, y, class: cls + " fade" }, gL); e.textContent = s; if (fill) e.style.fill = fill; return e; };
    const X = 630;
    const sets = [
      [T(X, 316, "lbl-s", `${n} holes`), T(X, 344, "lbl", "later added to CISA’s list")],
      [T(X, 128, "big-n", `${Math.round(100 * b.visible / n)}%`, "var(--lilac)"), T(X + 2, 164, "lbl-s", `${b.visible} had a warning sign`),
       T(X, 470, "big-n", `${Math.round(100 * b.blind / n)}%`, "var(--coral)"), T(X + 2, 506, "lbl-s", `${b.blind} had no warning sign`)],
      [T(X, 128, "big-n", `${b.simple_caught_visible}`, "var(--mint)"), T(X + 2, 164, "lbl-s", "caught by the usual rule"),
       T(X, 470, "big-n", `${b.simple_caught_blind}`, "var(--coral)"), T(X + 2, 506, "lbl-s", "caught by the usual rule")],
      [T(X, 128, "big-n", `${b.ours_caught_visible}`, "var(--mint)"), T(X + 2, 164, "lbl-s", "caught by Fortres"),
       T(X, 452, "big-n", `${b.ours_caught_blind}`, "var(--mint)"), T(X + 2, 488, "lbl-s", "caught by Fortres")],
    ];
    const byVendor = {};
    (b.ours_blind_cves || []).forEach(c => { byVendor[c.kev_vendor] = (byVendor[c.kev_vendor] || 0) + 1; });
    Object.entries(byVendor).sort((a, z) => z[1] - a[1]).forEach(([v, k], j) => sets[3].push(T(X + 2, 528 + j * 28, "tag", `${k} × ${v}`, "var(--mint)")));

    const colour = (t, s) => {
      if (s === 0) return ["var(--thread)", 0.8, 1.7];
      if (s === 1) return [t.grp === "warn" ? "var(--lilac)" : "var(--coral)", 0.8, 1.7];
      const hit = s === 2 ? t.rule : t.ours;
      return hit ? ["var(--mint)", 1, 2.6] : [t.grp === "warn" ? "var(--lilac)" : "var(--coral)", 0.18, 1.4];
    };
    // caption for small screens (desktop reads the steps on the left)
    const steps = $$("#steps .chap");
    const cap = document.createElement("div"); cap.className = "step-caption"; cap.setAttribute("aria-live", "polite");
    $(".chap-visual").insertBefore(cap, $(".chap-visual").firstChild);
    const dots = $("#fanDots");
    steps.forEach((_, i) => { const d = document.createElement("button"); d.type = "button"; d.setAttribute("aria-label", `Step ${i + 1}`); d.addEventListener("click", () => show(i)); dots.appendChild(d); });

    let cur = -1, raf = 0;
    function show(s) {
      s = Math.max(0, Math.min(steps.length - 1, s));
      if (s === cur) return; cur = s;
      steps.forEach((el, i) => el.classList.toggle("on", i === s));
      cap.innerHTML = steps[s].innerHTML;
      $$("button", dots).forEach((d, i) => d.setAttribute("aria-current", i === s));
      sets.forEach((g, i) => g.forEach(e => { e.style.opacity = i === s ? 1 : 0; }));
      threads.forEach(t => { const [c, o, w] = colour(t, s); t.p.style.stroke = c; t.p.style.opacity = o; t.p.style.strokeWidth = w; t.d.style.fill = c; t.d.style.opacity = o; });
      const from = threads.map(t => t.y), to = threads.map(t => yFor(t, s));
      const dur = reduce ? 0 : 750, t0 = performance.now();
      cancelAnimationFrame(raf);
      const ease = p => p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
      const frame = now => {
        threads.forEach((t, k) => {
          const delay = reduce ? 0 : (k / n) * 300;
          const p = dur ? Math.min(1, Math.max(0, (now - t0 - delay) / dur)) : 1;
          t.y = from[k] + (to[k] - from[k]) * ease(p);
          t.p.setAttribute("d", path(t.y, t.bend)); t.d.setAttribute("cy", t.y);
        });
        if (dur && now - t0 < dur + 320) raf = requestAnimationFrame(frame);
      };
      raf = requestAnimationFrame(frame);
    }
    $("#fanNext").addEventListener("click", () => show(cur + 1 >= steps.length ? 0 : cur + 1));
    $("#fanPrev").addEventListener("click", () => show(cur - 1));
    const io = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) show(+e.target.dataset.step); }), { rootMargin: "-45% 0px -45% 0px" });
    steps.forEach(el => io.observe(el));
    show(0);
    // draw the threads in once when the chart first comes into view
    if (!reduce) {
      const once = new IntersectionObserver(es => {
        if (!es[0].isIntersecting) return; once.disconnect();
        threads.forEach((t, k) => { const L = t.p.getTotalLength(); t.p.animate([{ strokeDasharray: L, strokeDashoffset: L }, { strokeDasharray: L, strokeDashoffset: 0 }], { duration: 900, delay: k * 10, easing: "cubic-bezier(0.22, 1, 0.36, 1)" }); });
      }, { threshold: 0.3 });
      once.observe(svg);
    }
  }

  /* ---------- why some get used: N in 1,000 ---------- */
  function traits(story) {
    const list = story.why.traits.slice();
    const base = list.shift();
    list.sort((a, z) => z.per_1000 - a.per_1000);
    const rows = [base, ...list];
    const max = Math.max(...rows.map(r => r.per_1000));
    $("#traits").innerHTML = rows.map((r, i) => {
      const cls = i === 0 ? "base" : r.few_cases ? "low" : i === 1 ? "top" : "";
      const name = r.trait.replace("Cross-site scripting", "Cross site scripting");
      const v = r.per_1000 < 1 ? r.per_1000.toFixed(1) : Math.round(r.per_1000);
      return `<div class="trait ${cls}" role="listitem">
        <span class="name">${esc(name)}${r.few_cases ? ' <span class="few">few cases</span>' : ""}</span>
        <div class="tbar" aria-hidden="true"><i style="transform:scaleX(${(r.per_1000 / max).toFixed(4)})"></i></div>
        <span class="val"><b>${v}</b> in 1,000<br><span class="num">${fmt(r.added_to_kev)} of ${fmt(r.cves)}</span></span></div>`;
    }).join("");
  }

  /* ---------- methods compared (Carbon dark categorical palette, in order) ---------- */
  function methods(story) {
    const names = { "Highest CVSS": "Most severe first (CVSS)", "Highest EPSS": "Highest EPSS score first", "Public exploit, then EPSS": "Public attack code, then EPSS" };
    const rows = story.results.map((r, i) => ({ name: r.is_ours ? "Fortres" : (names[r.name] || r.name), v: Object.values(r.by_year).reduce((a, z) => a + z, 0), ours: r.is_ours, c: `var(--c${(i % 4) + 1})` }));
    const max = Math.max(...rows.map(r => r.v));
    $("#methods").innerHTML = rows.map(r => `<div class="m-row${r.ours ? " ours" : ""}"><span class="name">${esc(r.name)}</span>
      <div class="bar" aria-hidden="true"><i style="background:${r.c};transform:scaleX(${(r.v / max).toFixed(4)})"></i></div><span class="v">${r.v}</span></div>`).join("");
  }

  /* ---------- the picks ---------- */
  function picksTable(p) {
    const tagFor = k => k === "Takes over the machine" ? "purple" : k === "No login needed" ? "teal" : "gray";
    const html = p.rows.slice(0, 8).map(r => `<div class="pick" role="row">
      <span class="rank" role="cell">${r.rank}</span>
      <span class="cve" role="cell">${esc(r.cve)}</span>
      <span class="what" role="cell"><span class="cds-tag ${tagFor(r.kind)}">${esc(r.kind)}</span><span class="reason">${esc(r.reason)}</span></span>
      <span class="epss" role="cell">top ${Math.max(0.1, 100 - r.epss_pct * 100).toFixed(1)}%</span>
      <span class="check" role="cell">${r.guardian_passed ? '<span class="cds-tag green">Guardian passed</span>' : '<span class="cds-tag gray">Plain template</span>'}</span></div>`).join("");
    $("#picksList").insertAdjacentHTML("beforeend", html);
  }
  function guardian(p) {
    $("#gPassed").textContent = fmt(p.guardian.passed_guardian);
    $("#gTotal").textContent = fmt(p.guardian.total);
  }

  /* ---------- Carbon notification enters once ---------- */
  const note = $("#guardianNote");
  if (note) new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { note.classList.add("in"); o.disconnect(); } }, { threshold: 0.6 }).observe(note);

  /* ---------- the one count: 27 and 19 roll up once ---------- */
  const counts = $$(".count");
  if (counts.length && !reduce) {
    const o = new IntersectionObserver(es => {
      if (!es.some(e => e.isIntersecting)) return; o.disconnect();
      counts.forEach(el => {
        const to = +el.dataset.to, t0 = performance.now(), dur = 1400;
        const step = now => { const p = Math.min(1, (now - t0) / dur); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 4))); if (p < 1) requestAnimationFrame(step); };
        el.textContent = "0"; requestAnimationFrame(step);
      });
    }, { threshold: 0.5 });
    counts.forEach(c => o.observe(c));
  }

  /* ---------- thesis: words light up as they cross the middle of the screen ---------- */
  const thesis = $("#thesis");
  if (thesis) {
    const wrapWords = node => {
      [...node.childNodes].forEach(ch => {
        if (ch.nodeType === 3) {
          const frag = document.createDocumentFragment();
          ch.textContent.split(/(\s+)/).forEach(part => {
            if (!part) return;
            if (/^\s+$/.test(part)) frag.appendChild(document.createTextNode(part));
            else { const s = document.createElement("span"); s.className = "w"; s.textContent = part; frag.appendChild(s); }
          });
          ch.replaceWith(frag);
        } else if (ch.nodeType === 1) wrapWords(ch);
      });
    };
    wrapWords(thesis);
    const words = $$(".w", thesis);
    let ticking = false;
    const light = () => { ticking = false; const line = innerHeight * 0.62; words.forEach(w => w.classList.toggle("on", w.getBoundingClientRect().top < line)); };
    if (reduce) words.forEach(w => w.classList.add("on"));
    else { addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(light); } }, { passive: true }); light(); }
  }

  /* ---------- nav: mark the current section ---------- */
  const links = $$(".nav-links a");
  const spy = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) links.forEach(a => a.setAttribute("aria-current", a.hash === "#" + e.target.id)); }), { rootMargin: "-45% 0px -50% 0px" });
  $$("main section[id]").forEach(s => spy.observe(s));
})();
