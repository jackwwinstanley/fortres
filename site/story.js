/* Before the Breach: scroll story. Every number comes from data/story.json (python -m src.b.export_story). */
(async function () {
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const D = await fetch("data/story.json").then((r) => r.json());
  const css = getComputedStyle(document.documentElement);
  const v = (n) => css.getPropertyValue(n).trim();
  const C = { bg: v("--bg"), dot: v("--dot"), ember: v("--ember"), emberGlow: v("--ember-glow"), mint: v("--mint"),
    mintGlow: v("--mint-glow"), violet: v("--violet"), lavender: v("--lavender"), ink: v("--ink"), ink2: v("--ink-2"),
    muted: v("--muted"), line: v("--line") };
  const fmt = d3.format(",");
  const dur = (ms) => (REDUCED ? 0 : ms);

  // ---------- derived numbers, written into the text ----------
  const caught = d3.sum(D.fan, (d) => d.caught), exploited = d3.sum(D.fan, (d) => d.exploited);
  const ratio = D.heat.late_2026_median_pct / D.heat.past_median_pct;
  const ours = D.results.find((r) => r.is_ours), base = D.results.find((r) => r.name.startsWith("Public exploit"));
  const sumYears = (r) => d3.sum(Object.values(r.by_year));
  const T = Object.fromEntries(D.why.traits.map((t) => [t.trait, t]));
  const allRate = T["All holes"].per_1000;
  const highs = D.why.traits.filter((t) => t.per_1000 > allRate * 2).map((t) => t.per_1000 / allRate);
  const K = {
    "field.scoreboard": fmt(D.field.scoreboard), "field.one_in": fmt(D.field.one_in), "field.expected_2026": fmt(D.field.expected_2026),
    "why.base": Math.round(allRate), "why.range": `about ${Math.round(d3.median(highs))}×`,
    "why.wp": fmt(T["WordPress plugin"].added_to_kev), "why.wp_n": fmt(T["WordPress plugin"].cves),
    "why.xss": fmt(T["Cross-site scripting"].added_to_kev), "why.xss_n": fmt(T["Cross-site scripting"].cves),
    "why.note": `CVEs published ${T["All holes"].period.replace(" to ", "–")}; “added to CISA KEV” = on CISA's Known Exploited Vulnerabilities list as of ${D.why.kev_as_of}. ` +
      `Public attack code: 2024–25 practice years. Traits are keyword tags on the description and are associated with, not causes of, a higher or lower rate. ` +
      `Descriptive only: never a model input. Every trait has ≥ ${fmt(D.why.min_n)} CVEs; fewer than ${D.why.few_cases_below} KEV entries = few cases, treat as a hint. ` +
      `Limitation: ${D.why.limitation}`,
    "fan.caught": caught, "fan.missed": exploited - caught, "fan.exploited": exploited,
    "fan.caught_pct": Math.round((caught / exploited) * 100) + "%",
    "blind.total": D.blind.visible + D.blind.blind, "blind.visible": D.blind.visible, "blind.blind": D.blind.blind,
    "blind.ours": D.blind.ours_caught_blind,
    "example.pct": Math.round(D.example.kev_text_pct * 100) + "%",
    "example.nearest_name": `a ${D.example.nearest.vendor} login bypass (${D.example.nearest.cve})`,
    "example.nearest_year": D.example.nearest.year_added,
    "heat.ratio": Math.round(ratio) + "×", "heat.late_share": Math.round(D.heat.late_share * 100) + "%",
    "leak.honest": D.leak.honest, "leak.analyzed": Math.round(D.leak.analyzed_exploited * 100) + "%",
    "leak.others": Math.round(D.leak.analyzed_others * 100) + "%",
    "results.ours": sumYears(ours), "results.base": sumYears(base),
  };
  document.querySelectorAll("[data-key]").forEach((el) => { if (K[el.dataset.key] != null) el.textContent = K[el.dataset.key]; });

  // ---------- stage ----------
  const sticky = document.querySelector(".sticky");
  const canvas = document.getElementById("field");
  const ctx = canvas.getContext("2d");
  const svg = d3.select("#stage");
  const overlay = d3.select("#overlay");
  const tip = document.getElementById("tip");
  let W = 0, H = 0, FH = 0, MOB = false, DPR = 1, current = { scene: null, step: -1 };

  // ---------- scene 1 & 2: the starfield (canvas) ----------
  const N = D.field.scoreboard, rng = d3.randomLcg(7);
  const px = new Float32Array(N), py = new Float32Array(N), sz = new Float32Array(N), bucket = new Uint8Array(N);
  const fires = d3.shuffler(d3.randomLcg(3))(d3.range(500, N)).slice(0, D.field.expected_2026);
  const F = { show: 0, fire: 0, grid: 0 };
  const NB = 4, layers = [];
  let tween = null, twinkle = null;

  function placeStars() { // jittered grid -> even spacing, no clumps, no TV static
    const aspect = (W - 48) / (FH - 48), cols = Math.ceil(Math.sqrt(N * aspect)), rows = Math.ceil(N / cols);
    const order = d3.shuffler(d3.randomLcg(11))(d3.range(cols * rows)).slice(0, N);
    for (let i = 0; i < N; i++) {
      const c = order[i] % cols, r = Math.floor(order[i] / cols);
      px[i] = (c + 0.5 + (rng() - 0.5) * 0.8) / cols; py[i] = (r + 0.5 + (rng() - 0.5) * 0.8) / rows;
      const h = rng(); sz[i] = h < 0.78 ? 0.55 : h < 0.96 ? 0.95 : 1.7; bucket[i] = h >= 0.96 ? NB - 1 : Math.floor(rng() * (NB - 1));
    }
  }
  function buildLayers() { // pre-render each twinkle group once; each frame only blits 4 images
    layers.length = 0;
    const m = 24, w = W - 2 * m, h = FH - 2 * m, unit = Math.max(1, Math.sqrt((w * h) / N) * 0.36);
    for (let b = 0; b < NB; b++) {
      const off = document.createElement("canvas"); off.width = W * DPR; off.height = FH * DPR;
      const o = off.getContext("2d"); o.setTransform(DPR, 0, 0, DPR, 0, 0); o.fillStyle = b === NB - 1 ? "#f2f4f8" : "#8d99c2";
      o.beginPath();
      for (let i = 500; i < N; i++) if (bucket[i] === b) { const s = sz[i] * unit; o.moveTo(m + px[i] * w + s, m + py[i] * h); o.arc(m + px[i] * w, m + py[i] * h, s, 0, 6.283); }
      o.fill(); layers.push(off);
    }
  }
  function gridPos(i) { // 500 dots: 25 x 20 grid filling the panel
    const cols = 25, rows = 20, s = Math.min((W * 0.8) / cols, (H * 0.74) / rows);
    const x0 = (W - s * (cols - 1)) / 2, y0 = (H - s * (rows - 1)) / 2 + H * 0.04;
    return [x0 + (i % cols) * s, y0 + Math.floor(i / cols) * s, s];
  }
  function drawField(t = 0) {
    ctx.clearRect(0, 0, W, FH);
    const m = 24, w = W - 2 * m, h = FH - 2 * m, unit = Math.max(1, Math.sqrt((w * h) / N) * 0.36);
    const bgA = F.show * (1 - F.grid);
    if (bgA > 0.002) for (let b = 0; b < NB; b++) {
      ctx.globalAlpha = bgA * (b === NB - 1 ? (REDUCED ? 0.85 : 0.6 + 0.4 * Math.sin(t / 700)) : (REDUCED ? 0.3 : 0.22 + 0.14 * Math.sin(t / (900 + b * 260) + b * 1.7)));
      ctx.drawImage(layers[b], 0, 0, W, FH);
    }
    const g = d3.easeCubicInOut(F.grid);
    for (let i = 0; i < 500; i++) { // the first 500 stars travel into the grid
      const [gx, gy, s] = gridPos(i), x = m + px[i] * w, y = m + py[i] * h;
      ctx.globalAlpha = F.show * (0.45 + 0.55 * g);
      ctx.fillStyle = g > 0.02 ? d3.interpolateRgb("#a2a9b0", C.ink)(g) : "#a2a9b0";
      ctx.beginPath(); ctx.arc(x + (gx - x) * g, y + (gy - y) * g, sz[i] * unit + g * (s * 0.3 - sz[i] * unit), 0, 6.283); ctx.fill();
    }
    const fa = F.fire * (1 - F.grid);
    if (fa > 0.002) for (let j = 0; j < fires.length; j++) { // ignited stars: ember core + pulsing glow
      const i = fires[j], x = m + px[i] * w, y = m + py[i] * h;
      const R = REDUCED ? 12 : 11 + 4 * Math.sin(t / 420 + j);
      const halo = ctx.createRadialGradient(x, y, 0, x, y, R);
      halo.addColorStop(0, "rgba(255,131,43,0.7)"); halo.addColorStop(1, "rgba(255,131,43,0)");
      ctx.globalAlpha = fa; ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(x, y, R, 0, 6.283); ctx.fill();
      ctx.fillStyle = C.ember; ctx.beginPath(); ctx.arc(x, y, 2.6, 0, 6.283); ctx.fill();
    }
    ctx.globalAlpha = 1;
  }
  function startTwinkle() {
    if (twinkle || REDUCED) { drawField(); return; }
    let last = 0;
    twinkle = d3.timer((t) => { if (t - last > 45) { last = t; drawField(t); } });
  }
  function stopTwinkle() { if (twinkle) { twinkle.stop(); twinkle = null; } }
  function animateField(target, ms) {
    if (tween) tween.stop();
    const from = { ...F };
    if (!ms) { Object.assign(F, target); drawField(); return; }
    tween = d3.timer((t) => {
      const k = Math.min(1, t / ms);
      for (const key in target) F[key] = from[key] + (target[key] - from[key]) * k;
      if (!twinkle) drawField();
      if (k >= 1) tween.stop();
    });
  }

  function size() {
    const r = sticky.getBoundingClientRect();
    W = r.width; FH = r.height; MOB = W < 820; H = MOB ? FH * 0.6 : FH;
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * DPR; canvas.height = FH * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    svg.attr("viewBox", `0 0 ${W} ${H}`);
    placeStars(); buildLayers();
  }

  // ---------- helpers ----------
  const clear = () => { svg.selectAll("*").interrupt().remove(); overlay.html(""); svg.classed("interactive", false); hideTip(); };
  function callout(html, x, y, cls = "") {
    const el = overlay.append("div").attr("class", "callout " + cls).html(html).style("left", x + "px").style("top", y + "px");
    requestAnimationFrame(() => el.classed("show", true));
    return el;
  }
  function showTip(evt, html) {
    tip.innerHTML = html; tip.hidden = false;
    const r = tip.getBoundingClientRect();
    let x = evt.clientX + 14, y = evt.clientY + 14;
    if (x + r.width > window.innerWidth - 8) x = evt.clientX - r.width - 14;
    if (y + r.height > window.innerHeight - 8) y = evt.clientY - r.height - 14;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  }
  function hideTip() { tip.hidden = true; }
  function glowFilter() {
    const f = svg.append("defs").append("filter").attr("id", "glow").attr("x", "-100%").attr("y", "-100%").attr("width", "300%").attr("height", "300%");
    f.append("feGaussianBlur").attr("stdDeviation", 3).attr("result", "b");
    const fm = f.append("feMerge"); fm.append("feMergeNode").attr("in", "b"); fm.append("feMergeNode").attr("in", "SourceGraphic");
  }

  // ---------- scene: traits of CVEs that end up on KEV (natural frequencies) ----------
  function why(step) {
    const traits = [D.why.traits[0], ...D.why.traits.slice(1).sort((a, b) => b.per_1000 - a.per_1000)];
    const cols = MOB ? 3 : 3, rowsN = Math.ceil(traits.length / cols);
    const pad = MOB ? 10 : 26, top = MOB ? 8 : H * 0.06, cw = (W - pad * (cols + 1)) / cols, ch = (H * (MOB ? 0.98 : 0.9) - top) / rowsN;
    const dc = 40, dr = 25, sp = Math.min((cw - 8) / dc, (ch - (MOB ? 34 : 54)) / dr), rr = Math.max(0.9, sp * 0.3);
    if (svg.select(".mtx").empty()) {
      clear(); glowFilter();
      traits.forEach((t, k) => {
        const gx = pad + (k % cols) * (cw + pad), gy = top + Math.floor(k / cols) * ch;
        const g = svg.append("g").attr("class", "mtx").attr("transform", `translate(${gx},${gy})`).attr("opacity", 0).datum(t);
        const lit = new Set(d3.shuffler(d3.randomLcg(k + 3))(d3.range(1000)).slice(0, Math.round(t.per_1000)));
        g.append("text").attr("class", "lbl").attr("y", MOB ? 11 : 16).text(t.trait);
        g.append("text").attr("class", "lbl-num").attr("y", MOB ? 25 : 38)
          .html(`<tspan fill="${C.emberGlow}" font-weight="600">${t.per_1000 < 1 ? t.per_1000.toFixed(1) : Math.round(t.per_1000)}</tspan> in 1,000 · ${fmt(t.added_to_kev)} of ${fmt(t.cves)}${t.few_cases ? " · few cases, a hint" : ""}`);
        const dots = g.append("g").attr("transform", `translate(${sp / 2},${(MOB ? 32 : 50) + sp / 2})`);
        dots.selectAll("circle").data(d3.range(1000)).join("circle").attr("cx", (i) => (i % dc) * sp).attr("cy", (i) => Math.floor(i / dc) * sp)
          .attr("r", (i) => (lit.has(i) ? rr * 1.9 : rr)).attr("fill", (i) => (lit.has(i) ? C.ember : C.dot))
          .attr("opacity", (i) => (lit.has(i) ? 1 : 0.55)).attr("filter", (i) => (lit.has(i) ? "url(#glow)" : null));
        g.append("rect").attr("x", -6).attr("y", -6).attr("width", cw + 4).attr("height", ch - 6).attr("fill", "transparent")
          .on("mousemove", (e) => showTip(e, `<span class="t-cve">${t.trait}</span><div class="t-meta">${t.period}</div>` +
            `${fmt(t.added_to_kev)} added to CISA KEV out of ${fmt(t.cves)} CVEs (${t.per_1000} per 1,000)${t.few_cases ? " · few cases, treat as a hint" : ""}`)).on("mouseleave", hideTip);
      });
      svg.classed("interactive", true);
    }
    svg.selectAll(".mtx").each(function (t, k) {
      const show = step === 0 ? k === 0 : true;
      const dim = step === 2 && !["WordPress plugin", "Cross-site scripting", "All holes"].includes(t.trait);
      d3.select(this).transition().delay(step === 1 && k > 0 ? dur(k * 260) : 0).duration(dur(500)).attr("opacity", show ? (dim ? 0.18 : 1) : 0);
    });
  }

  // ---------- scene: the fan of 75 threads ----------
  function fan(step) {
    const x0 = W * (MOB ? 0.06 : 0.08), y0 = H * 0.5, x1 = W * (MOB ? 0.58 : 0.62), xm = W * 0.3;
    const pc = caught / exploited;
    const yC = H * 0.24, yM = H * 0.66, sC = H * 0.13, sM = H * 0.2;
    if (svg.select(".thread").empty()) {
      clear(); glowFilter();
      const r2 = d3.randomLcg(5); const threads = d3.range(exploited).map((i) => {
        const isC = i < caught, k = isC ? i / Math.max(1, caught - 1) : (i - caught) / Math.max(1, exploited - caught - 1);
        const jitter = (r2() - 0.5) * 0.18;
        return { isC, ye: isC ? yC - sC / 2 + (k + jitter) * sC : yM - sM / 2 + (k + jitter) * sM, ys: y0 + (r2() - 0.5) * 6 };
      });
      const path = (d) => `M${x0},${d.ys} C${xm},${d.ys} ${xm + (x1 - xm) * 0.25},${d.ye} ${x1},${d.ye}`;
      svg.selectAll(".thread").data(threads).join("path").attr("class", "thread").attr("d", path).attr("fill", "none")
        .attr("stroke", C.muted).attr("stroke-width", MOB ? 1 : 1.6).attr("stroke-opacity", 0.55)
        .each(function () { const L = this.getTotalLength(); d3.select(this).attr("stroke-dasharray", `${L} ${L}`).attr("stroke-dashoffset", L).property("L", L); });
      svg.append("circle").attr("class", "origin").attr("cx", x0).attr("cy", y0).attr("r", 9).attr("fill", C.ember).attr("filter", "url(#glow)");
      svg.append("text").attr("class", "lbl-big").attr("x", x0).attr("y", y0 - 52).text(`${exploited} CVEs added to CISA KEV`);
      svg.append("text").attr("class", "lbl-mute").attr("x", x0).attr("y", y0 - 28).text(`2024 + 2025 practice years`);
    }
    const th = svg.selectAll(".thread");
    if (step === 0) {
      overlay.html(""); svg.selectAll(".end").remove();
      th.transition().delay((d, i) => dur(i * 14)).duration(dur(900)).attr("stroke", C.muted)
        .attr("stroke-dashoffset", function () { return this.L * 0.62; });
    } else {
      th.transition().delay((d, i) => dur(i * 16)).duration(dur(1100)).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0)
        .attr("stroke", (d) => (d.isC ? C.lavender : C.ember)).attr("stroke-opacity", 0.7);
      svg.selectAll(".end").data(th.data()).join("circle").attr("class", "end").attr("cx", x1).attr("cy", (d) => d.ye).attr("r", 0)
        .attr("fill", (d) => (d.isC ? C.lavender : C.ember))
        .transition().delay((d, i) => dur(900 + i * 16)).duration(dur(300)).attr("r", MOB ? 2 : 3);
      // density ridge at the landing edge
      ["c", "m"].forEach((grp) => {
        const ys = th.data().filter((d) => (grp === "c") === d.isC).map((d) => d.ye);
        const kde = d3.range(d3.min(ys) - 20, d3.max(ys) + 20, 2).map((y) => [y, d3.sum(ys, (v) => Math.exp(-((y - v) ** 2) / 120))]);
        const sx = d3.scaleLinear([0, d3.max(kde, (d) => d[1])], [0, W * 0.06]);
        svg.append("path").attr("class", "end").attr("fill", grp === "c" ? C.lavender : C.ember).attr("opacity", 0)
          .attr("d", d3.area().y((d) => d[0]).x0(x1 + 8).x1((d) => x1 + 8 + sx(d[1])).curve(d3.curveBasis)(kde))
          .transition().delay(dur(1400)).duration(dur(500)).attr("opacity", 0.35);
      });
      overlay.html("");
      const cx = x1 + W * 0.08;
      setTimeout(() => {
        if (current.scene !== "fan") return;
        callout(`${Math.round(pc * 100)}%<small>caught by the simple rule (${caught})</small>`, cx, yC - 70).style("color", C.lavender);
        callout(`${100 - Math.round(pc * 100)}%<small>missed (${exploited - caught})</small>`, cx, yM - 70).style("color", C.emberGlow);
      }, dur(1200));
    }
  }

  // ---------- scene: blind spots ----------
  function blind(step) {
    const vN = D.blind.visible, bN = D.blind.blind;
    const s = Math.min((W * 0.84) / 14, (H * 0.62) / 7), r = s / 2.6;
    const cluster = (n, cols, cx, cy) => d3.range(n).map((i) => ({
      x: cx - ((cols - 1) * s) / 2 + (i % cols) * s, y: cy - ((Math.ceil(n / cols) - 1) * s) / 2 + Math.floor(i / cols) * s }));
    const xA = W * 0.08 + 2 * s, xB = W * 0.08 + 7 * s + 3 * s;
    const A = cluster(vN, 5, xA, H * 0.5), B = cluster(bN, 7, xB, H * 0.5);
    const dots = [...A.map((p, i) => ({ ...p, grp: "v", i })), ...B.map((p, i) => ({ ...p, grp: "b", i }))];
    const LIT = [13, 34].slice(0, D.blind.ours_caught_blind);
    if (svg.select(".bdot").empty()) {
      clear(); glowFilter();
      svg.selectAll(".bdot").data(dots).join("circle").attr("class", "bdot").attr("cx", (d) => d.x).attr("cy", (d) => d.y)
        .attr("r", 0).attr("fill", (d) => (d.grp === "v" ? C.ember : "#3a2418")).attr("stroke", (d) => (d.grp === "b" ? C.ember : "none"))
        .attr("stroke-opacity", 0.4).attr("stroke-width", 1.2)
        .transition("grow").delay((d, i) => (REDUCED ? 0 : i * 12)).duration(dur(400)).attr("r", r);
      const lab = (x, y, t, cls) => svg.append("text").attr("class", cls).attr("x", x).attr("y", y).attr("text-anchor", "middle").text(t);
      const topA = d3.min(A, (d) => d.y) - r - 22, topB = d3.min(B, (d) => d.y) - r - 22;
      lab(xA, topA, MOB ? `${vN} with attack code` : `${vN} had public attack code`, "lbl-big");
      lab(xB, topB - (MOB ? 0 : 20), `${bN} blind spots`, "lbl-big blind-lbl").attr("opacity", 0);
      if (!MOB) lab(xB, topB, "no attack code · low risk score", "lbl-mute blind-lbl").attr("opacity", 0);
    }
    svg.selectAll(".blind-lbl").transition().duration(dur(500)).attr("opacity", step >= 1 ? 1 : 0);
    svg.selectAll(".bdot").filter((d) => d.grp === "b").transition().duration(dur(500))
      .attr("stroke-opacity", step >= 1 ? 0.75 : 0.25).attr("fill", "#3a2418");
    const simpleV = D.blind.simple_caught_visible, oursV = D.blind.ours_caught_visible;
    const ringData = step === 1 ? dots.filter((d) => d.grp === "v" && d.i < simpleV).map((d) => ({ ...d, c: C.lavender }))
      : step >= 2 ? [...dots.filter((d) => d.grp === "v" && d.i < oursV), ...dots.filter((d) => d.grp === "b" && LIT.includes(d.i))].map((d) => ({ ...d, c: C.mintGlow })) : [];
    svg.selectAll(".ring").data(ringData, (d) => d.grp + d.i).join(
      (e) => e.append("circle").attr("class", "ring").attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", r * 1.9)
        .attr("fill", "none").attr("stroke-width", 2.2).attr("stroke", (d) => d.c).attr("opacity", 0)
        .call((t) => t.transition().delay((d, i) => (REDUCED ? 0 : i * 25)).duration(dur(400)).attr("r", r * 1.42).attr("opacity", 1)),
      (u) => u.attr("stroke", (d) => d.c),
      (x) => x.transition().duration(dur(250)).attr("opacity", 0).remove());
    svg.selectAll(".tally,.who").remove();
    if (step >= 1) {
      const ay = d3.max(A, (d) => d.y) + r + 40, by = d3.max(B, (d) => d.y) + r + 40;
      const who = step === 1 ? "Simple rule" : "Our model", col = step === 1 ? C.lavender : C.mintGlow;
      svg.append("text").attr("class", "tally lbl-big").attr("x", xA).attr("y", ay).attr("text-anchor", "middle")
        .style("fill", col).text(`${who} caught ${step === 1 ? simpleV : oursV}`);
      svg.append("text").attr("class", "tally lbl-big").attr("x", xB).attr("y", by).attr("text-anchor", "middle")
        .style("fill", col).text(`${who} caught ${step === 1 ? 0 : D.blind.ours_caught_blind}`);
    }
    if (step >= 2) {
      const lit = dots.filter((d) => d.grp === "b" && LIT.includes(d.i));
      svg.selectAll(".bdot").filter((d) => d.grp === "b" && LIT.includes(d.i)).attr("filter", "url(#glow)")
        .transition().duration(dur(600)).attr("fill", C.ember);
      const xr = d3.max(B, (d) => d.x) + r * 2.4;
      lit.forEach((d, i) => {
        const c = D.blind.ours_blind_cves[i];
        if (!c || MOB) return;
        svg.append("line").attr("class", "who").attr("x1", d.x + r * 1.5).attr("x2", xr - 6).attr("y1", d.y).attr("y2", d.y).attr("stroke", C.mintGlow);
        svg.append("text").attr("class", "who lbl").attr("x", xr).attr("y", d.y + 5).text(`${c.kev_vendor} · ${c.test_replica}`);
      });
    } else svg.selectAll(".bdot").attr("filter", null);
  }

  // ---------- scene: what Granite reads ----------
  function read(step) {
    if (overlay.select(".reader").empty()) {
      clear();
      const ex = D.example;
      let html = ex.description.replace(/https?:\S+/g, "");
      ex.highlights.forEach((h, i) => { html = html.replace(h.phrase, `\u0000${i}\u0001`); });
      const words = html.split(/(\s+)/).map((w) => (/\s+/.test(w) ? w : `<span class="w">${w}</span>`)).join("");
      const withMarks = words.replace(/\u0000(\d+)\u0001/g, (_, i) => `<mark data-i="${i}">${ex.highlights[i].phrase}</mark>`);
      const rd = overlay.append("div").attr("class", "reader");
      rd.append("span").attr("class", "cve").text(`${ex.cve} · 2025 · no public attack code · low risk score`);
      rd.append("div").attr("class", "desc").html(withMarks);
      rd.append("div").attr("class", "tags");
      rd.append("div").attr("class", "match").html(
        `Closest past attack: <b>${ex.nearest.name || ex.nearest.vendor}</b> (<span class="num">${ex.nearest.cve}</span>), ` +
        `exploited and listed in ${ex.nearest.year_added}. Text similarity ${ex.nearest.similarity.toFixed(2)} out of 1.`);
      const ws = rd.selectAll(".desc .w, .desc mark").style("opacity", REDUCED ? 1 : 0);
      if (!REDUCED) ws.transition().delay((d, i) => i * 28).duration(180).style("opacity", 1);
    }
    const rd = overlay.select(".reader");
    rd.selectAll("mark").classed("on", false); rd.select(".match").classed("show", false); rd.select(".tags").html("");
    if (step >= 1) {
      rd.selectAll("mark").each(function (d, i) { setTimeout(() => this.classList.add("on"), dur(i * 350)); });
      rd.select(".tags").html(D.example.highlights.map((h) => `<span class="tag">${h.label}</span>`).join(""));
      setTimeout(() => rd.select(".match").classed("show", true), dur(1200));
    }
  }

  // ---------- scene: 2026 is different (heatmap) ----------
  function heat(step) {
    const months = D.heat.months, rows = MOB ? D.heat.rows.slice(0, 6) : D.heat.rows;
    const mL = MOB ? 84 : Math.min(160, W * 0.17), mT = MOB ? 64 : 150, mR = MOB ? 10 : 30, mB = MOB ? 64 : 120;
    const x = d3.scaleBand(months, [mL, W - mR]).paddingInner(0.1);
    const y = d3.scaleBand(rows.map((r) => r.name), [mT, H - mB]).paddingInner(0.12);
    const col = d3.scaleSequentialLog([0.02, 0.6], (t) => d3.interpolateInferno(0.12 + 0.86 * t)).clamp(true);
    const jx = x(D.heat.jump_month) - (x.step() - x.bandwidth()) / 2;
    if (svg.select(".cell").empty()) {
      clear();
      svg.classed("interactive", true);
      const cells = rows.flatMap((r) => r.cells.map((c) => ({ ...c, row: r.name })));
      svg.selectAll(".cell").data(cells).join("rect").attr("class", "cell").attr("x", (d) => x(d.month)).attr("y", (d) => y(d.row))
        .attr("width", x.bandwidth()).attr("height", y.bandwidth()).attr("rx", 2)
        .attr("fill", (d) => (d.median_pct == null ? "none" : col(d.median_pct)))
        .attr("stroke", (d) => (d.median_pct == null ? C.line : "none")).attr("opacity", 0)
        .on("mousemove", (e, d) => showTip(e, `<span class="t-cve">${d.row}</span><div class="t-meta">${d.month} · ${fmt(d.n)} new CVEs</div>` +
          (d.median_pct == null ? "Too few CVEs this month" : `Typical risk score (median EPSS): <b>${d.median_pct.toFixed(3)}%</b>`)))
        .on("mouseleave", hideTip)
        .transition().delay((d) => (REDUCED ? 0 : months.indexOf(d.month) * 40)).duration(dur(300)).attr("opacity", 1);
      svg.selectAll(".rl").data(rows).join("text").attr("class", "lbl rl").attr("x", mL - 12).attr("y", (d) => y(d.name) + y.bandwidth() / 2 + 5)
        .attr("text-anchor", "end").style("font-weight", (d) => (d.name === "All CVEs" ? 700 : 500)).text((d) => d.name);
      ["2024", "2025", "2026"].forEach((yr) => {
        const ms = months.filter((m) => m.startsWith(yr)), xa = x(ms[0]), xb = x(ms[ms.length - 1]) + x.bandwidth();
        svg.append("text").attr("class", "lbl-big").attr("x", (xa + xb) / 2).attr("y", mT - 18).attr("text-anchor", "middle").text(yr);
        svg.append("line").attr("x1", xa).attr("x2", xb).attr("y1", mT - 8).attr("y2", mT - 8).attr("stroke", C.line);
      });
      const qt = { "01": "Jan", "04": "Apr", "07": "Jul" };
      svg.selectAll(".mlab").data(months.filter((m) => qt[m.slice(5)])).join("text").attr("class", "lbl-mute mlab")
        .attr("x", (m) => x(m) + x.bandwidth() / 2).attr("y", H - mB + 22).attr("text-anchor", "middle").text((m) => qt[m.slice(5)]);
      // legend
      const lw = Math.min(260, W * 0.3), lg = svg.append("g").attr("transform", `translate(${mL},${H - mB + (MOB ? 36 : 50)})`);
      const grad = svg.append("defs").append("linearGradient").attr("id", "hg");
      d3.range(0, 1.001, 0.05).forEach((t) => grad.append("stop").attr("offset", t).attr("stop-color", col(0.02 * Math.pow(30, t))));
      lg.append("rect").attr("width", lw).attr("height", 10).attr("rx", 2).attr("fill", "url(#hg)");
      const ls = d3.scaleLog([0.02, 0.6], [0, lw]);
      [0.03, 0.1, 0.3].forEach((t) => {
        lg.append("line").attr("x1", ls(t)).attr("x2", ls(t)).attr("y1", 10).attr("y2", 15).attr("stroke", C.muted);
        lg.append("text").attr("class", "lbl-mute").attr("x", ls(t)).attr("y", 31).attr("text-anchor", "middle").text(t + "%");
      });
      if (!MOB) {
        lg.append("text").attr("class", "lbl-mute").attr("x", lw + 16).attr("y", 10).text("typical risk score (median EPSS)");
        lg.append("text").attr("class", "lbl-mute").attr("x", lw + 16).attr("y", 31)
          .text("No June 2026 square: June's holes are scored in July.");
      }
    }
    svg.selectAll(".jump").remove();
    svg.selectAll(".cell").transition().duration(dur(500)).attr("opacity", (d) => (step >= 1 && d.month < D.heat.jump_month ? 0.32 : 1));
    if (step >= 1) { // OWID-style annotated line, label in the top margin
      svg.append("line").attr("class", "jump").attr("x1", jx).attr("x2", jx).attr("y1", mT - (MOB ? 40 : 98)).attr("y2", H - mB + 6)
        .attr("stroke", C.emberGlow).attr("stroke-width", 2).attr("stroke-dasharray", "5 4");
      const tx = svg.append("text").attr("class", "jump").attr("x", jx - 10).attr("y", mT - (MOB ? 46 : 84)).attr("text-anchor", "end");
      tx.append("tspan").attr("class", "lbl-big").style("fill", C.emberGlow).text(`July 2026: typical score ${Math.round(ratio)}× higher`);
      if (!MOB) tx.append("tspan").attr("class", "lbl-mute").attr("x", jx - 10).attr("dy", 22)
        .text(`${D.heat.late_2026_median_pct}% vs ${D.heat.past_median_pct}% in 2024–25 · ${Math.round(D.heat.late_share * 100)}% of the 2026 list`);
    }
  }

  // ---------- scene: too good to be true ----------
  function leak(step) {
    if (overlay.select(".counter").empty()) {
      clear();
      const c = overlay.append("div").attr("class", "callout counter show").style("left", "8%").style("top", MOB ? "4%" : "12%")
        .style("color", C.mintGlow).style("font-size", MOB ? "64px" : "clamp(110px, 13vw, 200px)")
        .html(`<span class="n">${D.leak.honest}</span><small class="cl">CVEs added to KEV, caught · honest model</small>`);
      const done = () => { c.style("color", C.emberGlow); c.select(".cl").html(`with after-the-fact columns, up from ${D.leak.honest} · too good to be true`); };
      if (!REDUCED) {
        const n = c.select(".n");
        d3.select({}).transition().delay(500).duration(1600).ease(d3.easeCubicInOut)
          .tween("n", () => (t) => { n.text(Math.round(D.leak.honest + (D.leak.leaky - D.leak.honest) * t)); }).on("end", done);
      } else { c.select(".n").text(D.leak.leaky); done(); }
    }
    svg.selectAll(".abar").remove();
    if (step >= 1) {
      const x0 = W * 0.08, wmax = W * 0.78, y0 = H * (MOB ? 0.5 : 0.56), bh = Math.max(28, H * 0.065);
      const rows = [{ k: "Added to CISA KEV", v: D.leak.analyzed_exploited, c: C.ember }, { k: "All the others", v: D.leak.analyzed_others, c: C.dot }];
      const g = svg.append("g").attr("class", "abar");
      g.append("text").attr("class", "lbl-big").attr("x", x0).attr("y", y0 - 22).text("Marked “Analyzed” in today's database");
      rows.forEach((r, i) => {
        const y = y0 + i * (bh + 44);
        g.append("text").attr("class", "lbl").attr("x", x0).attr("y", y + 4).text(r.k);
        g.append("rect").attr("x", x0).attr("y", y + 14).attr("height", bh).attr("rx", 4).attr("fill", "#001d6c").attr("width", wmax);
        g.append("rect").attr("x", x0).attr("y", y + 14).attr("height", bh).attr("rx", 4).attr("fill", r.c).attr("width", 0)
          .transition().delay(dur(i * 300)).duration(dur(900)).attr("width", wmax * r.v);
        g.append("text").attr("class", "lbl-num").attr("x", x0 + wmax * r.v - 12).attr("y", y + 14 + bh / 2 + 6)
          .attr("text-anchor", "end").style("font-size", "20px").style("fill", C.ink).text(Math.round(r.v * 100) + "%");
      });
    }
  }

  // ---------- scene: our 500 ----------
  function pack() {
    clear();
    svg.classed("interactive", true);
    const items = D.top.items;
    const groups = d3.groups(items, (d) => d.kind).sort((a, b) => b[1].length - a[1].length);
    const root = d3.hierarchy({ children: groups.map(([g, vv]) => ({ name: g, children: vv })) })
      .sum((d) => (d.rank ? 1 + (501 - d.rank) / 120 : 0)).sort((a, b) => b.value - a.value);
    const side = Math.min(W * 0.94, H * 0.88);
    d3.pack().size([side, side]).padding((d) => (d.depth === 0 ? 10 : 1.6))(root);
    const g = svg.append("g").attr("transform", `translate(${(W - side) / 2},${(H - side) / 2})`);
    g.selectAll(".grp").data(root.children).join("circle").attr("class", "grp").attr("cx", (d) => d.x).attr("cy", (d) => d.y)
      .attr("r", (d) => d.r).attr("fill", "#001a5c").attr("stroke", C.line);
    const shade = (rank) => d3.interpolateRgb("#004144", C.mintGlow)(Math.pow(1 - rank / 500, 1.6));
    g.selectAll(".pick").data(root.leaves()).join("circle").attr("class", "pick")
      .attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", 0).attr("fill", (d) => shade(d.data.rank))
      .attr("stroke", C.bg).attr("stroke-width", 0.6)
      .on("mousemove", (e, d) => {
        d3.select(e.currentTarget).attr("stroke", C.ink).attr("stroke-width", 2);
        showTip(e, `<span class="t-cve">#${d.data.rank} · ${d.data.cve}</span><div class="t-meta">${d.data.kind} · reported by ${d.data.group}` +
          `${d.data.exploit ? " · public attack code" : ""}</div>${d.data.reason}`);
      })
      .on("mouseleave", (e) => { d3.select(e.currentTarget).attr("stroke", C.bg).attr("stroke-width", 0.6); hideTip(); })
      .transition().delay((d) => (REDUCED ? 0 : d.data.rank * 3)).duration(dur(450)).attr("r", (d) => d.r);
    const big = root.children.filter((d) => d.r > side * (MOB ? 0.14 : 0.075));
    g.selectAll(".gl").data(big).join("text").attr("class", "gl lbl-big").attr("x", (d) => d.x).attr("y", (d) => d.y - d.r - 8)
      .attr("text-anchor", "middle").style("font-size", MOB ? "13px" : "19px")
      .style("paint-order", "stroke").style("stroke", C.bg).style("stroke-width", 5)
      .text((d) => `${d.data.name} · ${d.children.length}`);
    const small = root.children.filter((d) => !big.includes(d));
    if (small.length && !MOB) svg.append("text").attr("class", "lbl-mute").attr("x", 16).attr("y", H - 18)
      .text("Smaller: " + small.map((d) => `${d.data.name} ${d.children.length}`).join(" · "));
  }

  // ---------- scene: honest results ----------
  function results() {
    clear();
    const vb = sumYears(base), vo = sumYears(ours), [lo, hi] = D.diff90, diff = vo - vb;
    const cx1 = W * 0.27, cx2 = W * 0.67, ny = H * (MOB ? 0.08 : 0.16);
    const big = (x, val, color, label, sub) => {
      const el = callout(`<span class="n">0</span><small><b>${label}</b><br>${sub}</small>`, x - W * 0.12, ny)
        .style("color", color).style("font-size", MOB ? "64px" : "clamp(110px, 12vw, 190px)");
      const n = el.select(".n");
      if (REDUCED) n.text(val);
      else d3.select({}).transition().duration(1200).ease(d3.easeCubicOut).tween("n", () => (t) => n.text(Math.round(val * t)));
    };
    big(cx1, vb, C.ink2, "Best simple rule", "CVEs added to KEV, caught");
    big(cx2, vo, C.mintGlow, "Our model", "CVEs added to KEV, caught");
    // the difference, with its range
    const yd = H * (MOB ? 0.72 : 0.7), xd = d3.scaleLinear([-6, 10], [W * 0.1, W * 0.9]);
    svg.append("text").attr("class", "lbl-big").attr("x", W * 0.1).attr("y", yd - 58).text("How sure are we? Our edge, with its 90% uncertainty range");
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${yd + 30})`)
      .call(d3.axisBottom(xd).ticks(8).tickFormat((t) => (t > 0 ? "+" + t : t)).tickSize(4)).call((a) => a.select(".domain").attr("stroke", C.line));
    svg.append("line").attr("x1", xd(0)).attr("x2", xd(0)).attr("y1", yd - 30).attr("y2", yd + 30).attr("stroke", C.muted).attr("stroke-dasharray", "4 4");
    svg.append("text").attr("class", "lbl-mute").attr("x", xd(0) - 8).attr("y", yd - 34).attr("text-anchor", "end").text("no difference");
    svg.append("line").attr("x1", xd(diff)).attr("x2", xd(diff)).attr("y1", yd).attr("y2", yd).attr("stroke", C.mint).attr("stroke-width", 12)
      .attr("stroke-linecap", "round").attr("opacity", 0.45).transition().delay(dur(900)).duration(dur(900)).attr("x1", xd(lo)).attr("x2", xd(hi));
    svg.append("circle").attr("cx", xd(diff)).attr("cy", yd).attr("r", 12).attr("fill", C.mintGlow);
    svg.append("text").attr("class", "lbl-num").attr("x", xd(diff)).attr("y", yd + 6).attr("dy", -24).attr("text-anchor", "middle")
      .style("font-size", "22px").style("fill", C.mintGlow).text((diff > 0 ? "+" : "") + diff);
  }

  // ---------- progress dots ----------
  const steps = [...document.querySelectorAll(".step")];
  const scenes = [...new Set(steps.map((s) => s.dataset.scene))];
  const nav = d3.select(".progress");
  nav.selectAll("button").data(scenes).join("button").attr("type", "button")
    .attr("aria-label", (s) => "Go to: " + (steps.find((x) => x.dataset.scene === s).dataset.title || s))
    .attr("title", (s) => steps.find((x) => x.dataset.scene === s).dataset.title || s)
    .on("click", (e, s) => steps.find((x) => x.dataset.scene === s).scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "center" }));
  function markNav(scene) {
    const k = scenes.indexOf(scene);
    nav.selectAll("button").classed("now", (s, i) => i === k).classed("done", (s, i) => i < k);
  }
  new IntersectionObserver(([e]) => nav.classed("on", e.isIntersecting), { threshold: 0.05 }).observe(document.getElementById("story"));

  // ---------- router ----------
  const fieldScenes = { field: true, grid: true };
  const SCENES = { why, fan, blind, read, heat, leak, pack, results };
  function render(scene, step, force) {
    if (!force && current.scene === scene && current.step === step) return;
    const sceneChanged = current.scene !== scene;
    hideTip(); markNav(scene);
    canvas.style.transition = REDUCED ? "none" : "opacity .6s";
    canvas.style.opacity = fieldScenes[scene] ? 1 : 0;
    if (fieldScenes[scene]) {
      if (sceneChanged) clear();
      startTwinkle();
      if (scene === "field") animateField({ show: 1, fire: step >= 1 ? 1 : 0, grid: 0 }, dur(step === 0 ? 1200 : 900));
      else {
        animateField({ show: 1, fire: 1, grid: 1 }, dur(1400));
        setTimeout(() => {
          if (current.scene !== "grid") return;
          const [gx, gy, s] = gridPos(0);
          callout(`500<small>the most a team can patch</small>`, gx - s * 0.3, Math.max(8, gy - s - (MOB ? 90 : 150)))
            .style("font-size", MOB ? "48px" : "clamp(56px,6vw,96px)");
        }, dur(1200));
      }
    } else {
      stopTwinkle();
      if (sceneChanged) clear();
      SCENES[scene](step);
    }
    current = { scene, step };
  }

  size();
  const scroller = scrollama();
  scroller.setup({ step: ".step", offset: 0.6 }).onStepEnter(({ element }) => {
    steps.forEach((s) => s.classList.toggle("is-active", s === element));
    render(element.dataset.scene, +element.dataset.step);
  });
  let rt;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(() => {
      size(); const c = current; current = { scene: null, step: -1 };
      if (c.scene) render(c.scene, c.step, true);
      scroller.resize();
    }, 150);
  });
  window.__story = { render, D };
})();
