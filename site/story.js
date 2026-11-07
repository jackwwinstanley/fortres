/* Before the Breach: scroll story. Every number comes from data/story.json (python -m src.b.export_story). */
(async function () {
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const D = await fetch("data/story.json").then((r) => r.json());
  const C = { bg: "#0b1026", dot: "#3a4670", ember: "#e8622a", emberGlow: "#ffb07a", mint: "#19a98c",
    mintGlow: "#6ff0d0", violet: "#9277e6", ink: "#eef1fb", ink2: "#b9c0dc", muted: "#7d87ad", line: "#2a3463" };
  const fmt = d3.format(",");
  const dur = (ms) => (REDUCED ? 0 : ms);

  // ---------- derived numbers, written into the text ----------
  const caught = d3.sum(D.fan, (d) => d.caught), exploited = d3.sum(D.fan, (d) => d.exploited);
  const ratio = D.heat.late_2026_median_pct / D.heat.past_median_pct;
  const ours = D.results.find((r) => r.is_ours), base = D.results.find((r) => r.name.startsWith("Public exploit"));
  const sumYears = (r) => d3.sum(Object.values(r.by_year));
  const K = {
    "field.scoreboard": fmt(D.field.scoreboard), "field.one_in": fmt(D.field.one_in), "field.expected_2026": fmt(D.field.expected_2026),
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

  function size() {
    const r = sticky.getBoundingClientRect();
    W = r.width; FH = r.height; MOB = W < 820; H = MOB ? FH * 0.6 : FH; // phones: graphics in the top 60%, cards below
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * DPR; canvas.height = FH * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    svg.attr("viewBox", `0 0 ${W} ${H}`);
  }

  // ---------- scene 1 & 2: the field (canvas) ----------
  const N = D.field.scoreboard, rng = d3.randomLcg(7);
  const px = new Float32Array(N), py = new Float32Array(N);
  for (let i = 0; i < N; i++) { px[i] = rng(); py[i] = rng(); }
  const fires = d3.shuffle(d3.range(500, N), rng).slice(0, D.field.expected_2026); // indices that ignite
  const F = { show: 0, fire: 0, grid: 0 }; // animated 0..1 states
  let tween = null;

  function gridPos(i) { // 500 dots: 25 x 20 grid, centred
    const cols = 25, rows = 20, s = Math.min((W * 0.62) / cols, (H * 0.62) / rows);
    const x0 = (W - s * (cols - 1)) / 2, y0 = (H - s * (rows - 1)) / 2;
    return [x0 + (i % cols) * s, y0 + Math.floor(i / cols) * s, s];
  }

  function drawField() {
    ctx.clearRect(0, 0, W, FH);
    const m = 24, w = W - 2 * m, h = FH - 2 * m, sz = Math.max(1.2, Math.sqrt((w * h) / N) * 0.55);
    // background dots (all except the 500 grid dots), fade out as the grid forms
    ctx.globalAlpha = F.show * (1 - F.grid * 0.92);
    ctx.fillStyle = C.dot;
    ctx.beginPath();
    for (let i = 500; i < N; i++) ctx.rect(m + px[i] * w, m + py[i] * h, sz, sz);
    ctx.fill();
    // the first 500 dots travel into the grid
    const g = d3.easeCubicInOut(F.grid);
    ctx.globalAlpha = F.show;
    for (let i = 0; i < 500; i++) {
      const [gx, gy, s] = gridPos(i);
      const x = m + px[i] * w, y = m + py[i] * h;
      const r = sz / 2 + g * (s * 0.32 - sz / 2);
      ctx.fillStyle = g > 0.02 ? d3.interpolateRgb(C.dot, C.ink2)(g) : C.dot;
      ctx.beginPath(); ctx.arc(x + (gx - x) * g, y + (gy - y) * g, r, 0, 2 * Math.PI); ctx.fill();
    }
    // fires: ember dots with a soft halo
    if (F.fire > 0) {
      const a = F.fire * (1 - F.grid * 0.85);
      for (const i of fires) {
        const x = m + px[i] * w, y = m + py[i] * h;
        const halo = ctx.createRadialGradient(x, y, 0, x, y, 14);
        halo.addColorStop(0, "rgba(255,176,122,0.55)"); halo.addColorStop(1, "rgba(255,176,122,0)");
        ctx.globalAlpha = a; ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(x, y, 14, 0, 2 * Math.PI); ctx.fill();
        ctx.fillStyle = C.ember; ctx.beginPath(); ctx.arc(x, y, 3, 0, 2 * Math.PI); ctx.fill();
      }
    }
    ctx.globalAlpha = 1;
  }

  function animateField(target, ms) {
    if (tween) tween.stop();
    const from = { ...F };
    if (!ms) { Object.assign(F, target); drawField(); return; }
    tween = d3.timer((t) => {
      const k = Math.min(1, t / ms);
      for (const key in target) F[key] = from[key] + (target[key] - from[key]) * k;
      drawField();
      if (k >= 1) tween.stop();
    });
  }

  // ---------- helpers ----------
  const clear = () => { svg.selectAll("*").interrupt().remove(); overlay.html(""); svg.classed("interactive", false); };
  function callout(html, x, y, cls = "", align = "left") {
    const el = overlay.append("div").attr("class", "callout " + cls).html(html)
      .style("left", align === "left" ? x + "px" : null).style("right", align === "right" ? W - x + "px" : null)
      .style("top", y + "px");
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
  const hideTip = () => { tip.hidden = true; };

  // ---------- scene 3: the fan ----------
  function fan(step) {
    const T = H * 0.42, cy = H * 0.5, x0 = W * 0.06, xs = W * 0.3, x1 = W * 0.62;
    const pc = caught / exploited;
    const band = (y0t, y0b, y1t, y1b, xa, xb) => {
      const xm = (xa + xb) / 2;
      return `M${xa},${y0t} C${xm},${y0t} ${xm},${y1t} ${xb},${y1t} L${xb},${y1b} C${xm},${y1b} ${xm},${y0b} ${xa},${y0b} Z`;
    };
    if (step === 0 || svg.select(".trunk").empty()) {
      clear();
      svg.append("rect").attr("class", "trunk").attr("x", x0).attr("y", cy - T / 2).attr("height", T).attr("width", 0)
        .attr("fill", C.ember).attr("opacity", 0.85).transition().duration(dur(900)).attr("width", xs - x0);
      svg.append("text").attr("class", "lbl-big").attr("x", x0).attr("y", cy - T / 2 - 14)
        .text(`${exploited} holes attackers used`);
      if (!MOB) svg.append("text").attr("class", "lbl-mute").attr("x", x0).attr("y", cy + T / 2 + 22)
        .text(`2024 + 2025 practice years (${D.fan.map((d) => d.exploited).join(" + ")})`);
    }
    if (step >= 1) {
      const gap = H * 0.05, tc = T * pc, tm = T * (1 - pc);
      const yc = cy - T / 2 - gap * 2.2, ym = cy - T / 2 + tc + gap * 1.6;
      const clip = svg.append("clipPath").attr("id", "fanclip").append("rect").attr("x", xs).attr("y", 0).attr("height", H).attr("width", 0);
      const g = svg.append("g").attr("clip-path", "url(#fanclip)");
      g.append("path").attr("d", band(cy - T / 2, cy - T / 2 + tc, yc, yc + tc, xs, x1)).attr("fill", C.ink2).attr("opacity", 0.9);
      g.append("path").attr("d", band(cy - T / 2 + tc + 1.5, cy + T / 2, ym, ym + tm, xs, x1)).attr("fill", C.ember).attr("opacity", 0.9);
      clip.transition().duration(dur(1100)).ease(d3.easeCubicOut).attr("width", x1 - xs + 2);
      const cx = x1 + 14;
      callout(`${Math.round(pc * 100)}%<small>caught by the simple rule (${caught})</small>`, cx, yc + tc / 2 - 40);
      callout(`${100 - Math.round(pc * 100)}%<small>missed (${exploited - caught})</small>`, cx, ym + tm / 2 - 40, "ember-c");
      overlay.selectAll(".ember-c").style("color", C.emberGlow);
    }
  }

  // ---------- scene 4: blind spots ----------
  function blind(step) {
    const v = D.blind.visible, b = D.blind.blind;
    const r = Math.max(6, Math.min(W, H) / 46), s = r * 2.7;
    const cluster = (n, cols, cx, cy) => d3.range(n).map((i) => ({
      x: cx - ((cols - 1) * s) / 2 + (i % cols) * s, y: cy - ((Math.ceil(n / cols) - 1) * s) / 2 + Math.floor(i / cols) * s }));
    const A = cluster(v, 5, W * 0.24, H * 0.52), B = cluster(b, 7, W * 0.6, H * 0.52);
    const dots = [...A.map((p, i) => ({ ...p, grp: "v", i })), ...B.map((p, i) => ({ ...p, grp: "b", i }))];
    if (svg.select(".bdot").empty()) {
      clear();
      const defs = svg.append("defs");
      const f = defs.append("filter").attr("id", "glow").attr("x", "-80%").attr("y", "-80%").attr("width", "260%").attr("height", "260%");
      f.append("feGaussianBlur").attr("stdDeviation", 4).attr("result", "b");
      const fm = f.append("feMerge"); fm.append("feMergeNode").attr("in", "b"); fm.append("feMergeNode").attr("in", "SourceGraphic");
      svg.selectAll(".bdot").data(dots).join("circle").attr("class", "bdot").attr("cx", (d) => d.x).attr("cy", (d) => d.y)
        .attr("r", 0).attr("fill", (d) => (d.grp === "v" ? C.ember : "#3b2a2a")).attr("stroke", (d) => (d.grp === "b" ? C.ember : "none"))
        .attr("stroke-opacity", 0.45).attr("stroke-width", 1)
        .transition("grow").delay((d, i) => (REDUCED ? 0 : i * 12)).duration(dur(400)).attr("r", r);
      const lab = (x, y, t, cls) => svg.append("text").attr("class", cls).attr("x", x).attr("y", y).attr("text-anchor", "middle").text(t);
      const topA = d3.min(A, (d) => d.y) - r - 20, topB = d3.min(B, (d) => d.y) - r - 20;
      lab(W * 0.24, topA, MOB ? `${v} with attack code` : `${v} had public attack code`, "lbl-big");
      lab(W * 0.6, topB, `${b} blind spots`, "lbl-big blind-lbl").attr("opacity", 0);
      if (!MOB) lab(W * 0.6, topB + 18, "no attack code · low risk score", "lbl-mute blind-lbl").attr("opacity", 0);
    }
    svg.selectAll(".blind-lbl").transition().duration(dur(500)).attr("opacity", step >= 1 ? 1 : 0);
    svg.selectAll(".bdot").filter((d) => d.grp === "b").transition().duration(dur(500))
      .attr("fill", step >= 1 ? "#3b2a2a" : "#2a2440").attr("stroke-opacity", step >= 1 ? 0.7 : 0.25);
    // rings: simple rule (grey) at step 1, ours (mint) at step 2
    const simpleV = D.blind.simple_caught_visible, oursV = D.blind.ours_caught_visible, oursB = D.blind.ours_caught_blind;
    const LIT = [13, 34].slice(0, oursB); // which blind dots light up (positions only; counts come from the data)
    const ringData = step === 1 ? dots.filter((d) => d.grp === "v" && d.i < simpleV).map((d) => ({ ...d, c: C.ink2 }))
      : step >= 2 ? [...dots.filter((d) => d.grp === "v" && d.i < oursV), ...dots.filter((d) => d.grp === "b" && LIT.includes(d.i))].map((d) => ({ ...d, c: C.mintGlow })) : [];
    svg.selectAll(".ring").data(ringData, (d) => d.grp + d.i).join(
      (e) => e.append("circle").attr("class", "ring").attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", r * 1.9)
        .attr("fill", "none").attr("stroke-width", 2).attr("stroke", (d) => d.c).attr("opacity", 0)
        .call((t) => t.transition().delay((d, i) => (REDUCED ? 0 : i * 25)).duration(dur(400)).attr("r", r * 1.45).attr("opacity", 1)),
      (u) => u.attr("stroke", (d) => d.c),
      (x) => x.transition().duration(dur(250)).attr("opacity", 0).remove());
    svg.selectAll(".tally").remove();
    if (step >= 1) {
      const by = d3.max(B, (d) => d.y) + r + 34, ay = d3.max(A, (d) => d.y) + r + 34;
      const who = step === 1 ? "Simple rule" : "Our model";
      const col = step === 1 ? C.ink2 : C.mintGlow;
      svg.append("text").attr("class", "tally lbl-big").attr("x", W * 0.24).attr("y", ay).attr("text-anchor", "middle")
        .attr("fill", col).style("fill", col).text(`${who} caught ${step === 1 ? simpleV : oursV}`);
      svg.append("text").attr("class", "tally lbl-big").attr("x", W * 0.6).attr("y", by).attr("text-anchor", "middle")
        .style("fill", col).text(`${who} caught ${step === 1 ? 0 : oursB}`);
    }
    svg.selectAll(".bdot").attr("filter", null);
    if (step >= 2) {
      const lit = dots.filter((d) => d.grp === "b" && LIT.includes(d.i));
      svg.selectAll(".bdot").filter((d) => d.grp === "b" && LIT.includes(d.i)).attr("filter", "url(#glow)")
        .transition().duration(dur(600)).attr("fill", C.ember);
      const xr = d3.max(B, (d) => d.x) + r * 2.6;
      svg.selectAll(".who").data(lit).join("g").attr("class", "who").each(function (d, i) {
        const c = D.blind.ours_blind_cves[i], g = d3.select(this);
        g.append("line").attr("x1", d.x + r * 1.5).attr("x2", xr - 6).attr("y1", d.y).attr("y2", d.y).attr("stroke", C.mintGlow).attr("stroke-width", 1);
        if (!MOB) g.append("text").attr("class", "lbl").attr("x", xr).attr("y", d.y + 4).text(c ? `${c.kev_vendor} · ${c.test_replica}` : "");
      });
      if (MOB) svg.append("text").attr("class", "who lbl").attr("x", W / 2).attr("y", d3.max(B, (d) => d.y) + r + 56).attr("text-anchor", "middle")
        .text("Caught: " + D.blind.ours_blind_cves.map((c) => `${c.kev_vendor} ${c.test_replica}`).join(" · "));
    } else svg.selectAll(".who").remove();
  }

  // ---------- scene 5: what Granite reads ----------
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
        `Closest past attack: <b>${D.example.nearest.name || D.example.nearest.vendor}</b> (${ex.nearest.cve}), ` +
        `exploited and listed in ${ex.nearest.year_added}. Text similarity ${ex.nearest.similarity.toFixed(2)} out of 1.`);
      const ws = rd.selectAll(".desc .w, .desc mark").style("opacity", REDUCED ? 1 : 0);
      if (!REDUCED) ws.transition().delay((d, i) => i * 28).duration(180).style("opacity", 1);
    }
    const rd = overlay.select(".reader");
    rd.selectAll("mark").classed("on", false);
    rd.select(".match").classed("show", false);
    rd.select(".tags").html("");
    if (step >= 1) {
      rd.selectAll("mark").each(function (d, i) { setTimeout(() => this.classList.add("on"), dur(i * 350)); });
      rd.select(".tags").html(D.example.highlights.map((h) => `<span class="tag">${h.label}</span>`).join(""));
      setTimeout(() => rd.select(".match").classed("show", true), dur(1200));
    }
  }

  // ---------- scene 6: heatmap ----------
  function heat(step) {
    const months = D.heat.months, rows = MOB ? D.heat.rows.slice(0, 6) : D.heat.rows;
    const mL = MOB ? 78 : Math.min(150, W * 0.2), mT = 70, mR = MOB ? 8 : 24, mB = MOB ? 36 : 70;
    const x = d3.scaleBand(months, [mL, W - mR]).paddingInner(0.12);
    const y = d3.scaleBand(rows.map((r) => r.name), [mT, H - mB]).paddingInner(0.14);
    const col = d3.scaleSequentialLog([0.02, 0.6], d3.interpolateRgbBasis(["#1b1a44", "#4a3c9a", C.violet, "#e9e1ff"])).clamp(true);
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
      svg.selectAll(".rl").data(rows).join("text").attr("class", "lbl rl").attr("x", mL - 10).attr("y", (d) => y(d.name) + y.bandwidth() / 2 + 4)
        .attr("text-anchor", "end").style("font-weight", (d) => (d.name === "All CVEs" ? 700 : 500)).text((d) => d.name);
      ["2024", "2025", "2026"].forEach((yr) => {
        const ms = months.filter((m) => m.startsWith(yr));
        const xa = x(ms[0]), xb = x(ms[ms.length - 1]) + x.bandwidth();
        svg.append("text").attr("class", "lbl-big").attr("x", (xa + xb) / 2).attr("y", mT - 26).attr("text-anchor", "middle").text(yr);
        svg.append("line").attr("x1", xa).attr("x2", xb).attr("y1", mT - 16).attr("y2", mT - 16).attr("stroke", C.line);
      });
      if (!MOB) svg.append("text").attr("class", "lbl-mute").attr("x", mL).attr("y", H - mB + 26)
        .text("Each column is one month of new CVEs (Jan–Sep of each year; the 2026 list has no June data)");
      // legend
      const lg = svg.append("g").attr("transform", `translate(${mL},${H - mB + (MOB ? 12 : 40)})`), lw = Math.min(220, W * 0.3);
      const grad = svg.append("defs").append("linearGradient").attr("id", "hg");
      d3.range(0, 1.01, 0.1).forEach((t) => grad.append("stop").attr("offset", t).attr("stop-color", col(0.02 * Math.pow(30, t))));
      lg.append("rect").attr("width", lw).attr("height", 8).attr("rx", 2).attr("fill", "url(#hg)");
      lg.append("text").attr("class", "lbl-mute").attr("y", 22).text("lower risk score");
      lg.append("text").attr("class", "lbl-mute").attr("x", lw).attr("y", 22).attr("text-anchor", "end").text("higher");
    }
    svg.selectAll(".jump").remove(); overlay.html("");
    svg.selectAll(".cell").transition().duration(dur(500))
      .attr("opacity", (d) => (step >= 1 && d.month < D.heat.jump_month ? 0.35 : 1));
    if (step >= 1) {
      const xj = x(D.heat.jump_month) - (x.step() - x.bandwidth()) / 2;
      svg.append("line").attr("class", "jump").attr("x1", xj).attr("x2", xj).attr("y1", mT - 8).attr("y2", H - mB + 4)
        .attr("stroke", C.emberGlow).attr("stroke-width", 2).attr("stroke-dasharray", "4 4");
      callout(`${Math.round(ratio)}×<small><b>July 2026: scores jump.</b><br>Typical score ${D.heat.late_2026_median_pct}% from July,<br>vs ${D.heat.past_median_pct}% in 2024–25</small>`,
        MOB ? 12 : Math.max(mL, xj - 300), H * (MOB ? 0.3 : 0.36), "card").style("color", C.emberGlow).style("font-size", "clamp(48px,6vw,80px)");
    }
  }

  // ---------- scene 7: too good to be true ----------
  function leak(step) {
    if (overlay.select(".counter").empty()) {
      clear();
      const c = overlay.append("div").attr("class", "callout counter show").style("left", "8%").style("top", "16%").style("color", C.mintGlow)
        .html(`<span class="n">${D.leak.honest}</span><small class="cl">attacked holes caught · honest model</small>`);
      if (!REDUCED) {
        const n = c.select(".n");
        d3.select({}).transition().delay(500).duration(1600).ease(d3.easeCubicInOut)
          .tween("n", () => (t) => { n.text(Math.round(D.leak.honest + (D.leak.leaky - D.leak.honest) * t)); })
          .on("end", () => { c.style("color", C.emberGlow); c.select(".cl").html(`with after-the-fact columns, up from ${D.leak.honest} · too good to be true`); });
      } else {
        c.select(".n").text(D.leak.leaky); c.style("color", C.emberGlow);
        c.select(".cl").html(`with after-the-fact columns, up from ${D.leak.honest} · too good to be true`);
      }
    }
    svg.selectAll(".abar").remove();
    if (step >= 1) {
      const x0 = W * 0.08, wmax = W * 0.7, y0 = H * 0.58, bh = Math.max(26, H * 0.05);
      const rows = [{ k: "Attacked holes", v: D.leak.analyzed_exploited, c: C.ember }, { k: "All the others", v: D.leak.analyzed_others, c: C.dot }];
      const g = svg.append("g").attr("class", "abar");
      g.append("text").attr("class", "lbl-big").attr("x", x0).attr("y", y0 - 18).text("Marked “Analyzed” in today's database");
      rows.forEach((r, i) => {
        const y = y0 + i * (bh + 34);
        g.append("text").attr("class", "lbl").attr("x", x0).attr("y", y + 2).text(r.k);
        g.append("rect").attr("x", x0).attr("y", y + 10).attr("height", bh).attr("rx", 4).attr("fill", "#151d42").attr("width", wmax);
        g.append("rect").attr("x", x0).attr("y", y + 10).attr("height", bh).attr("rx", 4).attr("fill", r.c).attr("width", 0)
          .transition().delay(dur(i * 300)).duration(dur(900)).attr("width", wmax * r.v);
        g.append("text").attr("class", "lbl-big").attr("x", x0 + wmax * r.v - 10).attr("y", y + 10 + bh / 2 + 5)
          .attr("text-anchor", "end").style("fill", C.ink).text(Math.round(r.v * 100) + "%");
      });
    }
  }

  // ---------- scene 8: our 500 ----------
  function pack() {
    clear();
    svg.classed("interactive", true);
    const items = D.top.items;
    const groups = d3.groups(items, (d) => d.group).sort((a, b) => b[1].length - a[1].length);
    const root = d3.hierarchy({ children: groups.map(([g, v]) => ({ name: g, children: v })) })
      .sum((d) => (d.rank ? 1 + (501 - d.rank) / 120 : 0)).sort((a, b) => b.value - a.value);
    const side = Math.min(W, H) * 0.94;
    d3.pack().size([side, side]).padding((d) => (d.depth === 0 ? 8 : 1.6))(root);
    const g = svg.append("g").attr("transform", `translate(${(W - side) / 2},${(H - side) / 2})`);
    g.selectAll(".grp").data(root.children).join("circle").attr("class", "grp").attr("cx", (d) => d.x).attr("cy", (d) => d.y)
      .attr("r", (d) => d.r).attr("fill", "#10173a").attr("stroke", C.line);
    const leaves = g.selectAll(".pick").data(root.leaves()).join("circle").attr("class", "pick")
      .attr("cx", (d) => d.x).attr("cy", (d) => d.y).attr("r", 0)
      .attr("fill", (d) => d3.interpolateRgb("#1d2a5e", C.mint)(0.25 + 0.75 * (1 - d.data.rank / 500)))
      .attr("stroke", C.mintGlow).attr("stroke-opacity", 0.55).attr("stroke-width", 0.8)
      .on("mousemove", (e, d) => {
        d3.select(e.currentTarget).attr("stroke-opacity", 1).attr("stroke-width", 2);
        showTip(e, `<span class="t-cve">#${d.data.rank} · ${d.data.cve}</span><div class="t-meta">${d.data.group} · ${d.data.flaw}` +
          `${d.data.exploit ? " · public attack code" : ""}</div>${d.data.reason}`);
      })
      .on("mouseleave", (e) => { d3.select(e.currentTarget).attr("stroke-opacity", 0.55).attr("stroke-width", 0.8); hideTip(); });
    leaves.transition().delay((d) => (REDUCED ? 0 : d.data.rank * 3)).duration(dur(450)).attr("r", (d) => d.r);
    g.selectAll(".gl").data(root.children.filter((d) => d.r > side * (MOB ? 0.16 : 0.07))).join("text").attr("class", "gl lbl-big")
      .attr("x", (d) => d.x).attr("y", (d) => d.y - d.r + 18).attr("text-anchor", "middle")
      .style("paint-order", "stroke").style("stroke", C.bg).style("stroke-width", 4)
      .text((d) => `${d.data.name} (${d.children.length})`);
  }

  // ---------- scene 9: honest results ----------
  function results() {
    clear();
    const h = D.headline, mL = W * 0.1, mR = W * 0.1, y1 = H * 0.3, y2 = H * 0.46;
    const x = d3.scaleLinear([0, D.blind.visible + D.blind.blind], [mL, W - mR]);
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${y2 + 40})`)
      .call(d3.axisBottom(x).ticks(5).tickSize(4)).call((a) => a.select(".domain").attr("stroke", C.line));
    svg.append("text").attr("class", "lbl-mute").attr("x", mL).attr("y", y2 + 80)
      .text(`attacked holes caught in the 2024 + 2025 tests, out of ${D.blind.visible + D.blind.blind}`);
    [[base, y1, C.ink2, "Best simple rule"], [ours, y2, C.mintGlow, "Our model"]].forEach(([r, y, c, label]) => {
      const v = sumYears(r);
      svg.append("line").attr("x1", x(0)).attr("x2", x(0)).attr("y1", y).attr("y2", y).attr("stroke", c).attr("stroke-width", 3)
        .transition().duration(dur(900)).attr("x2", x(v));
      svg.append("circle").attr("cx", x(0)).attr("cy", y).attr("r", 9).attr("fill", c)
        .transition().duration(dur(900)).attr("cx", x(v));
      svg.append("text").attr("class", "lbl-big").attr("x", mL).attr("y", y - 16).style("fill", c).text(`${label}: ${v}`);
    });
    // the difference with its range
    const yd = H * 0.72, xd = d3.scaleLinear([-6, 10], [mL, W - mR]);
    const [lo, hi] = h.diff_vs_baseline_cve_level_90, diff = h.pooled_hits_bag - h.baseline_pooled_hits;
    svg.append("text").attr("class", "lbl-big").attr("x", mL).attr("y", yd - 40).text("Our edge, with its 90% uncertainty range");
    svg.append("line").attr("x1", xd(0)).attr("x2", xd(0)).attr("y1", yd - 22).attr("y2", yd + 22).attr("stroke", C.muted).attr("stroke-dasharray", "3 3");
    svg.append("text").attr("class", "lbl-mute").attr("x", xd(0)).attr("y", yd + 40).attr("text-anchor", "middle").text("no difference");
    svg.append("line").attr("x1", xd(lo)).attr("x2", xd(hi)).attr("y1", yd).attr("y2", yd).attr("stroke", C.mint).attr("stroke-width", 6)
      .attr("stroke-linecap", "round").attr("opacity", 0.5);
    svg.append("circle").attr("cx", xd(diff)).attr("cy", yd).attr("r", 9).attr("fill", C.mintGlow);
    svg.append("text").attr("class", "lbl").attr("x", xd(lo)).attr("y", yd - 14).attr("text-anchor", "middle").text(lo);
    svg.append("text").attr("class", "lbl").attr("x", xd(hi)).attr("y", yd - 14).attr("text-anchor", "middle").text("+" + hi);
    svg.append("text").attr("class", "lbl-big").attr("x", xd(diff)).attr("y", yd + 32).attr("text-anchor", "middle").style("fill", C.mintGlow).text("+" + diff);
  }

  // ---------- router ----------
  const fieldScenes = { field: true, grid: true };
  function render(scene, step, force) {
    if (!force && current.scene === scene && current.step === step) return;
    const sceneChanged = current.scene !== scene;
    hideTip();
    canvas.style.opacity = fieldScenes[scene] ? 1 : 0;
    canvas.style.transition = REDUCED ? "none" : "opacity .6s";
    if (fieldScenes[scene]) {
      if (sceneChanged) clear();
      if (scene === "field") animateField({ show: 1, fire: step >= 1 ? 1 : 0, grid: 0 }, dur(step === 0 ? 1200 : 900));
      else {
        animateField({ show: 1, fire: 1, grid: 1 }, dur(1400));
        setTimeout(() => {
          if (current.scene !== "grid") return;
          const [, gy, s] = gridPos(0);
          const [gx] = gridPos(0); callout(`500<small>the most a team can patch</small>`, gx - s * 0.3, Math.max(8, gy - s - 130)).style("font-size", "clamp(40px,5vw,72px)");
        }, dur(1200));
      }
    } else {
      if (sceneChanged) clear();
      ({ fan, blind, read, heat, leak, pack, results })[scene](step);
    }
    current = { scene, step };
  }

  size();
  render("field", 0, true);
  const scroller = scrollama();
  scroller.setup({ step: ".step", offset: 0.6 }).onStepEnter(({ element }) => {
    document.querySelectorAll(".step").forEach((s) => s.classList.toggle("is-active", s === element));
    render(element.dataset.scene, +element.dataset.step);
  });
  let rt;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(() => { size(); const c = current; current = { scene: null, step: -1 }; render(c.scene, c.step, true); scroller.resize(); }, 150);
  });
  window.__story = { render, D }; // for screenshots
})();
