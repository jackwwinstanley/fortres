/* Findings page charts. Every value comes from data/findings.json (scripts/export_site_findings.py, read from outputs/)
   or from data- attributes next to the sentence that states it; this file only draws them. One brick = one item. */
(() => {
  const root = document.getElementById('found');
  if (!root) return;
  const REDUCE = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const C = { blue: 'var(--accent)', coral: 'var(--miss)', mint: 'var(--caught)', amber: '#f1c21b', dim: '#2a3646', dim2: '#3a4757', dim3: '#56616f' };
  const fmt = n => n.toLocaleString('en-US');
  let built = false;

  // a grid of bricks; cells = [{c, cls}], wave delay by row then column so rows ripple in
  function bricks(cells, cols, gap = 3, step = 1) {
    const g = document.createElement('div');
    g.className = 'bg';
    g.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
    g.style.setProperty('--g', gap + 'px');
    g.innerHTML = cells.map((x, i) => {
      const r = Math.floor(i / cols), c = i % cols;
      return `<i class="${x.cls || ''}" style="--c:${x.c};--d:${Math.round((r * 40 + c * 6) * step)}"></i>`;
    }).join('');
    return g;
  }
  const rep = (n, c, cls) => Array.from({ length: n }, () => ({ c, cls }));
  // after the bricks are in, recolour some of them (the "reveal" step)
  const later = (sec, ms, fn) => sec.__reveals.push([ms, fn]);

  const draw = {
    blind(sec, v, D) {
      const b = D.blind, warned = b.total - b.blind;
      v.append(bricks([...rep(warned, C.blue), ...rep(b.blind, C.dim2)], 15, 4, 1.2));
      later(sec, 900, () => {                       // the 44 turn coral, then the 5 fortres caught turn green
        const cells = [...v.querySelectorAll('i')].slice(warned);
        cells.forEach((el, k) => { el.style.transitionDelay = (k * 12) + 'ms'; el.style.setProperty('--c', C.coral); });
        setTimeout(() => cells.slice(0, b.ours_caught_blind).forEach((el, k) => { el.style.transitionDelay = (k * 120) + 'ms'; el.style.setProperty('--c', C.mint); }), REDUCE ? 0 : 1100);
      });
    },
    work(sec, v, D) {
      const order = ['fortres', 'usual rule', 'severity', 'EPSS'];
      const name = { fortres: 'fortres', 'usual rule': 'usual rule', severity: 'by severity', EPSS: 'EPSS alone' };
      const col = { fortres: C.mint, 'usual rule': C.dim3, severity: C.amber, EPSS: C.blue };
      const rows = order.map(k => {
        const r = D.workload.find(w => w.method.startsWith(k));
        return { k, n: k === 'fortres' ? r.k : r.fixes_to_match };
      });
      const max = Math.max(...rows.map(r => r.n));
      v.innerHTML = rows.map((r, i) => `<div class="bar${r.k === 'fortres' ? ' me' : ''}"><p class="lbl"><span>${name[r.k]}</span><b class="wn" data-n="${r.n}">${fmt(r.n)}</b></p>` +
        `<div class="tr"><div class="fl" style="--c:${col[r.k]};--w:${(r.n / max).toFixed(4)};--d:${i * 260}"></div></div></div>`).join('') +
        `<p class="lbl" style="margin-top:4px">fixes needed to catch the same 27 · fortres's list is 441 long</p>`;
    },
    sev(sec, v, D) {
      const s = D.severity;
      // the Medium ones are scattered through the grid (a fixed shuffle), hidden among the others until they light up
      const cells = [...rep(s.Critical, C.dim), ...rep(s.High, C.dim2), ...rep(s.Medium, C.dim2, 'med'), ...rep(s.Low + s['None or unscored'], C.dim3)];
      let seed = 7; const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
      for (let i = cells.length - 1; i > 0; i--) { const k = Math.floor(rnd() * (i + 1)); [cells[i], cells[k]] = [cells[k], cells[i]]; }
      const w = innerWidth < 700 ? 38 : 53;
      v.append(bricks(cells, w, 1.5, 0.25));
      later(sec, 1400, () => {
        v.querySelectorAll('i.med').forEach((el, k) => { el.style.transitionDelay = (k * 6) + 'ms'; el.style.setProperty('--c', C.amber); });
      });
    },
    leak(sec, v, D) {
      const L = D.leakage;
      v.append(bricks([...rep(L.honest, C.mint), ...rep(L.leaky - L.honest, '', 'ghost')], 11, 6, 2));
    },
    reasons(sec, v, D) {
      const R = D.reasons;
      v.append(bricks([...rep(R.passed_guardian, C.mint), ...rep(R.local_failed, C.amber), ...rep(R.guardian_rejected, C.coral)], 25, 3, 0.5));
    },
    events(sec, v, D) {
      const t0 = Date.parse('2024-01-01'), t1 = Date.parse('2026-01-01');
      const byDay = {};
      D.events.forEach(([d, vendor, n]) => (byDay[d] = byDay[d] || []).push([vendor, n]));
      const g = document.createElement('div'); g.className = 'tlg';
      Object.entries(byDay).forEach(([d, evs], j) => {
        const x = (Date.parse(d) - t0) / (t1 - t0) * 100;
        const col = document.createElement('div'); col.className = 'ev bg'; col.style.left = x + '%';
        col.title = evs.map(([vd, n]) => `${d} · ${vd} · ${n} hole${n > 1 ? 's' : ''}`).join('\n');
        col.innerHTML = evs.flatMap(([, n]) => Array.from({ length: n }, () => `<i style="--c:${n > 1 ? C.blue : C.dim3};--d:${j * 22}"></i>`)).join('');
        g.append(col);
      });
      v.append(g);
      v.insertAdjacentHTML('beforeend', '<div class="ax"><span>Jan 2024</span><span>Jan 2025</span><span>Dec 2025</span></div>');
    },
    vendor(sec, v, D) {
      const V = D.vendor_cv_2025;
      const row = (label, n) => {
        const r = document.createElement('div'); r.className = 'row';
        r.innerHTML = `<p class="lbl"><b>${n}</b>${label}</p>`;
        r.append(bricks([...rep(n, C.mint), ...rep(V.ungrouped - n, '', 'out')], V.ungrouped, 4, 3));
        return r;
      };
      v.append(row('caught when vendors are seen in training', V.ungrouped), row('caught when whole vendors are hidden', V.vendor_grouped));
    },
    epss(sec, v, D) {
      const ms = D.epss_months, max = Math.max(...ms.map(m => m[1]));
      const g = document.createElement('div'); g.className = 'eg';
      let prevYear = null;
      ms.forEach(([m, val], i) => {
        const y = m.slice(0, 4);
        if (prevYear && y !== prevYear) g.insertAdjacentHTML('beforeend', '<span class="gap"></span>');
        prevYear = y;
        const hot = m >= '2026-07';
        g.insertAdjacentHTML('beforeend', `<span class="m" title="${m} · median EPSS ${val}" style="--h:${(val / max * 100).toFixed(1)}%;--c:${hot ? C.blue : C.dim2};--d:${i * 35}"></span>`);
      });
      v.insertAdjacentHTML('beforeend', `<p class="jump">&times;${D.epss_jump} from July 2026</p>`);
      v.append(g);
      v.insertAdjacentHTML('beforeend', '<div class="ax"><span>2024</span><span>2025</span><span>2026</span></div><p class="lbl" style="margin-top:10px">median EPSS score of new holes, by monthly snapshot</p>');
    },
    dates(sec, v) {
      const n = +sec.dataset.n, hl = +sec.dataset.hl;
      v.append(bricks([...rep(hl, C.amber), ...rep(n - hl, C.dim2)], 35, 2, 0.4));
    },
    simple(sec, v) {
      const a = +sec.dataset.a, b = +sec.dataset.b;
      const tile = (k, kept) => `<i class="${kept ? 'kept' : ''}" style="--d:${k * 50}"></i>`;
      v.innerHTML = `<p class="lbl">${a} model variants</p><div class="tg">${Array.from({ length: a }, (_, k) => tile(k, k === a - 1)).join('')}</div>` +
        `<p class="lbl">${b} extra methods</p><div class="tg">${Array.from({ length: b }, (_, k) => tile(a + k, false)).join('')}</div>` +
        `<p class="lbl"><span style="color:var(--caught)">■</span> kept: the more constrained model</p>`;
    }
  };

  // big numbers count up once, with an ease-out, in tabular figures
  function countUp(el) {
    const to = +el.dataset.n; if (REDUCE || !to) return;
    const t0 = performance.now(), D = 900;
    const tick = now => { const k = Math.min(1, (now - t0) / D); el.textContent = fmt(Math.round(to * (1 - Math.pow(1 - k, 3)))); if (k < 1) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  }

  function build(D) {
    if (built) return; built = true;
    const secs = [...root.querySelectorAll('.fd')];
    const idx = root.querySelector('.fidx');
    if (idx) idx.innerHTML = secs.map((s, i) => `<button type="button" data-i="${i}"><b>${String(i + 1).padStart(2, '0')}</b>${s.dataset.t}</button>`).join('');
    if (idx) idx.addEventListener('click', e => { const b = e.target.closest('button'); if (b) secs[+b.dataset.i].scrollIntoView({ behavior: REDUCE ? 'auto' : 'smooth', block: 'start' }); });
    secs.forEach(sec => { sec.__reveals = []; const v = sec.querySelector('.viz'); try { draw[sec.dataset.viz](sec, v, D); } catch (e) { console.warn('finding chart', sec.id, e); } });
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (!e.isIntersecting) return;
      const sec = e.target; io.unobserve(sec);
      sec.classList.add('on');
      sec.querySelectorAll('.cu, .wn').forEach(countUp);
      sec.__reveals.forEach(([ms, fn]) => setTimeout(fn, REDUCE ? 0 : ms));
    }), { threshold: 0.3 });
    secs.forEach(s => io.observe(s));
  }

  let loading = null;
  const go = () => { if (location.hash !== '#found' || built) return; loading = loading || fetch('data/findings.json').then(r => r.json()).then(build).catch(e => console.warn('findings data did not load', e)); };
  addEventListener('hashchange', go);
  go();
})();
