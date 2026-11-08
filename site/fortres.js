/* Fortres page script.
   Numbers on the page come from index.html and data/ (exported from outputs/); this file never changes a value, it only animates to it.
   One requestAnimationFrame loop drives everything (Frame, below). Nothing in the loop reads layout. */
const REDUCE = matchMedia('(prefers-reduced-motion: reduce)').matches;
const Frame = (() => {
  const tasks = new Set(); let id = 0, last = 0, hidden = document.hidden;
  function tick(now) {
    id = 0;
    const dt = Math.min(((now - last) || 16.7) / 1000, 0.1); last = now;
    tasks.forEach(f => { if (f(now, dt) === false) tasks.delete(f); });
    wake();
  }
  function wake() { if (!id && tasks.size && !hidden) { if (!last) last = performance.now(); id = requestAnimationFrame(tick); } }
  document.addEventListener('visibilitychange', () => { hidden = document.hidden; if (hidden) { cancelAnimationFrame(id); id = 0; } else { last = 0; wake(); } });
  return { add(f) { tasks.add(f); wake(); }, remove(f) { tasks.delete(f); } };
})();

/* Count a number up from zero with easing, then restore the exact original text. Width stays fixed so nothing shifts. */
function countUp(el, delay) {
  if (REDUCE || !el) return;
  const n = [...el.childNodes].find(x => x.nodeType === 3 && /\d/.test(x.textContent)); if (!n) return;
  const orig = n.__orig || (n.__orig = n.textContent);
  const m = orig.match(/\d[\d,]*(\.\d+)?/); if (!m) return;
  const to = parseFloat(m[0].replace(/,/g, '')); if (to < 2) return;
  const pre = orig.slice(0, m.index), suf = orig.slice(m.index + m[0].length), dec = (m[1] || '.').length - 1, comma = m[0].includes(',');
  const show = v => pre + (comma ? v.toLocaleString('en-US', { minimumFractionDigits: dec, maximumFractionDigits: dec }) : v.toFixed(dec)).padEnd(m[0].length, ' ') + suf;
  if (n.__task) Frame.remove(n.__task);
  n.textContent = show(0);
  const t0 = performance.now() + (delay || 0), D = 1050;
  n.__task = now => {
    const k = Math.min(1, Math.max(0, (now - t0) / D));
    if (k >= 1) { n.textContent = orig; return false; }
    n.textContent = show(to * (1 - Math.pow(1 - k, 4)));
  };
  Frame.add(n.__task);
}
const routeNow = () => ({ '#picks': 'picks', '#lookup': 'lookup', '#found': 'found' }[location.hash] || 'story');
document.documentElement.classList.toggle('route-picks', routeNow() !== 'story');
document.documentElement.classList.toggle('route-lookup', routeNow() === 'lookup');


let ROUTE = 'story';
fetch('data/picks500.json').then(r => r.json()).then(pages).catch(e => console.warn('Fortres picks did not load', e));

function pages(PICKS) {
  const kinds = ['All', ...[...new Set(PICKS.map(p => p[2]))].sort((a, b) => PICKS.filter(p => p[2] === b).length - PICKS.filter(p => p[2] === a).length)];
  let kind = 'All', shown = 25; const open = new Set([PICKS[0][1]]);
  const chips = document.getElementById('chips');
  chips.innerHTML = kinds.map(k => `<button type="button" class="chip" data-k="${k}" aria-pressed="${k === 'All'}">${k}${k === 'All' ? '' : ' · ' + PICKS.filter(p => p[2] === k).length}</button>`).join('');
  chips.addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; kind = b.dataset.k; shown = 25; chips.querySelectorAll('.chip').forEach(c => c.setAttribute('aria-pressed', c === b)); render(); });
  const q = document.getElementById('q'), g = document.getElementById('gonly'), tb = document.getElementById('tb'), more = document.getElementById('more');
  q.addEventListener('input', () => { shown = 25; render(); }); g.addEventListener('change', () => { shown = 25; render(); });
  more.addEventListener('click', () => { shown += 25; render(); });
  const KC = { 'Takes over the machine': '165,110,255', 'No login needed': '69,137,255', "Reads files it shouldn't": '8,189,186', 'Gets admin powers': '255,126,182', 'Browser bug': '51,177,255', 'Network edge device': '255,131,43', 'Database attack': '66,190,101', 'WordPress plugin': '141,141,141' };
  const ktag = k => `<span class="ktag" style="background:rgba(${KC[k] || '141,141,141'},.18)">${k}</span>`;
  const GL = [[/nuclei template/i, 'Nuclei template', 'a ready-made script that scans computers for this exact hole, so attackers can find it automatically'],
    [/proof of concept/i, 'proof of concept', 'working example code, often on GitHub, that shows the attack works'],
    [/exploit-db/i, 'Exploit-DB', 'a public library of attack code'],
    [/metasploit/i, 'Metasploit', 'a popular hacking toolkit, so the attack is close to one click'],
    [/epss/i, 'EPSS percentile', 'a daily score from FIRST estimating how likely attackers are to use a hole soon; we compare it only with holes from the same month'],
    [/kev-likeness|similarity to past exploited/i, 'KEV-likeness', 'how much the description reads like holes already on CISA\'s list, as scored by IBM Granite'],
    [/unauthenticated/i, 'unauthenticated', 'the attacker doesn\'t need to log in first'],
    [/remote code execution/i, 'remote code execution', 'the attacker can run their own commands on the machine from anywhere'],
    [/path traversal/i, 'path traversal', 'tricking the software into opening files it should never show'],
    [/command injection/i, 'command injection', 'sneaking system commands into normal-looking input'],
    [/sql injection/i, 'SQL injection', 'sneaking database commands into normal-looking input'],
    [/deserialization/i, 'deserialization', 'feeding the software booby-trapped saved data'],
    [/privilege escalation/i, 'privilege escalation', 'going from a normal user to an admin'],
    [/edge-device|edge device/i, 'edge device', 'a firewall or VPN box that sits on the network\'s front door']];
  const plain = r => { const hits = GL.filter(g => g[0].test(r)); return hits.length ? '<ul class="plain">' + hits.map(g => `<li><b>${g[1]}</b>: ${g[2]}</li>`).join('') + '</ul>' : ''; };
  const code = document.getElementById('code'), info = document.getElementById('codeinfo');
  code.innerHTML = PICKS.map((p, i) => `<i class="${p[8] ? 'g' : ''}" data-i="${i}" style="height:${18 + p[5] * 82}%;animation-delay:${i * 1.4}ms"></i>`).join('');
  code.addEventListener('mouseover', e => { const b = e.target.closest('i'); if (!b) return; const p = PICKS[+b.dataset.i]; info.textContent = `#${p[0]} · ${p[1]} · ${p[2]} · EPSS ${(p[5] * 100).toFixed(1)}% in its month`; });
  code.addEventListener('click', e => { const b = e.target.closest('i'); if (!b) return; const p = PICKS[+b.dataset.i]; q.value = p[1]; kind = 'All'; chips.querySelectorAll('.chip').forEach(c => c.setAttribute('aria-pressed', c.dataset.k === 'All')); open.add(p[1]); shown = 25; render(); document.querySelector('.tablebox').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  function render() {
    const s = q.value.trim().toLowerCase();
    const f = PICKS.filter(p => (kind === 'All' || p[2] === kind) && (!g.checked || p[8]) && (!s || (p[1] + ' ' + p[2] + ' ' + p[3] + ' ' + p[4]).toLowerCase().includes(s)));
    document.getElementById('count').textContent = `${Math.min(shown, f.length)} of ${f.length} shown`;
    tb.innerHTML = f.slice(0, shown).map(p => {
      const o = open.has(p[1]);
      return `<tr class="r" tabindex="0" data-c="${p[1]}" aria-expanded="${o}"><td>${p[0]}</td><td class="cve">${p[1]}</td><td>${ktag(p[2])}</td><td>${esc(p[3])}</td><td>${esc(p[4])}</td><td class="pct">${(p[5] * 100).toFixed(1)}%<span class="meter"><i style="width:${p[5] * 100}%"></i></span></td><td>${p[6] ? '<span class="cds-tag coral">public</span>' : '<span class="cds-tag">none</span>'}</td><td>${p[8] ? '<span class="cds-tag mint">Guardian passed</span>' : '<span class="cds-tag">template</span>'}</td></tr>` +
        (o ? `<tr class="detail"><td colspan="8"><div>${esc(p[7])}${plain(p[7])}<span class="src">${p[8] ? 'Written by IBM Granite, passed a Granite Guardian groundedness check' : 'Plain template sentence built from the same facts'}</span></div></td></tr>` : '');
    }).join('') || `<tr><td colspan="8" style="color:var(--mute)">No picks match. Try a vendor name like Microsoft, or clear the filters.</td></tr>`;
    more.hidden = shown >= f.length;
  }
  function toggle(tr) { const c = tr.dataset.c; open.has(c) ? open.delete(c) : open.add(c); render(); const n = tb.querySelector(`[data-c="${c}"]`); if (n) n.focus(); }
  tb.addEventListener('click', e => { const tr = e.target.closest('tr.r'); if (tr) toggle(tr); });
  tb.addEventListener('keydown', e => { const tr = e.target.closest('tr.r'); if (tr && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); toggle(tr); } });
  render();
  // look up
  const IDX = new Map(); let RL = null, rankLoad = null;
  const needRanks = () => rankLoad || (rankLoad = fetch('data/ranks.txt').then(r => { if (!r.ok) throw new Error('ranks'); return r.text(); }).then(t => { RL = t.trim().split(','); RL.forEach((s, i) => IDX.set('CVE-20' + s.slice(0, s.indexOf('.')), i)); }).catch(e => { rankLoad = null; throw e; }));
  document.getElementById('t-lookup').addEventListener('pointerenter', () => needRanks().catch(() => {}), { once: true });
  const PMAP = new Map(PICKS.map(p => [p[1], p]));
  const MONTHS = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  const lres = document.getElementById('lres'), lq = document.getElementById('lq');
  const fmt = n => n.toLocaleString('en-US');
  async function lookup(raw) {
    try { await needRanks(); } catch (e) { lres.innerHTML = `<p class="miss">The ranking list did not load. Refresh and try again.</p>`; return; }
    const m = String(raw).match(/(?:CVE[-_ ]?)?(\d{4})[-_ ](\d{4,7})/i);
    if (!m) { lres.innerHTML = `<p class="miss">Type a CVE ID like CVE-2026-4092.</p>`; return; }
    const id = `CVE-${m[1]}-${m[2]}`; lq.value = id;
    if (!IDX.has(id)) { lres.innerHTML = `<p class="miss"><b style="color:var(--fg)">${id}</b> is not in the 2026 scoreboard. fortres only ranks the 72,670 holes published in 2026.</p>`; return; }
    const i = IDX.get(id), rank = i + 1, [, mo, ep, fl] = RL[i].split('.'), flags = parseInt(fl, 16);
    const code = [[8, 'GitHub proof of concept'], [4, 'Nuclei template'], [1, 'Exploit-DB'], [2, 'Metasploit']].filter(x => flags & x[0]).map(x => x[1]);
    const pick = PMAP.get(id), pct = rank / RL.length * 100;
    const pos = Math.max(0.3, Math.min(99.7, pct));
    lres.innerHTML = `<div class="cv">${id} ${pick ? '<span class="cds-tag mint">in the top 500</span>' : '<span class="cds-tag">not in the top 500</span>'}</div>
      <div class="rk"><b id="lrk">#${fmt(rank)}</b><span>of ${fmt(RL.length)} · ${pct > 50 ? 'in the lower half' : 'top ' + (pct < 0.1 ? pct.toFixed(3) : pct < 1 ? pct.toFixed(2) : pct.toFixed(1)) + '%'}</span></div>
      <div class="lane" aria-hidden="true"><div class="tr"></div><div class="top" style="width:max(3px,${500 / RL.length * 100}%)"></div><div class="mk" style="left:${pos}%"></div><span class="lb">#1 fix first</span><span class="lb r">#${fmt(RL.length)}</span></div>
      <div class="facts2">
        <div><h3>public attack code</h3><p>${code.length ? code.join(', ') : 'None found when it was scored'}</p></div>
        <div><h3>EPSS warning score</h3><p>${ep === '-' ? 'No score yet when it was scored' : `Higher than ${ep}% of holes published that month`}</p></div>
        <div><h3>published</h3><p>${MONTHS[parseInt(mo, 16)]} 2026</p></div>
      </div>` +
      (pick ? `<div class="why"${pick[8] ? '' : ' style="border-left-color:var(--mute)"'}>${esc(pick[7])}${plain(pick[7])}<span class="src">${pick[8] ? 'Written by IBM Granite, passed a Granite Guardian groundedness check' : 'Plain template sentence built from the same facts'}</span></div>`
            : `<p class="note2">It ranks below the 500 we'd fix first, so fortres puts it lower in the queue. We only write reasons for the top 500. The rank is a priority order, not a probability.</p>`);
    countUp(document.getElementById('lrk'));
  }
  document.getElementById('lform').addEventListener('submit', e => { e.preventDefault(); lookup(lq.value); });
  lq.addEventListener('paste', () => setTimeout(() => lookup(lq.value), 0));
  document.querySelector('.tries').addEventListener('click', e => { const b = e.target.closest('button'); if (b) lookup(b.dataset.c); });
  function route() {
    ROUTE = location.hash === '#picks' ? 'picks' : location.hash === '#lookup' ? 'lookup' : location.hash === '#found' ? 'found' : 'story';
    document.documentElement.classList.toggle('route-picks', ROUTE !== 'story');
    document.documentElement.classList.toggle('route-lookup', ROUTE === 'lookup');
    document.documentElement.classList.toggle('route-found', ROUTE === 'found');
    document.getElementById('t-found').setAttribute('aria-current', ROUTE === 'found' ? 'page' : 'false');
    document.getElementById('t-lookup').setAttribute('aria-current', ROUTE === 'lookup' ? 'page' : 'false');
    if (ROUTE === 'lookup') { needRanks().catch(() => {}); countUp(document.getElementById('lnum')); setTimeout(() => lq.focus({ preventScroll: true }), 50); }
    document.getElementById('t-story').setAttribute('aria-current', ROUTE === 'story' ? 'page' : 'false');
    document.getElementById('t-picks').setAttribute('aria-current', ROUTE === 'picks' ? 'page' : 'false');
    if (ROUTE !== 'story' || location.hash === '#story') window.scrollTo(0, 0);
    if (ROUTE === 'picks') { countUp(document.getElementById('dnum')); code.classList.remove('go'); void code.offsetWidth; code.classList.add('go'); }
  }
  addEventListener('hashchange', route); route();
}

/* ---------- the wall: one instanced mesh, moved by the GPU ----------
   Every brick has a start and an end (position, scale, rotation, colour, highlight) stored once per state change.
   The vertex shader does the in-between, so a frame costs no per-brick JavaScript. */
(function wall() {
  const root = document.documentElement;
  const fallback = () => root.classList.add('no-gl');
  const steps = [...document.querySelectorAll('.step')];
  const prog = document.getElementById('prog');
  prog.innerHTML = steps.map(() => '<i></i>').join('');
  const bars = [...prog.children];
  const counted = new WeakSet();

  // text side of each step: runs from an observer, never from the frame loop
  const io = new IntersectionObserver(es => es.forEach(e => {
    if (!e.isIntersecting) return;
    steps.forEach(s => s.classList.toggle('active', s === e.target));
    e.target.querySelectorAll('.num').forEach((n, k) => { if (!counted.has(n)) { counted.add(n); countUp(n, k * 150); } });
    const k = steps.indexOf(e.target); bars.forEach((b, j) => b.classList.toggle('on', j <= k));
  }), { rootMargin: '-45% 0px -45% 0px' });
  steps.forEach(s => io.observe(s));

  // arrow keys, Page Up/Down and space move one whole story step, so each press plays the full scene change and lands
  // on the next block of text instead of nudging the page a little
  let keyTarget = -1, keyTimer = 0;
  const stepY = s => s.offsetTop + s.offsetHeight / 2 - innerHeight / 2;
  addEventListener('keydown', e => {
    const dir = { ArrowDown: 1, PageDown: 1, ' ': e.shiftKey ? -1 : 1, ArrowUp: -1, PageUp: -1 }[e.key];
    if (!dir || e.altKey || e.ctrlKey || e.metaKey || !['', '#story'].includes(location.hash)) return;
    if (e.target.closest && e.target.closest(e.key === ' ' ? 'input, textarea, select, button, a, [contenteditable]' : 'input, textarea, select, [contenteditable]')) return;
    const mid = scrollY + innerHeight / 2;
    let k = keyTarget >= 0 ? keyTarget : steps.findIndex(s => s.offsetTop + s.offsetHeight > mid);
    if (keyTarget < 0) { if (k < 0) k = steps.length - 1; const c = stepY(steps[k]); if (dir > 0 ? scrollY < c - innerHeight * 0.2 : scrollY > c + innerHeight * 0.2) k -= dir; }
    const next = k + dir;
    if (next < 0 || next >= steps.length) return;
    e.preventDefault();
    keyTarget = next;
    scrollTo({ top: Math.max(0, stepY(steps[next])), behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    clearTimeout(keyTimer); keyTimer = setTimeout(() => { keyTarget = -1; }, 900);
  });

  const canvas = document.getElementById('stage');
  if (!window.THREE || !canvas) { fallback(); return; }
  // let the words paint first, then build the scene
  requestAnimationFrame(() => setTimeout(() => { try { build(); } catch (e) { console.warn('Fortres wall fallback', e); fallback(); } }, 30));

  function build() {
    const coarse = matchMedia('(pointer: coarse), (max-width: 760px)').matches;
    const mem = navigator.deviceMemory || 8, cores = navigator.hardwareConcurrency || 8;
    let tier = (mem <= 2 || cores <= 2) ? 2 : (coarse || mem <= 4 || cores <= 4) ? 1 : 0;   // 0 full, 1 lighter, 2 lightest
    const dprFor = t => { const d = devicePixelRatio || 1; return t === 0 ? Math.min(d, 2) : t === 1 ? Math.min(d, 1.5) : Math.min(d, 1) * 0.75; };

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
    renderer.outputEncoding = THREE.sRGBEncoding;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.0;
    renderer.shadowMap.enabled = tier === 0;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.shadowMap.autoUpdate = false;

    const tok = hex => new THREE.Color(hex).convertSRGBToLinear();
    const scene = new THREE.Scene(), BG = tok('#080c12');
    scene.background = BG;
    scene.fog = new THREE.Fog(BG, 26, 92);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

    { // sky: panel colour at the horizon, background colour above
      const g = new THREE.SphereGeometry(160, 24, 12), cols = [], pos = g.attributes.position, top = tok('#080c12'), hor = tok('#0e141c');
      for (let i = 0; i < pos.count; i++) { const c = hor.clone().lerp(top, Math.min(1, Math.max(0, pos.getY(i) / 160 * 2.4 + 0.05))); cols.push(c.r, c.g, c.b); }
      g.setAttribute('color', new THREE.Float32BufferAttribute(cols, 3));
      scene.add(new THREE.Mesh(g, new THREE.MeshBasicMaterial({ vertexColors: true, side: THREE.BackSide, fog: false, toneMapped: false })));
    }
    const hemi = new THREE.HemisphereLight('#a8b6c8', '#04060a', 0.42); scene.add(hemi);
    const key = new THREE.DirectionalLight('#ffffff', 1.4);   // the one soft key, upper left
    key.position.set(-16, 24, 20); key.castShadow = renderer.shadowMap.enabled;
    key.shadow.mapSize.set(2048, 2048);
    Object.assign(key.shadow.camera, { left: -30, right: 30, top: 30, bottom: -12, near: 1, far: 80 });
    key.shadow.bias = -0.0006; key.shadow.radius = 5;
    scene.add(key);

    // dark slab behind the wall so city lights never show through the mortar; it sinks away when the wall comes apart
    const slab = new THREE.Mesh(new THREE.BoxGeometry(47.6, 10.45, 0.1), new THREE.MeshBasicMaterial({ color: tok('#080c12').multiplyScalar(0.3) }));
    slab.position.set(0, 4.95, -0.42); slab.visible = false; scene.add(slab);
    const ground = new THREE.Mesh(new THREE.PlaneGeometry(200, 200), new THREE.MeshStandardMaterial({ color: tok('#080c12').multiplyScalar(0.45), roughness: 1 }));
    ground.rotation.x = -Math.PI / 2; ground.position.y = -0.27; ground.receiveShadow = true; scene.add(ground);

    /* static scenery is merged so it costs a handful of draw calls instead of several hundred */
    function merge(items) {
      let n = 0; const gs = items.map(({ g, m }) => { const q = g.index ? g.toNonIndexed() : g; if (m) q.applyMatrix4(m); n += q.attributes.position.count; return q; });
      const P = new Float32Array(n * 3), N = new Float32Array(n * 3), U = new Float32Array(n * 2); let o = 0;
      gs.forEach(g => { P.set(g.attributes.position.array, o * 3); N.set(g.attributes.normal.array, o * 3); U.set(g.attributes.uv.array, o * 2); o += g.attributes.position.count; });
      const b = new THREE.BufferGeometry(); b.setAttribute('position', new THREE.BufferAttribute(P, 3)); b.setAttribute('normal', new THREE.BufferAttribute(N, 3)); b.setAttribute('uv', new THREE.BufferAttribute(U, 2));
      return b;
    }
    const T = (x, y, z, ry) => new THREE.Matrix4().compose(new THREE.Vector3(x, y, z), new THREE.Quaternion().setFromEuler(new THREE.Euler(0, ry || 0, 0)), new THREE.Vector3(1, 1, 1));
    let cs = 91; const cr = () => ((cs = (cs * 16807) % 2147483647) / 2147483647);

    // the city behind the wall: blocks of dark towers with cobbled streets between them, fading into the distance
    const wc = document.createElement('canvas'); wc.width = wc.height = 128; const wx = wc.getContext('2d');
    wx.fillStyle = '#000'; wx.fillRect(0, 0, 128, 128);
    for (let gy = 0; gy < 8; gy++) for (let gx = 0; gx < 8; gx++) { const v = cr(); if (v < 0.62) continue; wx.fillStyle = v > 0.95 ? '#e8edf3' : v > 0.8 ? '#4589ff' : '#1c2632'; wx.fillRect(gx * 16 + 3, gy * 16 + 4, 10, 8); }
    const winTex = new THREE.CanvasTexture(wc); winTex.wrapS = winTex.wrapT = THREE.RepeatWrapping; winTex.magFilter = THREE.NearestFilter;
    const cityItems = [], edgePts = [];
    const addEdges = (g, x, y, z) => { const e = new THREE.EdgesGeometry(g).attributes.position.array; for (let k = 0; k < e.length; k += 3) edgePts.push(e[k] + x, e[k + 1] + y, e[k + 2] + z); };
    const blank = g => { const uv = g.attributes.uv; for (let k = 0; k < uv.count; k++) uv.setXY(k, 0.01, 0.01); return g; };
    // street plan: avenues run away from the wall (along z), cross streets run along it (along x); the main road comes
    // through the gate and becomes the centre avenue
    const CITY_X = 60, CITY_Z0 = -11, CITY_Z1 = -60;
    const AVES = [[0, 3], [-16, 1.8], [16, 1.8], [-32, 1.8], [32, 1.8], [-48, 1.8], [48, 1.8]];   // [centre x, half width]
    const STREETS = [[-13, 2.2], [-27, 1.8], [-41, 1.8]];                                            // [centre z, half width]
    const building = (x, z, w, d, h) => {
      const g = new THREE.BoxGeometry(w, h, d), uv = g.attributes.uv, S = 0.5, ox = cr(), oy = cr();
      const dims = [[d, h], [d, h], [w, d], [w, d], [w, h], [w, h]];
      for (let f = 0; f < 6; f++) for (let v = 0; v < 4; v++) { const n = f * 4 + v; uv.setXY(n, uv.getX(n) * dims[f][0] * S + ox, uv.getY(n) * dims[f][1] * S + oy); }
      addEdges(g, x, h / 2 - 0.27, z);
      cityItems.push({ g, m: T(x, h / 2 - 0.27, z) });
      const kind = cr(), top = h - 0.27;
      if (kind < 0.35) { const sw = w * 0.62, sh = 0.8 + cr() * 2.2, sd = d * 0.62, sg = blank(new THREE.BoxGeometry(sw, sh, sd)); addEdges(sg, x, top + sh / 2, z); cityItems.push({ g: sg, m: T(x, top + sh / 2, z) }); }
      else if (kind < 0.55 && h > 7) cityItems.push({ g: blank(new THREE.CylinderGeometry(0.05, 0.09, 3.2, 6)), m: T(x, top + 1.6, z) });
      else if (kind < 0.68) { const cg = blank(new THREE.ConeGeometry(Math.min(w, d) * 0.72, 1.4 + cr(), 4)); cg.rotateY(Math.PI / 4); addEdges(cg, x, top + 0.7, z); cityItems.push({ g: cg, m: T(x, top + 0.7, z) }); }
    };
    const trees = [];
    // blocks are the gaps between streets; each is split into lots, and a few lots stay open as small squares with a tree
    const xs = [-CITY_X, ...AVES.flatMap(([c, h]) => [c - h, c + h]).sort((a, b) => a - b), CITY_X];
    const zs = [CITY_Z0, ...STREETS.flatMap(([c, h]) => [c + h, c - h]).sort((a, b) => b - a), CITY_Z1];
    const SIDE = 0.9;   // pavement between the street and the buildings
    for (let i = 0; i + 1 < xs.length; i += 2) for (let j = 0; j + 1 < zs.length; j += 2) {
      const x0 = xs[i] + SIDE, x1 = xs[i + 1] - SIDE, z0 = zs[j] - SIDE, z1 = zs[j + 1] + SIDE;
      if (j === 0) continue;                                   // the strip between the wall and the first street stays open
      const W = x1 - x0, D = z0 - z1; if (W < 2 || D < 2) continue;
      const nx = Math.max(1, Math.round(W / 5)), nz = Math.max(1, Math.round(D / 4.6)), lw = W / nx, ld = D / nz;
      for (let a = 0; a < nx; a++) for (let b = 0; b < nz; b++) {
        const cx = x0 + lw * (a + 0.5), cz = z0 - ld * (b + 0.5);
        if (cr() < 0.12) { trees.push([cx, cz, 1.1 + cr() * 0.4]); continue; }
        const w = lw * (0.72 + cr() * 0.2), d = ld * (0.72 + cr() * 0.2), far = Math.min(1, (-cz - 12) / 40);
        building(cx + (cr() - 0.5) * (lw - w), cz + (cr() - 0.5) * (ld - d), w, d, 3 + Math.pow(cr(), 1.6) * (9 + far * 8));
      }
    }
    const city = new THREE.Mesh(merge(cityItems), new THREE.MeshStandardMaterial({ color: tok('#0e141c'), metalness: 0.2, roughness: 0.7, emissive: '#ffffff', emissiveMap: winTex, emissiveIntensity: 0.14 }));
    scene.add(city);
    const eg = new THREE.BufferGeometry(); eg.setAttribute('position', new THREE.Float32BufferAttribute(edgePts, 3));
    const edges = new THREE.LineSegments(eg, new THREE.LineBasicMaterial({ color: tok('#1c2632'), transparent: true, opacity: 0.5 })); scene.add(edges);

    // fortress turrets at both ends of the wall
    const bc = document.createElement('canvas'); bc.width = 256; bc.height = 128; const bx = bc.getContext('2d');
    bx.fillStyle = '#1c2632'; bx.fillRect(0, 0, 256, 128);
    for (let r = 0; r < 4; r++) for (let c = -1; c < 5; c++) { const v = 0.9 + ((r * 7 + c * 13) % 5) * 0.035; bx.fillStyle = `rgb(${34 * v | 0},${43 * v | 0},${55 * v | 0})`; bx.fillRect(c * 64 + (r % 2) * 32 + 2, r * 32 + 2, 60, 28); }
    const brickTex = new THREE.CanvasTexture(bc); brickTex.wrapS = brickTex.wrapT = THREE.RepeatWrapping; brickTex.repeat.set(3, 6); brickTex.encoding = THREE.sRGBEncoding;
    const stoneMat = new THREE.MeshStandardMaterial({ map: brickTex, roughness: 0.9, metalness: 0 });
    const capTex = brickTex.clone(); capTex.needsUpdate = true; capTex.repeat.set(0.4, 0.25);
    const capMat = new THREE.MeshStandardMaterial({ map: capTex, roughness: 0.9, metalness: 0 });
    const wallHalf = 45 / 2 * 1.06 + 0.4;
    [-1, 1].forEach(sd => {
      const tw = new THREE.Group(), H = 13;
      const body = new THREE.Mesh(new THREE.CylinderGeometry(1.9, 2.15, H, 20), stoneMat); body.position.y = H / 2 - 0.27; body.castShadow = body.receiveShadow = true; tw.add(body);
      const ring = new THREE.Mesh(new THREE.CylinderGeometry(2.25, 2.25, 0.5, 20), capMat); ring.position.y = H - 0.1; tw.add(ring);
      const mers = []; for (let k = 0; k < 10; k++) { const a = k / 10 * Math.PI * 2; mers.push({ g: new THREE.BoxGeometry(0.75, 0.9, 0.55), m: T(Math.cos(a) * 2.0, H + 0.55, Math.sin(a) * 2.0, -a) }); }
      const mer = new THREE.Mesh(merge(mers), capMat); mer.castShadow = true; tw.add(mer);
      const slit = new THREE.Mesh(new THREE.BoxGeometry(0.16, 1.1, 0.1), new THREE.MeshBasicMaterial({ color: tok('#4589ff') })); slit.position.set(0, H * 0.62, 2.0); tw.add(slit);
      tw.position.set(sd * (wallHalf + 1.7), 0, 0); scene.add(tw);
    });

    // stars and a dim moon
    const sp = []; for (let k = 0; k < 900; k++) { const th = cr() * Math.PI * 2, y = 0.1 + cr() * 0.9, rr = Math.sqrt(1 - y * y); sp.push(Math.cos(th) * rr * 150, y * 150, Math.sin(th) * rr * 150); }
    const sg = new THREE.BufferGeometry(); sg.setAttribute('position', new THREE.Float32BufferAttribute(sp, 3));
    const stars = new THREE.Points(sg, new THREE.PointsMaterial({ size: 1.3, sizeAttenuation: false, color: tok('#8d9aaa'), transparent: true, opacity: 0.6, fog: false })); scene.add(stars);
    const mc = document.createElement('canvas'); mc.width = mc.height = 128; const mx = mc.getContext('2d');
    mx.fillStyle = '#4b5666'; mx.fillRect(0, 0, 128, 128);
    for (let k = 0; k < 22; k++) { mx.fillStyle = `rgba(28,38,50,${0.1 + cr() * 0.25})`; mx.beginPath(); mx.arc(cr() * 128, cr() * 128, 3 + cr() * 14, 0, 7); mx.fill(); }
    const moonTex = new THREE.CanvasTexture(mc); moonTex.encoding = THREE.sRGBEncoding;
    const moon = new THREE.Mesh(new THREE.SphereGeometry(4.2, 24, 12), new THREE.MeshBasicMaterial({ map: moonTex, fog: false })); moon.position.set(22, 30, -125); scene.add(moon);

    // cobbled streets: the road through the gate and every street of the city share one material. The stones are drawn
    // once as a height map; the colour keeps the old road tones and a normal map built from the heights makes each
    // stone round, so the key light picks out their tops and the joints fall dark
    const RS = 512, hc = document.createElement('canvas'); hc.width = hc.height = RS; const hx = hc.getContext('2d');
    const cc = document.createElement('canvas'); cc.width = cc.height = RS; const cx = cc.getContext('2d');
    hx.fillStyle = '#000'; hx.fillRect(0, 0, RS, RS); cx.fillStyle = '#080c12'; cx.fillRect(0, 0, RS, RS);
    const ROWSN = 10, rh = RS / ROWSN;
    for (let r = 0; r < ROWSN; r++) {
      let x = -cr() * 40;
      while (x < RS) {
        const w = 38 + cr() * 26, h = rh * (0.78 + cr() * 0.12), cxp = x + w / 2, cyp = r * rh + rh / 2 + (cr() - 0.5) * 4, v = 0.75 + cr() * 0.4;
        for (const ox of [-RS, 0, RS]) {                      // draw wrapped copies so the tile repeats without a seam
          const px = cxp + ox, rx = w / 2 - 3, ry = h / 2;
          const gr = hx.createRadialGradient(px, cyp, 1, px, cyp, Math.max(rx, ry));
          gr.addColorStop(0, '#fff'); gr.addColorStop(0.55, '#d8d8d8'); gr.addColorStop(1, '#202020');
          hx.fillStyle = gr; hx.beginPath(); hx.ellipse(px, cyp, rx, ry, (cr() - 0.5) * 0.12, 0, 7); hx.fill();
          cx.fillStyle = `rgb(${15 * v | 0},${20 * v | 0},${27 * v | 0})`; cx.beginPath(); cx.ellipse(px, cyp, rx, ry, 0, 0, 7); cx.fill();
        }
        x += w;
      }
    }
    const hd = hx.getImageData(0, 0, RS, RS).data, rnc = document.createElement('canvas'); rnc.width = rnc.height = RS;
    const nctx = rnc.getContext('2d'), nd = nctx.createImageData(RS, RS), H = (x, y) => hd[(((y + RS) % RS) * RS + ((x + RS) % RS)) * 4] / 255;
    for (let y = 0; y < RS; y++) for (let x = 0; x < RS; x++) {
      const dx = (H(x - 1, y) - H(x + 1, y)) * 2.2, dy = (H(x, y + 1) - H(x, y - 1)) * 2.2, l = Math.hypot(dx, dy, 1), o = (y * RS + x) * 4;
      nd.data[o] = (dx / l * 0.5 + 0.5) * 255; nd.data[o + 1] = (dy / l * 0.5 + 0.5) * 255; nd.data[o + 2] = (1 / l * 0.5 + 0.5) * 255; nd.data[o + 3] = 255;
    }
    nctx.putImageData(nd, 0, 0);
    const roadTex = new THREE.CanvasTexture(cc), roadN = new THREE.CanvasTexture(rnc);
    [roadTex, roadN].forEach(t => { t.wrapS = t.wrapT = THREE.RepeatWrapping; t.anisotropy = 8; });
    roadTex.encoding = THREE.sRGBEncoding;
    const TILE = 4;                                            // one texture tile covers 4 x 4 world units, the same everywhere
    const strip = (x0, x1, z0, z1, y) => {                    // a flat street piece with UVs from world position, so pieces meet seamlessly
      const g = new THREE.PlaneGeometry(x1 - x0, z0 - z1); g.rotateX(-Math.PI / 2); g.translate((x0 + x1) / 2, y, (z0 + z1) / 2);
      const p = g.attributes.position, uv = g.attributes.uv; for (let k = 0; k < p.count; k++) uv.setXY(k, p.getX(k) / TILE, -p.getZ(k) / TILE);
      return { g };
    };
    const pieces = [strip(-6, 6, 60, CITY_Z0 + 0.01, -0.245)];                                  // through the gate
    AVES.forEach(([c, h]) => pieces.push(strip(c - h, c + h, CITY_Z0, CITY_Z1, -0.246)));       // avenues
    STREETS.forEach(([c, h]) => pieces.push(strip(-CITY_X, CITY_X, c + h, c - h, -0.244)));     // cross streets
    pieces.push(strip(-6, 6, CITY_Z0 + 0.01, STREETS[0][0], -0.2455));                          // join the road to the first street
    const roadMat = new THREE.MeshStandardMaterial({ map: roadTex, normalMap: roadN, normalScale: new THREE.Vector2(1.6, 1.6), roughness: 0.82 });
    const road = new THREE.Mesh(merge(pieces), roadMat); road.receiveShadow = true; scene.add(road);

    // kerbs: along the road through the gate, and around every city block so each street has the same stone edge
    const kerbs = [], KW = 0.28;
    [-1, 1].forEach(sd => { kerbs.push({ g: new THREE.BoxGeometry(KW, 0.16, 60 - CITY_Z0), m: T(sd * 6.14, -0.19, (60 + CITY_Z0) / 2) }); });
    const kx = (x0, x1, z) => kerbs.push({ g: new THREE.BoxGeometry(x1 - x0, 0.16, KW), m: T((x0 + x1) / 2, -0.19, z) });
    const kz = (z0, z1, x) => kerbs.push({ g: new THREE.BoxGeometry(KW, 0.16, z0 - z1), m: T(x, -0.19, (z0 + z1) / 2) });
    [[-CITY_X, -6], [6, CITY_X]].forEach(([a, b]) => kx(a, b, zs[1] + KW / 2));          // wall side of the first street, open at the gate
    for (let i = 0; i + 1 < xs.length; i += 2) for (let j = 2; j + 1 < zs.length; j += 2) {
      const x0 = xs[i] - KW / 2, x1 = xs[i + 1] + KW / 2, z0 = zs[j] + KW / 2, z1 = zs[j + 1] - KW / 2;
      kx(x0, x1, z0); if (j + 2 < zs.length) kx(x0, x1, z1);
      if (i > 0) kz(z0, z1, x0); if (i + 2 < xs.length) kz(z0, z1, x1);
    }
    const kerb = new THREE.Mesh(merge(kerbs), capMat); kerb.receiveShadow = true; scene.add(kerb);

    // old iron street lamps behind the wall, along the road and at the city corners, and trees along the first street
    const lampAt = [];
    [-4.5].forEach(z => [-1, 1].forEach(sd => lampAt.push([sd * 7.2, z])));
    AVES.forEach(([c, h]) => STREETS.forEach(([z, zh]) => { if (c !== 0 || z !== STREETS[0][0]) lampAt.push([c + h + 0.6, z + zh + 0.6]); }));
    for (let x = -54; x <= 54; x += 6) if (Math.abs(x) > 8) trees.push([x, CITY_Z0 + 0.2 + (Math.abs(x) % 12 ? 0 : 0), 0.9 + cr() * 0.35]);
    const pc = document.createElement('canvas'); pc.width = pc.height = 64; const px = pc.getContext('2d');
    const pg = px.createRadialGradient(32, 32, 0, 32, 32, 32); pg.addColorStop(0, 'rgba(166,200,255,0.55)'); pg.addColorStop(1, 'rgba(166,200,255,0)');
    px.fillStyle = pg; px.fillRect(0, 0, 64, 64);
    const ironMat = new THREE.MeshStandardMaterial({ color: tok('#0e141c'), roughness: 0.5, metalness: 0.6 });
    const glassMat = new THREE.MeshBasicMaterial({ color: tok('#a6c8ff') });
    const poolMat = new THREE.MeshBasicMaterial({ map: new THREE.CanvasTexture(pc), transparent: true, opacity: 0.32, blending: THREE.AdditiveBlending, depthWrite: false });
    const lampGroup = list => {
      const iron = [], glass = [], glow = [], grp = new THREE.Group();
      list.forEach(([x, z]) => {
        iron.push({ g: new THREE.BoxGeometry(0.42, 0.34, 0.42), m: T(x, -0.1, z) });                                   // plinth
        iron.push({ g: new THREE.CylinderGeometry(0.06, 0.09, 3.3, 8), m: T(x, 1.7, z) });                             // post
        iron.push({ g: new THREE.CylinderGeometry(0.15, 0.1, 0.12, 8), m: T(x, 3.38, z) });                            // collar
        const cap = new THREE.ConeGeometry(0.34, 0.34, 4); cap.rotateY(Math.PI / 4); iron.push({ g: cap, m: T(x, 4.12, z) });
        iron.push({ g: new THREE.CylinderGeometry(0.03, 0.03, 0.22, 6), m: T(x, 4.38, z) });                           // finial
        const lan = new THREE.CylinderGeometry(0.24, 0.16, 0.56, 4); lan.rotateY(Math.PI / 4); glass.push({ g: lan, m: T(x, 3.71, z) });
        const pool = new THREE.PlaneGeometry(4.2, 4.2); pool.rotateX(-Math.PI / 2); glow.push({ g: pool, m: T(x, -0.23, z) });
      });
      const im = new THREE.Mesh(merge(iron), ironMat); im.castShadow = true;
      grp.add(im, new THREE.Mesh(merge(glass), glassMat));
      const pm = new THREE.Mesh(merge(glow), poolMat); pm.renderOrder = 1; grp.add(pm);
      scene.add(grp); return grp;
    };
    lampGroup(lampAt);
    const leaf = [], wood = [];
    trees.forEach(([x, z, s]) => {
      wood.push({ g: new THREE.CylinderGeometry(0.08 * s, 0.12 * s, 1.4 * s, 6), m: T(x, 0.7 * s - 0.27, z) });
      const a = new THREE.IcosahedronGeometry(0.85 * s, 0), b = new THREE.IcosahedronGeometry(0.6 * s, 0);
      leaf.push({ g: a, m: T(x, 1.9 * s - 0.27, z, cr() * 3) }, { g: b, m: T(x + 0.25 * s, 2.6 * s - 0.27, z - 0.1, cr() * 3) });
    });
    const woodMesh = new THREE.Mesh(merge(wood), new THREE.MeshStandardMaterial({ color: tok('#0e141c'), roughness: 0.9 }));
    const leafMesh = new THREE.Mesh(merge(leaf), new THREE.MeshStandardMaterial({ color: tok('#1c2632'), roughness: 0.85, flatShading: true }));
    woodMesh.castShadow = leafMesh.castShadow = true; scene.add(woodMesh, leafMesh);

    const scan = new THREE.Mesh(new THREE.BoxGeometry(0.06, 14, 0.06), new THREE.MeshBasicMaterial({ color: tok('#4589ff') }));
    scan.position.set(-30, 4.6, 0.6); scan.visible = false; scene.add(scan);

    /* bricks */
    const COLS = 45, ROWS = 19, N = COLS * ROWS, BW = 1.0, BH = 0.5, BD = 0.62, GX = 0.06, GY = 0.05;
    function bevelBox(w, h, d, b) { // a box with a fine chamfer; the chamfer catches the key light and the lower edges go dark
      const hx = w / 2, hy = h / 2, hz = d / 2, ix = hx - b, iy = hy - b, iz = hz - b, P = [], Nn = [], UV = [], AO = [];
      const tri = (a, bb, c, n, ao) => {
        const e1 = [bb[0] - a[0], bb[1] - a[1], bb[2] - a[2]], e2 = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
        const cx2 = e1[1] * e2[2] - e1[2] * e2[1], cy2 = e1[2] * e2[0] - e1[0] * e2[2], cz2 = e1[0] * e2[1] - e1[1] * e2[0];
        const v = cx2 * n[0] + cy2 * n[1] + cz2 * n[2] < 0 ? [a, c, bb] : [a, bb, c];
        v.forEach(p => { P.push(...p); Nn.push(...n); UV.push(p[0] + p[2], p[1] + p[2]); AO.push(ao); });
      };
      const quad = (a, bb, c, e, n, ao) => { tri(a, bb, c, n, ao); tri(a, c, e, n, ao); };
      const s2 = Math.SQRT1_2, s3 = 1 / Math.sqrt(3);
      for (const s of [-1, 1]) {
        quad([-ix, -iy, s * hz], [ix, -iy, s * hz], [ix, iy, s * hz], [-ix, iy, s * hz], [0, 0, s], 1);
        quad([s * hx, -iy, -iz], [s * hx, iy, -iz], [s * hx, iy, iz], [s * hx, -iy, iz], [s, 0, 0], 0.72);
        quad([-ix, s * hy, -iz], [ix, s * hy, -iz], [ix, s * hy, iz], [-ix, s * hy, iz], [0, s, 0], s > 0 ? 1.05 : 0.4);
      }
      for (const sy of [-1, 1]) for (const sz of [-1, 1]) quad([-ix, sy * iy, sz * hz], [ix, sy * iy, sz * hz], [ix, sy * hy, sz * iz], [-ix, sy * hy, sz * iz], [0, sy * s2, sz * s2], sy > 0 ? 1.5 : 0.35);
      for (const sx of [-1, 1]) for (const sz of [-1, 1]) quad([sx * ix, -iy, sz * hz], [sx * ix, iy, sz * hz], [sx * hx, iy, sz * iz], [sx * hx, -iy, sz * iz], [sx * s2, 0, sz * s2], sx < 0 ? 1.25 : 0.5);
      for (const sx of [-1, 1]) for (const sy of [-1, 1]) quad([sx * ix, sy * hy, -iz], [sx * ix, sy * hy, iz], [sx * hx, sy * iy, iz], [sx * hx, sy * iy, -iz], [sx * s2, sy * s2, 0], sy > 0 ? 1.2 : 0.35);
      for (const sx of [-1, 1]) for (const sy of [-1, 1]) for (const sz of [-1, 1]) tri([sx * ix, sy * iy, sz * hz], [sx * ix, sy * hy, sz * iz], [sx * hx, sy * iy, sz * iz], [sx * s3, sy * s3, sz * s3], sy > 0 ? 1.1 : 0.4);
      const g = new THREE.BufferGeometry();
      g.setAttribute('position', new THREE.Float32BufferAttribute(P, 3)); g.setAttribute('normal', new THREE.Float32BufferAttribute(Nn, 3));
      g.setAttribute('uv', new THREE.Float32BufferAttribute(UV, 2)); g.setAttribute('aAO', new THREE.Float32BufferAttribute(AO, 1));
      return g;
    }
    const geo = new THREE.InstancedBufferGeometry().copy(bevelBox(BW, BH, BD, 0.03));
    geo.instanceCount = N;
    // fine speckle so the stone isn't plastic
    const nc = document.createElement('canvas'); nc.width = nc.height = 128; const nx = nc.getContext('2d'), id = nx.createImageData(128, 128);
    for (let k = 0; k < id.data.length; k += 4) { const v = 205 + cr() * 50 | 0; id.data[k] = id.data[k + 1] = id.data[k + 2] = v; id.data[k + 3] = 255; }
    nx.putImageData(id, 0, 0);
    const speck = new THREE.CanvasTexture(nc); speck.wrapS = speck.wrapT = THREE.RepeatWrapping; speck.repeat.set(1.3, 1.3);

    const U = { uT: { value: 99 }, uDur: { value: 0.52 }, uSpin: { value: 0 }, uScanX: { value: -99 }, uScanOn: { value: 0 }, uRim: { value: tok('#4589ff') } };
    const HEAD = `
      attribute vec4 aP0, aP1, aR0, aR1, aH; attribute vec3 aC0, aC1; attribute vec2 aX;
      attribute float aAO;
      uniform float uT, uDur, uSpin, uScanX, uScanOn; uniform vec3 uRim;
      varying vec2 vHi;
      float fE() { if (uDur <= 0.0) return 1.0; float k = clamp((uT - aX.x) / uDur, 0.0, 1.0); return k < 0.5 ? 4.0 * k * k * k : 1.0 - pow(-2.0 * k + 2.0, 3.0) / 2.0; }
      mat3 fM(vec3 r) { vec3 c = cos(r), s = sin(r);
        return mat3(c.y*c.z, c.x*s.z + s.x*s.y*c.z, s.x*s.z - c.x*s.y*c.z,  -c.y*s.z, c.x*c.z - s.x*s.y*s.z, s.x*c.z + c.x*s.y*s.z,  s.y, -s.x*c.y, c.x*c.y); }
      vec3 fRot(float e) { return mix(aR0.xyz, aR1.xyz, e) + vec3(uSpin, uSpin, 0.0) * mix(aR0.w, aR1.w, e); }
    `;
    function patch(shader, isDepth) {
      Object.assign(shader.uniforms, U);
      shader.vertexShader = shader.vertexShader.replace('#include <common>', '#include <common>\n' + HEAD);
      if (!isDepth) shader.vertexShader = shader.vertexShader
        .replace('#include <beginnormal_vertex>', 'vec3 objectNormal = fM(fRot(e_)) * normal;')
        .replace('#include <color_vertex>', `
          vec3 wp_ = mix(aP0.xyz, aP1.xyz, e_);
          vColor = mix(aC0, aC1, e_) * aAO * (0.86 + aX.y * 0.28);
          vColor = mix(vColor, uRim, uScanOn * smoothstep(2.2, 0.0, abs(wp_.x - uScanX)) * 0.8);
          vHi = mix(aH.xy, aH.zw, e_);`)
        .replace('#include <uv_vertex>', 'float e_ = fE(); vUv = uv * 0.34 + aX.y * vec2(3.1, 7.7);');
      shader.vertexShader = shader.vertexShader.replace('#include <begin_vertex>', `
        ${isDepth ? 'float e_ = fE();' : ''}
        float s_ = max(mix(aP0.w, aP1.w, e_), 0.0001);
        float bump_ = sin(3.14159 * e_) * 0.16 * s_;
        vec3 transformed = fM(fRot(e_)) * (position * s_) + mix(aP0.xyz, aP1.xyz, e_) + vec3(0.0, 0.0, bump_);`);
      if (!isDepth) {
        shader.fragmentShader = shader.fragmentShader
          .replace('#include <common>', '#include <common>\nvarying vec2 vHi; uniform vec3 uRim;')
          .replace('#include <emissivemap_fragment>', `#include <emissivemap_fragment>
            float rim_ = pow(1.0 - saturate(dot(normalize(vViewPosition), normal)), 4.0);
            totalEmissiveRadiance += uRim * rim_ * vHi.x * 0.55 + vColor.rgb * vHi.y * 0.22;`);
      }
    }
    const mat = new THREE.MeshStandardMaterial({ map: speck, roughness: 0.88, metalness: 0, vertexColors: true });
    mat.onBeforeCompile = s => patch(s, false);
    const depth = new THREE.MeshDepthMaterial({ depthPacking: THREE.RGBADepthPacking });
    depth.onBeforeCompile = s => patch(s, true);

    const attr = (name, size) => { const a = new THREE.InstancedBufferAttribute(new Float32Array(N * size), size); geo.setAttribute(name, a); return a; };
    const A = { p0: attr('aP0', 4), p1: attr('aP1', 4), r0: attr('aR0', 4), r1: attr('aR1', 4), c0: attr('aC0', 3), c1: attr('aC1', 3), x: attr('aX', 2), h: attr('aH', 4) };
    const mesh = new THREE.Mesh(geo, mat);
    mesh.customDepthMaterial = depth;
    mesh.castShadow = mesh.receiveShadow = true;
    mesh.frustumCulled = false;
    scene.add(mesh);

    const lit = hex => tok(hex).multiplyScalar(0.5);   // the key light adds the rest: on-screen colour lands near the page tokens
    const C = { stone: tok('#2c3644'), dim: tok('#0e141c'), coral: lit('#ff7b6b'), mint: lit('#42be65'), blue: lit('#4589ff'), warn: lit('#8d9aaa'), coralDim: tok('#ff7b6b').multiplyScalar(0.12), amber: lit('#f1c21b') };
    let seed = 7; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    const jit = []; for (let i = 0; i < N; i++) jit.push(0.82 + rnd() * 0.3);
    const seeds = []; for (let i = 0; i < N; i++) seeds.push(rnd());
    const HOT = 9 * COLS + 22;
    const PICKB = [HOT, 4 * COLS + 9, 13 * COLS + 31, 6 * COLS + 38, 15 * COLS + 14, 2 * COLS + 27];
    const wallPos = i => { const c = i % COLS, r = Math.floor(i / COLS); return [(c - (COLS - 1) / 2) * (BW + GX) + (r % 2 ? 0.26 : -0.26), r * (BH + GY), 0]; };
    const cloudPos = []; for (let i = 0; i < N; i++) { const u = rnd() * 2 - 1, th = rnd() * Math.PI * 2, rad = 7 + Math.cbrt(rnd()) * 15; cloudPos.push([Math.sqrt(1 - u * u) * Math.cos(th) * rad * 1.4, 6 + u * rad * 0.55, Math.sqrt(1 - u * u) * Math.sin(th) * rad * 0.8]); }
    const rotJit = []; for (let i = 0; i < N; i++) rotJit.push([rnd() * 6, rnd() * 6, rnd() * 6]);
    const RANKPOS = {}; { let i = 0; for (let c = 0; c < 40 && i < N; c++) { const h = Math.max(1, Math.round(20 * Math.exp(-c / 7))); for (let l = 0; l < h && i < N; l++, i++) RANKPOS[i] = { p: [(13 - c) * (BW + 0.2), l * (BH + GY), 2], c: c < 2 ? C.blue : C.stone.clone().multiplyScalar(1 - c / 55), l, g: c }; } }
    const rowD = i => 0.28 * Math.floor(i / COLS) / (ROWS - 1) + 0.04 * ((i % COLS) % 3) / 2;   // the ripple: row by row, up the wall
    function S(fn, cam, look, opts) {
      const st = { pos: new Float32Array(N * 3), scl: new Float32Array(N), col: new Float32Array(N * 3), rot: new Float32Array(N * 4), hi: new Float32Array(N * 2), del: new Float32Array(N), grow: new Uint8Array(N), cam, look, name: '' };
      for (let i = 0; i < N; i++) {
        const o = fn(i), h = o.h || [0, 0];
        st.pos.set(o.p, i * 3); st.scl[i] = o.s == null ? 1 : o.s; st.col[i * 3] = o.c.r; st.col[i * 3 + 1] = o.c.g; st.col[i * 3 + 2] = o.c.b;
        const r = o.r || [0, 0, 0]; st.rot.set([r[0], r[1], r[2], o.spin ? 1 : 0], i * 4);
        st.hi[i * 2] = h[0]; st.hi[i * 2 + 1] = h[1];
        st.del[i] = o.d == null ? rowD(i) : o.d;
        st.grow[i] = o.grow ? 1 : 0;
      }
      return st;
    }
    const stone = i => C.stone.clone().multiplyScalar(jit[i]);
    const tower = (k, cx) => [cx + ((k % 3) - 1) * (BW + GX), Math.floor(k / 3) * (BH + GY), 0];
    const blk = (k, cols, cx) => [cx + ((k % cols) - (cols - 1) / 2) * (BW + GX), Math.floor(k / cols) * (BH + GY), 0];
    const bar = (group, layer, gap, step) => group * gap + layer * step;
    const blind = rule => S(i => {
      if (i < 31) return { p: blk(i, 5, -4.6), c: i < (rule ? 19 : 22) ? C.mint : C.warn, h: i < (rule ? 19 : 22) ? [0.4, 0.1] : undefined };
      if (i < 75) { const k = i - 31, hit = !rule && k < 5; return { p: blk(k, 8, 3.8), c: hit ? C.mint : C.coralDim, h: hit ? [1, 0.45] : undefined }; }
      return { p: wallPos(i), s: 0, c: C.dim };
    }, [0.6, 3.6, 20], [0.4, 1.6, 0]);
    const pulled = (i, z, c, s, h) => ({ p: [wallPos(i)[0], wallPos(i)[1], z], c, s: s || 1, h });
    const STATES = {
      wall: S(i => ({ p: wallPos(i), c: stone(i) }), [0, 5.2, 31], [0, 4.6, 0]),
      one: S(i => i === HOT ? pulled(i, 1.1, C.coral, 1, [1, 0.5]) : { p: wallPos(i), c: stone(i).multiplyScalar(0.55) }, [5, 6.5, 11], [0.3, 4.9, 0]),
      cost: S(i => i === HOT ? { ...pulled(i, 2.2, C.coral, 1, [1, 0.55]), r: [0.25, 0.6, 0.1] } : { p: wallPos(i), c: stone(i).multiplyScalar(0.4) }, [-3.5, 5.8, 8], [0.3, 4.9, 1]),
      cloud: S(i => ({ p: cloudPos[i], c: stone(i), r: rotJit[i], s: 0.85, spin: 1 }), [0, 6, 44], [0, 6, 0]),
      picks: S(i => PICKB.indexOf(i) >= 0 ? pulled(i, 3.2, C.blue, 1.15, [1, 0.6]) : { p: wallPos(i), c: stone(i).multiplyScalar(0.3) }, [-7, 7.5, 27], [0, 4.6, 1]),
      severity: S(i => i < 9 ? { p: [0.12 * Math.sin(i * 1.7), 0.08 + i * (BH * 1.4 + 0.06), 2], c: i === 0 ? C.amber : C.stone.clone().multiplyScalar(1.15), s: 1.4, r: [0, 0.06 * Math.sin(i * 2.3), 0], h: i === 0 ? [0.8, 0.3] : undefined, d: i * 0.04 } : { p: wallPos(i), c: stone(i).multiplyScalar(0.22) }, [3.2, 4.6, 16], [0.4, 3, 2]),
      towers: S(i => i < 5 ? { p: tower(i, 1.2), c: C.amber, grow: 1, d: bar(0, Math.floor(i / 3), 0.14, 0.012) } : i < 16 ? { p: tower(i - 5, 5.2), c: C.blue, grow: 1, d: bar(1, Math.floor((i - 5) / 3), 0.14, 0.012) } : i < 43 ? { p: tower(i - 16, 9.2), c: C.mint, grow: 1, h: [0.5, 0.2], d: bar(2, Math.floor((i - 16) / 3), 0.14, 0.012) } : { p: wallPos(i), s: 0, c: C.dim }, [5.4, 3.8, 19.5], [5.4, 2.2, 0]),
      work: S(i => { const g = (k, cols, cx, c, gi, h) => ({ p: blk(k, cols, cx), c, grow: 1, h, d: bar(gi, Math.floor(k / cols), 0.12, 0.008) });
        return i < 4 ? g(i, 2, 1.6, C.mint, 0, [0.6, 0.3]) : i < 15 ? g(i - 4, 4, 5.0, C.warn, 1) : i < 84 ? g(i - 15, 9, 11.8, C.amber, 2) : i < 184 ? g(i - 84, 10, 22.4, C.blue, 3) : { p: wallPos(i), s: 0, c: C.dim }; }, [11.6, 6.2, 40], [12.6, 2.8, 0]),
      blindRule: blind(true),
      blindOurs: blind(false),
      read: S(i => ({ p: wallPos(i), c: stone(i).multiplyScalar(0.55) }), [6, 5.5, 24], [0, 4.6, 0]),
      rank: S(i => { const r = RANKPOS[i]; return r ? { p: r.p, c: r.c, h: r.g < 2 ? [0.6, 0.25] : undefined, d: r.g * 0.012 + r.l * 0.008 } : { p: wallPos(i), s: 0, c: C.dim }; }, [0, 8.5, 34], [6, 3.8, 2]),
      check: S(i => { const k = PICKB.indexOf(i); return k >= 0 ? { p: [0.4 + (k - 2.5) * 1.7, 2.4, 7], c: k < 4 ? C.mint : C.warn, s: 1.3, h: k < 4 ? [1, 0.45] : undefined, d: k * 0.07 } : { p: wallPos(i), c: stone(i).multiplyScalar(0.25) }; }, [1.2, 4.4, 24], [1.2, 2.6, 3]),
      trust: S(i => i < 27 ? { p: tower(i, 0), c: C.mint, grow: 1, h: [0.5, 0.2], d: Math.floor(i / 3) * 0.02 } : i < 33 ? { p: [2.9 + ((i - 27) % 3) * 1.12, 0, 1.4 + Math.floor((i - 27) / 3) * 0.8], c: C.coralDim, r: [0, 0.08 * ((i % 3) - 1), 0], d: 0.3 + (i - 27) * 0.05 } : { p: wallPos(i), s: 0, c: C.dim }, [1.2, 3.6, 17], [1.6, 2.4, 0.6]),
      close: S(i => PICKB.includes(i) ? { p: wallPos(i), c: C.mint, h: [1, 0.6] } : { p: wallPos(i), c: stone(i) }, [0, 7, 36], [0, 4.6, 0]),
    };
    Object.keys(STATES).forEach(k => { STATES[k].name = k; });
    const seq = steps.map(s => STATES[s.dataset.s] || STATES.wall);

    /* transition: copy where each brick is right now into the "start" slots, write the new state into the "end" slots */
    const ease = k => k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
    let transStart = 0, transEnd = 0, current = null, tNow = 0;
    function retarget(st, first) {
      const P0 = A.p0.array, P1 = A.p1.array, R0 = A.r0.array, R1 = A.r1.array, C0 = A.c0.array, C1 = A.c1.array, X = A.x.array, H = A.h.array;
      const elapsed = REDUCE ? 99 : tNow - transStart, dur = U.uDur.value;
      let last = 0;
      for (let i = 0; i < N; i++) {
        const j4 = i * 4, j3 = i * 3, j2 = i * 2;
        const k = Math.min(1, Math.max(0, (elapsed - X[j2]) / (dur || 1))), e = first ? 1 : ease(k);
        for (let c = 0; c < 4; c++) { P0[j4 + c] = P0[j4 + c] + (P1[j4 + c] - P0[j4 + c]) * e; R0[j4 + c] = R0[j4 + c] + (R1[j4 + c] - R0[j4 + c]) * e; }
        for (let c = 0; c < 3; c++) C0[j3 + c] = C0[j3 + c] + (C1[j3 + c] - C0[j3 + c]) * e;
        H[j4] += (H[j4 + 2] - H[j4]) * e; H[j4 + 1] += (H[j4 + 3] - H[j4 + 1]) * e;
        if (st.grow[i] && !(current && current.grow[i])) { P0[j4] = st.pos[j3]; P0[j4 + 1] = 0; P0[j4 + 2] = st.pos[j3 + 2]; P0[j4 + 3] = 0; R0[j4] = R0[j4 + 1] = R0[j4 + 2] = 0; C0[j3] = st.col[j3]; C0[j3 + 1] = st.col[j3 + 1]; C0[j3 + 2] = st.col[j3 + 2]; }
        P1[j4] = st.pos[j3]; P1[j4 + 1] = st.pos[j3 + 1]; P1[j4 + 2] = st.pos[j3 + 2]; P1[j4 + 3] = st.scl[i];
        R1[j4] = st.rot[j4]; R1[j4 + 1] = st.rot[j4 + 1]; R1[j4 + 2] = st.rot[j4 + 2]; R1[j4 + 3] = st.rot[j4 + 3];
        C1[j3] = st.col[j3]; C1[j3 + 1] = st.col[j3 + 1]; C1[j3 + 2] = st.col[j3 + 2];
        X[j2] = st.del[i]; X[j2 + 1] = seeds[i]; H[j4 + 2] = st.hi[j2]; H[j4 + 3] = st.hi[j2 + 1];
        if (st.del[i] > last) last = st.del[i];
      }
      Object.values(A).forEach(a => { a.needsUpdate = true; });
      U.uDur.value = REDUCE ? 0 : 0.52;
      transStart = tNow; transEnd = tNow + last + 0.56; current = st;
      renderer.shadowMap.needsUpdate = true;
    }
    // first state: bricks gather from the air
    { const c = STATES.cloud;
      for (let i = 0; i < N; i++) { A.p1.array.set([c.pos[i * 3], c.pos[i * 3 + 1], c.pos[i * 3 + 2], 0], i * 4); A.r1.array.set([c.rot[i * 4], c.rot[i * 4 + 1], c.rot[i * 4 + 2], 0], i * 4); A.c1.array.set([STATES.wall.col[i * 3], STATES.wall.col[i * 3 + 1], STATES.wall.col[i * 3 + 2]], i * 3); } }
    retarget(seq[0], true);

    /* layout is read here, on resize only, and cached for the frame loop */
    let centers = [], vw = innerWidth, vh = innerHeight, scrollNow = scrollY, sD = scrollY;
    function measure() {
      centers = steps.map(s => { const r = s.getBoundingClientRect(); return r.top + scrollY + r.height / 2 - innerHeight / 2; });
    }
    function resize() {
      vw = innerWidth; vh = innerHeight; const w = vw, h = vh;
      renderer.setPixelRatio(dprFor(tier)); renderer.setSize(w, h, false); camera.aspect = w / h;
      if (w / h > 1.1) camera.setViewOffset(w, h, -w * 0.2, 0, w, h); else camera.setViewOffset(w, h, 0, h * 0.24, w, h);
      camera.updateProjectionMatrix();
    }
    addEventListener('resize', () => { if (coarse && innerWidth === vw && Math.abs(innerHeight - vh) < 130) { measure(); return; } resize(); measure(); }, { passive: true });
    addEventListener('scroll', () => { scrollNow = scrollY; }, { passive: true });
    new ResizeObserver(measure).observe(document.querySelector('.story'));
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(measure);
    resize(); measure();

    const clamp01 = x => Math.max(0, Math.min(1, x));
    const smooth = x => x * x * x * (x * (6 * x - 15) + 10);
    const ptr = { x: 0, y: 0, sx: 0, sy: 0 };
    if (!REDUCE) addEventListener('pointermove', e => { ptr.x = e.clientX / vw - 0.5; ptr.y = e.clientY / vh - 0.5; }, { passive: true });

    let slabK = 1;
    let active = 0, tStart = performance.now(), winStart = 0, winN = 0, winSum = 0, lastDown = 0, sawFirst = false;
        function setTier(t) {
      tier = Math.min(2, t);
      if (tier > 0 && renderer.shadowMap.enabled) { renderer.shadowMap.enabled = false; key.castShadow = false; [mat, stoneMat, capMat, ground.material, road.material, city.material, ironMat, woodMesh.material, leafMesh.material].forEach(m => { m.needsUpdate = true; }); }
      if (tier === 2) { stars.visible = false; edges.visible = false; }
      resize();
    }
    if (tier === 2) setTier(2);
    window.__fortres = { get tier() { return tier; }, setTier, states: Object.keys(STATES) };

    function frame(now, dt) {
      if (lost) return;
      tNow = (now - tStart) / 1000;
      // the page's scroll position, smoothed: no snaps, no overshoot
      sD = REDUCE ? scrollNow : sD + (scrollNow - sD) * (1 - Math.exp(-dt * 9));
      let i = 0; while (i < centers.length - 2 && sD >= centers[i + 1]) i++;
      const span = centers[i + 1] - centers[i] || 1;
      const p = i + clamp01((sD - centers[i]) / span);
      const target = Math.round(p);
      if (target !== active && Math.abs(p - active) > 0.56) { active = target; retarget(seq[active]); }
      // camera holds on each step, then glides to the next
      const a = seq[Math.floor(p)], b = seq[Math.min(seq.length - 1, Math.floor(p) + 1)], f = smooth(clamp01((p - Math.floor(p) - 0.16) / 0.68));
      const narrow = camera.aspect < 0.9 ? 1 + (0.9 - camera.aspect) * 1.5 : 1;
      const lerp = (u, v) => u + (v - u) * f;
      let dx = 0, dy = 0;
      if (!REDUCE) {
        const k = 1 - Math.exp(-dt * 2.2); ptr.sx += (ptr.x - ptr.sx) * k; ptr.sy += (ptr.y - ptr.sy) * k;
        dx = Math.sin(tNow * 0.11) * 0.45 + ptr.sx * 1.0; dy = Math.sin(tNow * 0.08 + 1) * 0.16 - ptr.sy * 0.5;
      }
      camera.position.set(lerp(a.cam[0], b.cam[0]) * narrow + dx, lerp(a.cam[1], b.cam[1]) + dy, lerp(a.cam[2], b.cam[2]) * narrow);
      camera.lookAt(lerp(a.look[0], b.look[0]), lerp(a.look[1], b.look[1]), lerp(a.look[2], b.look[2]));
      U.uT.value = tNow - transStart;
      slabK += ((current.scl[N - 1] > 0 && current.name !== 'cloud' ? 1 : 0) - slabK) * (REDUCE ? 1 : 1 - Math.exp(-dt * 5));
      slab.visible = slabK > 0.01; if (slab.visible) { slab.scale.y = Math.max(0.001, slabK); slab.position.y = -0.27 + 5.22 * slabK; }
      const inRead = current.name === 'read' && !REDUCE;
      scan.visible = inRead;
      U.uScanOn.value = inRead ? Math.min(1, U.uT.value / 0.6) : 0;
      if (inRead) { U.uScanX.value = -26 + ((tNow * 5) % 52); scan.position.x = U.uScanX.value; }
      U.uSpin.value = REDUCE ? 0 : (tNow * 0.08) % 6.2832;
      if (tier === 0 && tNow < transEnd) renderer.shadowMap.needsUpdate = true;
      renderer.render(scene, camera);
      if (!sawFirst) { sawFirst = true; canvas.classList.add('on'); }
      // watch the frame time and step down if the machine is struggling
      if (dt < 0.2) { winN++; winSum += dt; }
      if (winN >= 45) {
        const avg = winSum / winN * 1000; winN = 0; winSum = 0;
        if (avg > 20 && now - lastDown > 1500 && now - tStart > 1500 && tier < 2) { lastDown = now; setTier(tier + 1); }
      }
    }
    let lost = false, running = false;
    function setRunning() {
      const want = !lost && routeNow() === 'story';
      if (want && !running) { running = true; Frame.add(frame); }
      if (!want && running) { running = false; Frame.remove(frame); }
    }
    addEventListener('hashchange', setRunning);
    canvas.addEventListener('webglcontextlost', e => { e.preventDefault(); lost = true; running = false; Frame.remove(frame); fallback(); });
    canvas.addEventListener('webglcontextrestored', () => { lost = false; root.classList.remove('no-gl'); Object.values(A).forEach(a => { a.needsUpdate = true; }); renderer.shadowMap.needsUpdate = true; setRunning(); });
    setRunning();
  }
})();
