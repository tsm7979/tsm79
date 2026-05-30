/* =====================================================================
   TSM79 v3 ENGINE
   ===================================================================== */
(() => {
  'use strict';

  /* ------------------------------------------------------------------
     0.  CINEMATIC LOADER  — sequential boot sequence
     ------------------------------------------------------------------ */
  const loader   = document.querySelector('.loader');
  const linesEl  = document.querySelector('.loader-lines');
  const barEl    = document.querySelector('.loader-bar');
  const percEl   = document.querySelector('.loader-bottom .p');

  const BOOT = [
    { ts: '00:00:01', msg: 'POWER ON · TSM SOVEREIGN EDGE',     end: 'OK' },
    { ts: '00:00:02', msg: 'ATTESTING SUPPLY CHAIN',            end: 'OK' },
    { ts: '00:00:03', msg: 'LOADING POLICY ENGINE',             end: 'OK' },
    { ts: '00:00:04', msg: 'INITIALIZING ROUTING LAYER',        end: 'OK' },
    { ts: '00:00:05', msg: 'BINDING OBSERVABILITY PIPELINE',    end: 'OK' },
    { ts: '00:00:06', msg: 'OPENING AUDIT LEDGER · IMMUTABLE',  end: 'OK' },
    { ts: '00:00:07', msg: 'HANDSHAKE · SOVEREIGN BROKER',      end: 'OK' },
    { ts: '00:00:08', msg: 'CONTROL PLANE · READY',             end: 'LIVE' },
  ];

  let loaderDone = false;
  const startApp = () => {
    if (loaderDone) return;
    loaderDone = true;
    setTimeout(() => loader?.classList.add('is-done'), 400);
    document.body.classList.add('is-loaded');
    setTimeout(() => {
      document.querySelector('.hero-title')?.classList.add('is-in');
      document.querySelectorAll('.hero-col').forEach(el => el.classList.add('is-in'));
      runCliTyper();
    }, 60);
    // Safety: after the entrance has played, force the title to its final
    // position with no transition — bulletproof even if a transition froze
    // (e.g. backgrounded tab) or JS timing slipped.
    setTimeout(() => {
      document.documentElement.classList.remove('anim');
      document.querySelectorAll('.hero-title .row > span').forEach(s => {
        s.style.transition = 'none';
        s.style.transform = 'translateY(0)';
      });
    }, 2600);
    /* hero scene owned by engine_v4.js (WebGPU module) */
  };

  function runLoader() {
    if (!loader || !linesEl) { startApp(); return; }
    let p = 0, i = 0;
    const tick = () => {
      // append line
      if (i < BOOT.length) {
        const b = BOOT[i++];
        const ln = document.createElement('div');
        ln.className = 'loader-line';
        ln.innerHTML = `<span class="ts">[ ${b.ts} ]</span><span class="msg">${b.msg}</span><span class="ok">${b.end}</span>`;
        linesEl.appendChild(ln);
        // animate in
        setTimeout(() => ln.classList.add('is-in'), 20);
      }
      p = Math.min(100, (i / BOOT.length) * 100);
      if (barEl) barEl.style.setProperty('--p', p + '%');
      if (percEl) percEl.textContent = String(Math.floor(p)).padStart(3, '0') + '%';

      if (i < BOOT.length) setTimeout(tick, 240 + Math.random() * 160);
      else setTimeout(startApp, 480);
    };
    setTimeout(tick, 180);
    // Hard fallback
    setTimeout(startApp, 4500);
  }
  runLoader();

  /* ------------------------------------------------------------------
     1.  CURSOR (inner dot + outer ring · mix-blend-mode difference)
     ------------------------------------------------------------------ */
  const cd = document.querySelector('.cursor-dot');
  const cr = document.querySelector('.cursor-ring');
  let mx = innerWidth / 2, my = innerHeight / 2;
  let cx = mx, cy = my, rx = mx, ry = my;
  addEventListener('pointermove', e => { mx = e.clientX; my = e.clientY; });
  function cursorLoop() {
    cx += (mx - cx) * 0.55;
    cy += (my - cy) * 0.55;
    rx += (mx - rx) * 0.18;
    ry += (my - ry) * 0.18;
    if (cd) cd.style.transform = `translate(${cx}px, ${cy}px) translate(-50%, -50%)`;
    if (cr) cr.style.transform = `translate(${rx}px, ${ry}px) translate(-50%, -50%)`;
    requestAnimationFrame(cursorLoop);
  }
  cursorLoop();
  document.addEventListener('pointerover', e => {
    if (e.target.closest('a, button, [data-cursor="hot"], .console-tab, .audit-row, .editor-files .f, .pane-side .item')) document.body.classList.add('is-hot');
  });
  document.addEventListener('pointerout', e => {
    if (e.target.closest('a, button, [data-cursor="hot"], .console-tab, .audit-row, .editor-files .f, .pane-side .item')) document.body.classList.remove('is-hot');
  });

  /* ------------------------------------------------------------------
     2.  LIVE UTC TIMECODE (with offset that advances on loop)
     ------------------------------------------------------------------ */
  let pageTimeOffset = 0;
  const tcEls = document.querySelectorAll('[data-tc]');
  const pad = n => String(n).padStart(2, '0');
  const updateTime = () => {
    const d = new Date(Date.now() + pageTimeOffset);
    const t = `${d.getUTCFullYear()} · ${pad(d.getUTCMonth()+1)} · ${pad(d.getUTCDate())} · ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
    tcEls.forEach(el => el.textContent = t);
  };
  updateTime(); setInterval(updateTime, 1000);

  /* ------------------------------------------------------------------
     4.  ROUTING CANVAS — animated provider flow
     ------------------------------------------------------------------ */
  function initRoutingCanvas() {
    const canvas = document.querySelector('canvas.routing-canvas');
    if (!canvas || canvas.dataset.inited) return;
    canvas.dataset.inited = '1';
    const ctx = canvas.getContext('2d');
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    let W = 0, H = 0;
    const resize = () => {
      const r = canvas.parentElement.getBoundingClientRect();
      W = Math.max(200, r.width - 80);
      H = Math.max(200, r.height - 80);
      canvas.width = W * DPR; canvas.height = H * DPR;
      canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    };
    resize();
    setTimeout(resize, 200);
    addEventListener('resize', resize);

    const layout = () => {
      const sources = [0.2, 0.4, 0.6, 0.8].map((t, i) => ({ x: 0, y: H * t, label: ['app.web','app.mobile','app.cli','app.svc'][i] }));
      const policy  = { x: W * 0.42, y: H * 0.5, label: 'TSM79' };
      const models  = [0.22, 0.5, 0.78].map((t, i) => ({ x: W, y: H * t, label: ['MODEL · PUBLIC','MODEL · PRIVATE','MODEL · SOVEREIGN'][i], hint: ['openai · anthropic · google','vpc · your region','onprem · attested'][i] }));
      return { sources, policy, models };
    };

    const packets = [];
    for (let i = 0; i < 22; i++) {
      packets.push({ phase: Math.random() < 0.5 ? 'in' : 'out', src: Math.floor(Math.random()*4), dst: Math.floor(Math.random()*3), t: Math.random(), spd: 0.003 + Math.random()*0.004 });
    }

    function frame() {
      if (W < 50 || H < 50) { resize(); requestAnimationFrame(frame); return; }
      ctx.clearRect(0, 0, W, H);
      const { sources, policy, models } = layout();

      // grid backdrop
      ctx.strokeStyle = 'rgba(255,255,255,0.025)';
      ctx.lineWidth = 1;
      for (let g = 0; g < W; g += 64) { ctx.beginPath(); ctx.moveTo(g, 0); ctx.lineTo(g, H); ctx.stroke(); }
      for (let g = 0; g < H; g += 64) { ctx.beginPath(); ctx.moveTo(0, g); ctx.lineTo(W, g); ctx.stroke(); }

      // Connections (hairline)
      ctx.strokeStyle = 'rgba(122,122,122,0.5)';
      ctx.lineWidth = 1;
      sources.forEach(s => { ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(policy.x, policy.y); ctx.stroke(); });
      models.forEach(m => { ctx.beginPath(); ctx.moveTo(policy.x, policy.y); ctx.lineTo(m.x, m.y); ctx.stroke(); });

      // Halo around policy
      const haloGrad = ctx.createRadialGradient(policy.x, policy.y, 4, policy.x, policy.y, 80);
      haloGrad.addColorStop(0, 'rgba(199,242,62,0.22)');
      haloGrad.addColorStop(1, 'rgba(199,242,62,0)');
      ctx.fillStyle = haloGrad;
      ctx.fillRect(policy.x - 80, policy.y - 80, 160, 160);

      // Nodes
      ctx.font = '10px JetBrains Mono, monospace';
      sources.forEach(s => {
        ctx.fillStyle = '#F3F3F3';
        ctx.fillRect(s.x - 4, s.y - 4, 8, 8);
        ctx.fillStyle = '#7A7A7A';
        ctx.fillText(s.label, s.x + 14, s.y + 4);
      });
      models.forEach(m => {
        ctx.fillStyle = '#F3F3F3';
        ctx.fillRect(m.x - 4, m.y - 4, 8, 8);
        ctx.fillStyle = '#7A7A7A';
        ctx.textAlign = 'right';
        ctx.fillText(m.label, m.x - 14, m.y - 4);
        ctx.fillStyle = '#4A4A4A';
        ctx.fillText(m.hint, m.x - 14, m.y + 8);
        ctx.textAlign = 'left';
      });

      // Policy center node (square + outer)
      ctx.fillStyle = '#C7F23E';
      ctx.fillRect(policy.x - 8, policy.y - 8, 16, 16);
      ctx.strokeStyle = 'rgba(199,242,62,0.6)';
      ctx.strokeRect(policy.x - 16, policy.y - 16, 32, 32);
      ctx.fillStyle = '#C7F23E';
      ctx.font = '11px JetBrains Mono, monospace';
      ctx.fillText(policy.label, policy.x - 16, policy.y + 36);
      ctx.fillStyle = '#7A7A7A';
      ctx.font = '9px JetBrains Mono, monospace';
      ctx.fillText('CONTROL PLANE', policy.x - 32, policy.y + 50);

      // Packets
      packets.forEach(p => {
        p.t += p.spd;
        if (p.t > 1) {
          p.t = 0;
          p.src = Math.floor(Math.random()*4);
          p.dst = Math.floor(Math.random()*3);
          p.phase = Math.random() < 0.5 ? 'in' : 'out';
        }
        let a, b;
        if (p.phase === 'in')  { a = sources[p.src]; b = policy; }
        else                   { a = policy;         b = models[p.dst]; }
        const x = a.x + (b.x - a.x) * p.t;
        const y = a.y + (b.y - a.y) * p.t;
        // trail
        for (let k = 3; k >= 0; k--) {
          const tk = p.t - k * 0.025;
          if (tk < 0) continue;
          const tx = a.x + (b.x - a.x) * tk;
          const ty = a.y + (b.y - a.y) * tk;
          ctx.fillStyle = `rgba(199,242,62,${0.85 - k * 0.22})`;
          ctx.fillRect(tx - 2, ty - 2, 4, 4);
        }
        ctx.fillStyle = '#C7F23E';
        ctx.fillRect(x - 2, y - 2, 4, 4);
      });

      requestAnimationFrame(frame);
    }
    frame();
  }
  setTimeout(initRoutingCanvas, 600);

  /* ------------------------------------------------------------------
     5.  SPARKLINES + BARS
     ------------------------------------------------------------------ */
  function drawSpark(c) {
    const ctx = c.getContext('2d');
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    const seedStr = c.getAttribute('data-seed') || '0';
    const seed = Array.from(seedStr).reduce((a,b) => a + b.charCodeAt(0), 1);
    const color = c.getAttribute('data-color') || '#C7F23E';
    const trend = parseFloat(c.getAttribute('data-trend') || '0.4');

    function rng(n) { const x = Math.sin(n * 9301 + seed * 49297) * 233280; return x - Math.floor(x); }

    function draw() {
      const r = c.getBoundingClientRect();
      if (r.width < 10) return;
      c.width = r.width * DPR; c.height = r.height * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      ctx.clearRect(0, 0, r.width, r.height);

      // grid
      ctx.strokeStyle = 'rgba(255,255,255,0.05)';
      ctx.lineWidth = 1;
      for (let g = 1; g <= 3; g++) {
        const y = (r.height / 4) * g;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(r.width, y); ctx.stroke();
      }
      for (let g = 1; g <= 5; g++) {
        const x = (r.width / 6) * g;
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, r.height); ctx.stroke();
      }

      const N = 64;
      const pts = [];
      for (let i = 0; i < N; i++) {
        const t = i / (N-1);
        const base = rng(i) * 0.55 + 0.2;
        const slope = t * trend;
        pts.push({ x: t * r.width, y: r.height * (1 - base * 0.6 - slope * 0.4 + 0.05) });
      }
      // area
      ctx.beginPath();
      ctx.moveTo(pts[0].x, r.height);
      pts.forEach(p => ctx.lineTo(p.x, p.y));
      ctx.lineTo(pts[pts.length-1].x, r.height);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, 0, 0, r.height);
      grad.addColorStop(0, color + '40');
      grad.addColorStop(1, color + '00');
      ctx.fillStyle = grad;
      ctx.fill();
      // line
      ctx.beginPath();
      pts.forEach((p,i) => i===0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
      ctx.strokeStyle = color; ctx.lineWidth = 1.4; ctx.stroke();
      const last = pts[pts.length-1];
      ctx.fillStyle = color;
      ctx.fillRect(last.x - 3, last.y - 3, 6, 6);
    }
    draw();
    addEventListener('resize', draw);
  }
  function drawBars(c) {
    const ctx = c.getContext('2d');
    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    const seedStr = c.getAttribute('data-seed') || '0';
    const seed = Array.from(seedStr).reduce((a,b) => a + b.charCodeAt(0), 1);
    function rng(n) { const x = Math.sin(n * 9301 + seed * 49297) * 233280; return x - Math.floor(x); }

    function draw() {
      const r = c.getBoundingClientRect();
      if (r.width < 10) return;
      c.width = r.width * DPR; c.height = r.height * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      ctx.clearRect(0, 0, r.width, r.height);

      const N = 24;
      const bw = r.width / (N * 1.2);
      const gap = bw * 0.2;
      for (let i = 0; i < N; i++) {
        const h = rng(i) * r.height * 0.85 + r.height * 0.1;
        const x = i * (bw + gap);
        const y = r.height - h;
        // base bar (muted)
        ctx.fillStyle = 'rgba(122,122,122,0.5)';
        ctx.fillRect(x, y, bw, h);
        // accent
        const accent = rng(i + 100) * h * 0.4;
        ctx.fillStyle = '#C7F23E';
        ctx.fillRect(x, y, bw, accent);
      }
    }
    draw();
    addEventListener('resize', draw);
  }
  document.querySelectorAll('canvas.spark').forEach(drawSpark);
  document.querySelectorAll('canvas.bars').forEach(drawBars);

  /* ------------------------------------------------------------------
     6.  CONSOLE TABS  +  Pane Side selection
     ------------------------------------------------------------------ */
  document.querySelectorAll('.console-tab').forEach((t, i) => {
    t.addEventListener('click', () => {
      const target = t.getAttribute('data-pane');
      document.querySelectorAll('.console-tab').forEach(x => x.classList.remove('is-active'));
      t.classList.add('is-active');
      document.querySelectorAll('.console-pane').forEach(p => p.classList.toggle('is-active', p.getAttribute('data-pane') === target));
    });
  });
  document.querySelectorAll('.pane-side .item, .editor-files .f').forEach(el => {
    el.addEventListener('click', () => {
      el.parentElement.querySelectorAll('.item, .f').forEach(x => x.classList.remove('is-active'));
      el.classList.add('is-active');
    });
  });

  /* ------------------------------------------------------------------
     7.  LEDGER STREAMING
     ------------------------------------------------------------------ */
  function streamLedger(target) {
    const states = [
      { tag: 'ROUTED',   pip: 'live',    body: 'req · policy.allow · model.b · vpc',     lat: '11 ms', tok: '1.4k' },
      { tag: 'BLOCKED',  pip: 'blocked', body: 'req · policy.block.pii · —',             lat: '3 ms',  tok: '—' },
      { tag: 'ROUTED',   pip: 'live',    body: 'req · policy.allow · model.a · cloud',   lat: '13 ms', tok: '2.1k' },
      { tag: 'REROUTED', pip: 'routed',  body: 'req · policy.cost.cap · model.c',        lat: '14 ms', tok: '0.9k' },
      { tag: 'ROUTED',   pip: 'live',    body: 'req · policy.allow · model.a · cloud',   lat: '12 ms', tok: '1.7k' },
      { tag: 'BLOCKED',  pip: 'blocked', body: 'req · policy.block.secret · —',          lat: '4 ms',  tok: '—' },
    ];
    let i = 0;
    const push = () => {
      const s = states[i++ % states.length];
      const row = document.createElement('div');
      row.className = 'ledger-row';
      row.innerHTML = `
        <span class="pip ${s.pip}"></span>
        <span class="body">${s.body}</span>
        <span class="lat">${s.lat}</span>
        <span class="v">${s.tok}</span>
      `;
      target.prepend(row);
      while (target.children.length > 7) target.lastElementChild.remove();
    };
    for (let k = 0; k < 6; k++) push();
    setInterval(push, 1900);
  }
  const ledger = document.querySelector('[data-ledger]');
  if (ledger) streamLedger(ledger);

  /* ------------------------------------------------------------------
     8.  POLICY-STREAM LIVE BLOCK FEED
     ------------------------------------------------------------------ */
  function streamPolicy() {
    const target = document.querySelector('[data-policy-stream]');
    if (!target) return;
    const lines = [
      { kind: 'blocked', tag: '[BLOCKED]', body: 'pii.email · redacted at ingress' },
      { kind: 'routed',  tag: '[ALLOW]',   body: 'policy.standard.v3 · model.b · vpc' },
      { kind: 'reroute', tag: '[REROUTE]', body: 'cost.cap exceeded · → model.c · onprem' },
      { kind: 'blocked', tag: '[BLOCKED]', body: 'secret.api_key · pattern match · drop' },
      { kind: 'routed',  tag: '[ALLOW]',   body: 'policy.sovereign.eu · model.a · eu-west' },
      { kind: 'blocked', tag: '[BLOCKED]', body: 'intent.dual_use · escalated to review' },
      { kind: 'routed',  tag: '[ALLOW]',   body: 'policy.healthcare.v2 · model.b · vpc' },
    ];
    let i = 0;
    const push = () => {
      const l = lines[i++ % lines.length];
      const now = new Date(Date.now() + pageTimeOffset);
      const ts = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
      const id = 'req_' + Math.random().toString(16).slice(2, 12);
      const row = document.createElement('div');
      row.className = 'policy-stream-row ' + l.kind;
      row.innerHTML = `<span class="ts">[ ${ts} ]</span><span class="tag">${l.tag}</span><span class="body">${id}  <em>·</em>  ${l.body}</span>`;
      target.prepend(row);
      while (target.children.length > 6) target.lastElementChild.remove();
    };
    for (let k = 0; k < 5; k++) push();
    setInterval(push, 1600);
  }
  streamPolicy();

  /* ------------------------------------------------------------------
     9.  AUDIT TIMELINE — select row → update side detail
     ------------------------------------------------------------------ */
  const auditRows = document.querySelectorAll('.audit-row');
  const auditId    = document.querySelector('[data-audit-id]');
  const auditPolicy = document.querySelector('[data-audit-policy]');
  const auditTitle = document.querySelector('[data-audit-title]');
  const auditSteps = document.querySelector('[data-audit-steps]');

  function selectAudit(row) {
    auditRows.forEach(r => r.classList.remove('is-selected'));
    row.classList.add('is-selected');
    const id     = row.getAttribute('data-id') || '—';
    const policy = row.getAttribute('data-policy') || '—';
    const title  = row.getAttribute('data-title') || 'Request';
    const stepsJSON = row.getAttribute('data-steps') || '[]';
    let steps = [];
    try { steps = JSON.parse(stepsJSON); } catch (e) {}
    if (auditId) auditId.textContent = id;
    if (auditPolicy) auditPolicy.textContent = policy;
    if (auditTitle) auditTitle.textContent = title;
    if (auditSteps) {
      auditSteps.innerHTML = steps.map(s => `
        <div class="step ${s.k || ''}"><span class="dot"></span><span class="lbl-step">${s.l}</span><span class="ms">${s.t}</span></div>
      `).join('');
    }
  }
  auditRows.forEach(r => r.addEventListener('click', () => selectAudit(r)));
  if (auditRows[0]) selectAudit(auditRows[0]);

  /* ------------------------------------------------------------------
     10. CLI TYPER — long classified sequence
     ------------------------------------------------------------------ */
  const cliBody = document.querySelector('.cli-body');
  const cliCursor = document.querySelector('.cli-cursor');

  const CLI_SCRIPT = [
    { type: 'prompt', text: '$ ', after: 200 },
    { type: 'in', text: 'tsm init --sovereign-edge', after: 500 },
    { type: 'newline' },
    { type: 'out', text: '✓ workspace created  · tsm@sovereign-edge', cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ control plane reserved · 12 ms median',   cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ ledger opened · immutable · 7y retain',   cls: 'ok',   after: 160 },
    { type: 'newline' },
    { type: 'prompt', text: '$ ', after: 380 },
    { type: 'in', text: 'tsm route --policy sovereign.yaml --canary 5%', after: 600 },
    { type: 'newline' },
    { type: 'out', text: '◇ loading policy file  ............... sovereign.yaml',   cls: 'mute', after: 180 },
    { type: 'out', text: '✓ policy.block.pii        · active',                      cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ policy.block.secret     · active',                      cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ policy.intent           · active · 98.1% acc',          cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ policy.cost.cap         · active · $0 overage',         cls: 'ok',   after: 160 },
    { type: 'out', text: '✓ policy.geo.eu           · active · gdpr · ccpa',        cls: 'ok',   after: 160 },
    { type: 'out', text: '◇ routing                 · cost · latency · sovereign',  cls: 'mute', after: 180 },
    { type: 'out', text: '◇ canary at 5%            · model.b · vpc',               cls: 'mute', after: 180 },
    { type: 'newline' },
    { type: 'prompt', text: '$ ', after: 460 },
    { type: 'in', text: 'tsm tail --filter blocked --follow', after: 600 },
    { type: 'newline' },
    { type: 'out', text: '[ 14:22:08 ]  req_8f3a2e1c  → policy.block.pii      · ✗ rejected',          cls: 'err', after: 280 },
    { type: 'out', text: '[ 14:22:09 ]  req_8f3a2e1d  → policy.allow          · ✓ model.b · 11 ms', cls: 'ok',  after: 280 },
    { type: 'out', text: '[ 14:22:09 ]  req_8f3a2e1e  → policy.cost.cap       · ↻ → model.c',       cls: 'warn',after: 280 },
    { type: 'out', text: '[ 14:22:10 ]  req_8f3a2e1f  → policy.block.secret   · ✗ rejected',        cls: 'err', after: 280 },
    { type: 'out', text: '[ 14:22:11 ]  req_8f3a2e20  → policy.allow          · ✓ model.a · 13 ms', cls: 'ok',  after: 280 },
    { type: 'newline' },
    { type: 'prompt', text: '$ ', after: 400 },
  ];

  function runCliTyper() {
    if (!cliBody || !cliCursor) return;
    let i = 0, line = null;
    const newline = () => {
      line = document.createElement('span');
      line.className = 'cli-line';
      cliBody.insertBefore(line, cliCursor);
    };
    const step = () => {
      if (i >= CLI_SCRIPT.length) return;
      const s = CLI_SCRIPT[i++];
      if (!line) newline();
      if (s.type === 'prompt') {
        const sp = document.createElement('span'); sp.className = 'prompt'; sp.textContent = s.text;
        line.appendChild(sp);
        setTimeout(step, s.after ?? 120);
      } else if (s.type === 'in') {
        let k = 0; const sp = document.createElement('span'); sp.className = 'out';
        line.appendChild(sp);
        const typeChar = () => {
          if (k < s.text.length) { sp.textContent += s.text.charAt(k++); setTimeout(typeChar, 12 + Math.random() * 22); }
          else setTimeout(step, s.after ?? 200);
        };
        typeChar();
      } else if (s.type === 'newline') {
        newline();
        setTimeout(step, 30);
      } else if (s.type === 'out') {
        const sp = document.createElement('span'); sp.className = s.cls || 'out'; sp.textContent = s.text;
        line.appendChild(sp);
        newline();
        setTimeout(step, s.after ?? 160);
      }
    };
    step();
  }

  /* ------------------------------------------------------------------
     11. REVEAL — defaults visible; below-fold pre-hides + io reveals
     ------------------------------------------------------------------ */
  const revealTargets = document.querySelectorAll('[data-reveal], [data-mask]');
  revealTargets.forEach(el => {
    const r = el.getBoundingClientRect();
    if (r.top >= innerHeight) el.classList.add('pre-reveal');
  });
  const io = new IntersectionObserver((entries) => {
    entries.forEach(en => {
      if (en.isIntersecting) {
        en.target.classList.remove('pre-reveal');
        io.unobserve(en.target);
      }
    });
  }, { rootMargin: '0px 0px -4% 0px', threshold: 0.04 });
  revealTargets.forEach(el => { if (el.classList.contains('pre-reveal')) io.observe(el); });
  setTimeout(() => document.querySelectorAll('.pre-reveal').forEach(el => el.classList.remove('pre-reveal')), 5000);

  /* ------------------------------------------------------------------
     12. ACTIVE SECTION TRACKER
     ------------------------------------------------------------------ */
  const navLinks = document.querySelectorAll('.mast-nav a, .transport a');
  const sections = document.querySelectorAll('[data-section]');
  const updateActive = () => {
    let active = null;
    sections.forEach(s => {
      const r = s.getBoundingClientRect();
      if (r.top < innerHeight * 0.5 && r.bottom > innerHeight * 0.4) active = '#' + s.id;
    });
    navLinks.forEach(l => l.classList.toggle('is-active', l.getAttribute('href') === active));
  };
  addEventListener('scroll', updateActive, { passive: true });
  updateActive();

  /* ------------------------------------------------------------------
     13. INFINITE LOOP
     ------------------------------------------------------------------ */
  let lastLoop = 0;
  function checkLoop() {
    const max = document.documentElement.scrollHeight - innerHeight;
    if (max <= 0) return;
    if (window.scrollY >= max - 4 && Date.now() - lastLoop > 1500) {
      lastLoop = Date.now();
      pageTimeOffset += 60 * 1000;
      const m = document.querySelector('.mast-logo');
      if (m) { m.style.color = '#C7F23E'; setTimeout(() => m.style.color = '', 320); }
      setTimeout(() => {
        if (lenis) lenis.scrollTo(1, { immediate: true });
        else window.scrollTo({ top: 1, behavior: 'auto' });
      }, 80);
    }
  }
  addEventListener('scroll', checkLoop, { passive: true });

  /* ------------------------------------------------------------------
     14. LENIS SMOOTH SCROLL  (inertial · the shader.se feel)
     ------------------------------------------------------------------ */
  let lenis = null;
  try {
    if (typeof Lenis !== 'undefined') {
      lenis = new Lenis({
        duration: 1.2,
        easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        smoothWheel: true,
        wheelMultiplier: 1.0,
        touchMultiplier: 1.5,
      });
      const raf = (time) => { lenis.raf(time); requestAnimationFrame(raf); };
      requestAnimationFrame(raf);
      // keep active-section + loop logic in sync with Lenis' virtual scroll
      lenis.on('scroll', () => { updateActive(); checkLoop(); });
    }
  } catch (e) { console.warn('[tsm] lenis unavailable', e); }

  /* ------------------------------------------------------------------
     15. SMOOTH ANCHOR  (routes through Lenis when present)
     ------------------------------------------------------------------ */
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', (e) => {
      const id = a.getAttribute('href');
      if (id === '#' || id.length < 2) return;
      const el = document.querySelector(id);
      if (!el) return;
      e.preventDefault();
      if (lenis) { lenis.scrollTo(el, { offset: -88, duration: 1.4 }); return; }
      const top = el.getBoundingClientRect().top + window.scrollY - 88;
      window.scrollTo({ top, behavior: 'smooth' });
    });
  });
})();
