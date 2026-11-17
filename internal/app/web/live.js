'use strict';
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const SVG = 'http://www.w3.org/2000/svg';
const qs = new URLSearchParams(location.search);
if (qs.has('kiosk')) document.body.classList.add('kiosk');
if (qs.has('embed')) document.body.classList.add('embed');

const ago = (ms) => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return s + ' s';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' min';
  const h = Math.floor(m / 60);
  return h + ' h ' + (m % 60) + ' min';
};
const money = (v) => '$' + Math.round(v).toLocaleString('en-US');

function spark(series, sev) {
  const pts = (series && series.points) || [];
  if (pts.length < 2) return null;
  const box = el('div', 'sparkbox');
  const last = pts[pts.length - 1];
  const cap = el('div', 'cap');
  cap.append(el('span', 'capname', series.name), el('span', 'capval', (Math.round(last.v * 10) / 10) + (series.unit ? ' ' + series.unit : '')));
  cap.title = series.name + ' over the last 6 hours';
  const W = 340, H = 38, pad = 4;
  const ys = pts.map((p) => p.v), lo = Math.min(...ys), hi = Math.max(...ys);
  const span = hi - lo || 1;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('class', 'spark');
  svg.setAttribute('role', 'img');
  const x = (i) => pad + (i / (pts.length - 1)) * (W - 2 * pad);
  const y = (v) => H - pad - ((v - lo) / span) * (H - 2 * pad);
  const color = sev === 'crit' ? 'var(--crit)' : 'var(--warn)';
  const line = document.createElementNS(SVG, 'polyline');
  line.setAttribute('points', pts.map((p, i) => x(i).toFixed(1) + ',' + y(p.v).toFixed(1)).join(' '));
  line.setAttribute('fill', 'none');
  line.setAttribute('stroke', color);
  line.setAttribute('stroke-width', '2');
  line.setAttribute('vector-effect', 'non-scaling-stroke');
  line.setAttribute('stroke-linejoin', 'round');
  svg.append(line);
  box.append(cap, svg);
  return box;
}

// linkTo wraps text in a link that opens in a new tab, or returns the plain
// element when there is no usable http(s) address.
function linkTo(node, href) {
  if (!href || !/^https?:\/\//i.test(href)) return node;
  const a = el('a', 'golink');
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.title = 'Open where this problem lives';
  a.append(node);
  return a;
}

function renderSignal(s) {
  const d = el('div', 'sig ' + s.severity);
  d.append(linkTo(el('div', 't', s.title), s.link));
  if (s.evidence && s.evidence.length) {
    const ul = el('ul');
    s.evidence.forEach((e) => ul.append(el('li', null, e)));
    d.append(ul);
  }
  if (s.threshold) d.append(el('div', 'thr', 'rule: ' + s.threshold));
  const sp = spark(s.series, s.severity);
  if (sp) d.append(sp);
  (s.changes || []).forEach((c) => {
    const w = el('div', 'chg');
    const when = el('span', 'ago-live', ago(Date.now() - new Date(c.when).getTime()) + ' ago');
    when.dataset.t = new Date(c.when).getTime();
    when.dataset.suffix = ' ago';
    w.append(when, document.createTextNode(' · '));
    if (c.who) { w.append(el('b', null, c.who), document.createTextNode(' · ')); }
    w.append(document.createTextNode(c.what));
    d.append(w);
  });
  return d;
}

function renderNode(n) {
  const sev = n.signals[0].severity;
  const box = el('div', 'node');
  const top = el('div', 'top');
  top.append(el('span', 'dot ' + sev), el('span', 'name', n.name), el('span', 'kind', n.kind + (n.region ? ' · ' + n.region : '')));
  const since = Math.min(...n.signals.map((s) => new Date(s.since).getTime()));
  const a = el('span', 'ago ago-live', ago(Date.now() - since));
  a.dataset.t = since;
  top.append(a);
  box.append(top);
  n.signals.forEach((s) => box.append(renderSignal(s)));
  const foot = el('div', 'foot');
  if (n.connected) foot.append(el('span', null, 'connected to ' + n.connected + ': ' + (n.neighbors || []).join(', ')));
  if (n.owner) foot.append(el('span', null, 'owner ' + n.owner));
  if (n.cost_month) foot.append(el('span', null, money(n.cost_month) + '/mo'));
  if (n.unmapped) foot.append(el('span', null, 'not in the last scan'));
  if (foot.childNodes.length) box.append(foot);
  return box;
}

const CHRONIC = {
  'alarm.firing': 'Alarms that have stood in ALARM for more than 3 days',
  'ecs.under-replicated': 'Services short of tasks for more than 3 days',
  'sqs.dlq-standing': 'Dead-letter queues holding messages that are not changing',
};
let chronicOpen = false;
function renderChronic(groups) {
  const total = groups.reduce((a, g) => a + g.count, 0);
  const btn = $('chronicBtn'), panel = $('chronic');
  btn.hidden = total === 0;
  if (!total) { panel.hidden = true; return; }
  btn.textContent = total + ' standing ' + (chronicOpen ? '▴' : '▾');
  btn.title = 'Wrong, but not changing: not what is sick right now';
  panel.hidden = !chronicOpen;
  panel.textContent = '';
  groups.forEach((g) => {
    panel.append(el('h3', null, (CHRONIC[g.kind] || g.kind) + ' (' + g.count + ')'));
    g.items.forEach((it) => {
      const row = el('div', 'item');
      row.append(linkTo(el('span', 'n', it.name), it.link));
      let d = it.title;
      if (it.since && it.since.indexOf('0001') !== 0) d += ' · for ' + ago(Date.now() - new Date(it.since).getTime());
      row.append(el('span', 'd', d));
      panel.append(row);
    });
  });
}
$('chronicBtn').addEventListener('click', () => { chronicOpen = !chronicOpen; if (last) renderChronic(last.chronic || []); });

let last = null;
function render(snap) {
  last = snap;
  $('demo').hidden = !snap.demo;
  $('kindtag').textContent = snap.kind === 'k8s' ? 'Kubernetes' : snap.kind === 'aws' ? 'AWS' : '';
  const counts = $('counts'); counts.textContent = '';
  if (snap.crit) counts.append(el('span', 'cnt crit', snap.crit + ' critical'));
  if (snap.warn) counts.append(el('span', 'cnt warn', snap.warn + ' warning'));
  const n = snap.crit + snap.warn;
  document.title = (n ? '(' + n + ') ' : '') + 'Problem Monitor Live';
  renderChronic(snap.chronic || []);

  const blind = $('blind'); blind.textContent = '';
  blind.hidden = !(snap.blind && snap.blind.length);
  if (!blind.hidden) {
    blind.append(document.createTextNode('The monitor cannot see everything right now'));
    snap.blind.forEach((b) => blind.append(el('div', null, b)));
  }

  const board = $('board'); board.textContent = '';
  if (!snap.incidents.length) {
    const q = el('div', 'quiet');
    q.append(el('b', null, 'No problems'));
    const ok = snap.collectors.filter((c) => c.ok && !c.disabled).length;
    const off = snap.collectors.filter((c) => c.disabled);
    q.append(el('span', null, snap.blind && snap.blind.length ? 'but not every source is answering' : ok + ' source' + (ok === 1 ? '' : 's') + ' answering'));
    off.forEach((c) => q.append(el('div', 'kind', c.name + ' is not available: ' + (c.why || ''))));
    board.append(q);
  }
  snap.incidents.forEach((inc) => {
    const c = el('section', 'inc ' + inc.severity);
    inc.nodes.forEach((nd) => c.append(renderNode(nd)));
    board.append(c);
  });
  tick();
}

function tick() {
  document.querySelectorAll('.ago-live').forEach((e) => {
    e.textContent = ago(Date.now() - Number(e.dataset.t)) + (e.dataset.suffix || '');
  });
  if (!last) return;
  const parts = [];
  if (last.updated_at && last.updated_at.indexOf('0001') !== 0) parts.push('checked ' + ago(Date.now() - new Date(last.updated_at).getTime()) + (Date.now() - new Date(last.updated_at).getTime() < 5000 ? '' : ' ago'));
  if (last.budget && last.budget.cap_usd) parts.push('metrics $' + last.budget.spent_usd.toFixed(2) + ' of $' + last.budget.cap_usd.toFixed(2) + ' today' + (last.budget.throttled ? ' (slowed)' : ''));
  if (last.suppressed) parts.push(last.suppressed + ' silenced by your notes');
  $('meta').textContent = parts.join(' · ');
}

const api = async (method, path, body) => {
  const r = await fetch(path, {
    method, headers: { 'X-Infralens': '1', 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let j = {};
  try { j = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) { const err = new Error(j.error || r.statusText); err.status = r.status; throw err; }
  return j;
};

// ---- monitors are tabs ------------------------------------------------------
let monitors = [], selected = sessionStorage.getItem('il-mon') || '', adding = false, startShown = false;

function badge(m) {
  if (m.crit) return el('span', 'tb crit', String(m.crit + m.warn));
  if (m.warn) return el('span', 'tb warn', String(m.warn));
  if (m.blind) return el('span', 'tb blind', '!');
  return null;
}

function renderTabs() {
  const t = $('tabs'); t.textContent = '';
  monitors.forEach((m) => {
    const b = el('button', 'tab' + (!adding && m.id === selected ? ' on' : ''));
    b.append(el('span', 'k', m.kind === 'k8s' ? 'K8s' : m.kind === 'aws' ? 'AWS' : m.kind), el('span', null, ' ' + m.name));
    const bd = badge(m); if (bd) b.append(bd);
    b.addEventListener('click', () => { selected = m.id; adding = false; startShown = false; sessionStorage.setItem('il-mon', selected); poll(); });
    t.append(b);
  });
  const plus = el('button', 'tab plus' + (adding ? ' on' : ''), '+');
  plus.title = 'Watch another AWS account or Kubernetes cluster';
  plus.addEventListener('click', () => { adding = true; startShown = false; poll(); });
  t.append(plus);
}

function clearBoardChrome() {
  last = null;
  $('stop').hidden = true; $('chronicBtn').hidden = true; $('chronic').hidden = true;
  $('counts').textContent = ''; $('meta').textContent = ''; $('blind').hidden = true; $('kindtag').textContent = '';
  document.title = 'Problem Monitor Live';
}

async function showStart(note) {
  clearBoardChrome();
  startShown = true;
  let profiles = [];
  try {
    const st = await api('GET', '/api/state');
    const scanned = new Set((st.scans || []).map((s) => s.profile).filter(Boolean));
    profiles = (st.profiles || []).filter((p) => scanned.has(p));
  } catch (e) { /* none */ }
  const board = $('board'); board.textContent = '';
  const box = el('div', 'start');
  box.append(el('h2', null, monitors.length ? 'Watch something else' : 'Not watching anything yet'));
  const kinds = el('div', 'kinds');
  const bAws = el('button', 'kind on', 'AWS account'), bK8s = el('button', 'kind', 'Kubernetes cluster');
  kinds.append(bAws, bK8s);
  const body = el('div'); const err = el('div', 'err'); if (note) err.textContent = note;
  box.append(kinds, body, err);

  const awsForm = () => {
    body.textContent = '';
    body.append(el('p', null, 'The account must have been scanned once: the scan is the map this screen works from.'));
    const row = el('div', 'row');
    const sel = el('select'); profiles.forEach((p) => sel.append(new Option(p, p)));
    const go = el('button', 'go', 'Start watching');
    if (!profiles.length) { go.disabled = true; body.append(el('p', 'kind', 'No scanned profile yet. Scan one on the Scan tab first.')); }
    row.append(sel, go); body.append(row);
    go.addEventListener('click', () => start(go, { kind: 'aws', name: sel.value }));
  };
  const k8sForm = () => {
    body.textContent = '';
    body.append(el('p', null, 'Read-only: only GET requests are ever sent to the cluster. Leave the path empty to use your default kubeconfig.'));
    const path = el('input'); path.placeholder = 'kubeconfig file (optional), e.g. ~/.kube/prod.yaml';
    const load = el('button', null, 'Read contexts');
    const row1 = el('div', 'row'); row1.append(path, load);
    const sel = el('select'); sel.hidden = true;
    const go = el('button', 'go', 'Start watching'); go.hidden = true;
    const row2 = el('div', 'row'); row2.append(sel, go);
    body.append(row1, row2);
    const read = async () => {
      err.textContent = '';
      try {
        const r = await api('GET', '/api/k8s/contexts' + (path.value.trim() ? '?kubeconfig=' + encodeURIComponent(path.value.trim()) : ''));
        sel.textContent = ''; (r.contexts || []).forEach((c) => sel.append(new Option(c, c)));
        sel.hidden = go.hidden = !(r.contexts || []).length;
        if (!(r.contexts || []).length) err.textContent = 'No contexts found in that kubeconfig.';
      } catch (e) { err.textContent = e.message; sel.hidden = go.hidden = true; }
    };
    load.addEventListener('click', read);
    go.addEventListener('click', () => start(go, { kind: 'k8s', name: sel.value, kubeconfig: path.value.trim() }));
    read();
  };
  const start = async (btn, spec) => {
    btn.disabled = true; err.textContent = '';
    try {
      const r = await api('POST', '/api/live/start', spec);
      selected = r.id; adding = false; startShown = false; sessionStorage.setItem('il-mon', selected);
      poll();
    } catch (e) { err.textContent = e.message; btn.disabled = false; }
  };
  bAws.addEventListener('click', () => { bAws.classList.add('on'); bK8s.classList.remove('on'); awsForm(); });
  bK8s.addEventListener('click', () => { bK8s.classList.add('on'); bAws.classList.remove('on'); k8sForm(); });
  awsForm();
  board.append(box);
}

async function poll() {
  try {
    monitors = (await api('GET', '/api/live/monitors')).monitors || [];
  } catch (e) {
    const blind = $('blind'); blind.hidden = false; blind.textContent = 'Lost contact with InfraLens: ' + e.message;
    return;
  }
  if (!monitors.length) adding = true;
  if (!adding && !monitors.some((m) => m.id === selected)) selected = monitors[0].id;
  renderTabs();
  if (adding) { if (!startShown) showStart(); return; }
  try {
    const snap = await api('GET', '/api/live/state?id=' + encodeURIComponent(selected));
    $('stop').hidden = false;
    render(snap);
  } catch (e) {
    if (e.status === 404) { selected = ''; return; }
    const blind = $('blind'); blind.hidden = false; blind.textContent = 'Lost contact with InfraLens: ' + e.message;
  }
}
$('stop').addEventListener('click', async () => {
  const m = monitors.find((x) => x.id === selected);
  if (!m || !confirm('Stop watching ' + m.name + '?')) return;
  await api('POST', '/api/live/stop', { id: m.id });
  selected = ''; poll();
});

$('fs').addEventListener('click', () => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen()));
document.addEventListener('keydown', (e) => {
  if (e.key === 'f' || e.key === 'F') $('fs').click();
  if (e.key === 'k' || e.key === 'K') document.body.classList.toggle('kiosk');
});
setInterval(tick, 1000);
setInterval(poll, 3000);
poll();
