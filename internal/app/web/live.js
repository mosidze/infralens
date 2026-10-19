'use strict';
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const SVG = 'http://www.w3.org/2000/svg';
if (new URLSearchParams(location.search).has('kiosk')) document.body.classList.add('kiosk');

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

function renderSignal(s) {
  const d = el('div', 'sig ' + s.severity);
  d.append(el('div', 't', s.title));
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

let last = null;
function render(snap) {
  last = snap;
  $('demo').hidden = !snap.demo;
  const counts = $('counts'); counts.textContent = '';
  if (snap.crit) counts.append(el('span', 'cnt crit', snap.crit + ' critical'));
  if (snap.warn) counts.append(el('span', 'cnt warn', snap.warn + ' warning'));
  const n = snap.crit + snap.warn;
  document.title = (n ? '(' + n + ') ' : '') + 'Problem Monitor Live';

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
  if (last.profile) parts.push(last.profile);
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

let stopped = true;
async function showStart(note) {
  last = null; stopped = true;
  $('stop').hidden = true; $('counts').textContent = ''; $('meta').textContent = ''; $('blind').hidden = true;
  document.title = 'Problem Monitor Live';
  let profiles = [];
  try { profiles = (await api('GET', '/api/state')).profiles || []; } catch (e) { /* none */ }
  const board = $('board'); board.textContent = '';
  const box = el('div', 'start');
  box.append(el('h2', null, 'Not watching yet'), el('p', null, 'Choose an account. It must have been scanned once: the scan is the map this screen works from.'));
  const row = el('div', 'row');
  const sel = el('select');
  profiles.forEach((p) => sel.append(new Option(p, p)));
  const go = el('button', 'go', 'Start watching');
  row.append(sel, go);
  box.append(row);
  const err = el('div', 'err'); if (note) err.textContent = note;
  box.append(err);
  go.addEventListener('click', async () => {
    go.disabled = true; err.textContent = '';
    try { await api('POST', '/api/live/start', { profile: sel.value }); stopped = false; poll(); }
    catch (e) { err.textContent = e.message; go.disabled = false; }
  });
  board.append(box);
}

async function poll() {
  try {
    const snap = await api('GET', '/api/live/state');
    if (stopped) { stopped = false; }
    $('stop').hidden = false;
    render(snap);
  } catch (e) {
    if (e.status === 404) { if (!stopped || !document.querySelector('.start')) showStart(); return; }
    const blind = $('blind'); blind.hidden = false; blind.textContent = 'Lost contact with InfraLens: ' + e.message;
  }
}
$('stop').addEventListener('click', async () => { await api('POST', '/api/live/stop', {}); showStart(); });

$('fs').addEventListener('click', () => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen()));
document.addEventListener('keydown', (e) => {
  if (e.key === 'f' || e.key === 'F') $('fs').click();
  if (e.key === 'k' || e.key === 'K') document.body.classList.toggle('kiosk');
});
setInterval(tick, 1000);
setInterval(poll, 3000);
poll();
