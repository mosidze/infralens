'use strict';
const $ = (id) => document.getElementById(id);
const api = async (method, path, body) => {
  const r = await fetch(path, {
    method, headers: {'X-Infralens': '1', 'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let j = {};
  try { j = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) throw new Error(j.error || r.status + ' ' + r.statusText);
  return j;
};
const el = (tag, props, ...kids) => {
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  for (const k of kids) e.append(k);
  return e;
};
const money = (v) => '$' + Math.round(v).toLocaleString('en-US');
let state = {scans: [], notes: []};
let chosen = '';

// ---- tabs -------------------------------------------------------------------
document.querySelectorAll('#nav button').forEach((b) => b.addEventListener('click', () => show(b.dataset.tab)));
function show(tab) {
  document.querySelector('main').classList.toggle('wide', tab === 'map');
  document.querySelectorAll('#nav button').forEach((b) => b.classList.toggle('on', b.dataset.tab === tab));
  if (tab === 'map') loadMap();
  document.querySelectorAll('main > section').forEach((s) => { s.hidden = s.id !== 'tab-' + tab; });
}

// ---- state ------------------------------------------------------------------
async function refresh() {
  try { state = Object.assign(state, await api('GET', '/api/state')); } catch (e) { return; }
  $('ver').textContent = 'v' + String(state.version).replace(/^v/, '');
  const dl = $('profiles'); dl.textContent = '';
  (state.profiles || []).forEach((p) => dl.append(el('option', {value: p})));
  renderScans(); renderJob(state.job); renderAIScans();
  if (!$('tab-map').hidden && !$('mapframe').getAttribute('src')) loadMap();
}
function renderScans() {
  const tb = document.querySelector('#scans tbody'); tb.textContent = '';
  $('noscans').hidden = state.scans.length > 0;
  $('scans').hidden = state.scans.length === 0;
  for (const s of state.scans) {
    const [acct, file] = s.id.split('/');
    const open = el('a', {href: '#map', textContent: 'Open map'});
    open.addEventListener('click', (ev) => { ev.preventDefault(); openMap(s.id); });
    const gen = el('button', {textContent: 'Generate report'});
    gen.addEventListener('click', () => pick(s));
    tb.append(el('tr', {},
      el('td', {textContent: new Date(s.time).toLocaleString()}),
      el('td', {textContent: s.account || '—'}),
      el('td', {textContent: s.profile || '—'}),
      el('td', {className: 'n', textContent: s.resources}),
      el('td', {className: 'n', textContent: s.findings}),
      el('td', {className: 'n', textContent: money(s.waste)}),
      el('td', {}, open, document.createTextNode(' '), gen)));
  }
}

// ---- scan -------------------------------------------------------------------
let poll = null;
let shownJob = '';
let wasRunning = false;
function renderJob(j) {
  const running = !!j && j.state === 'running';
  $('go').disabled = running; $('stop').hidden = !running;
  $('log').hidden = !j;
  if (j) {
    $('log').textContent = (j.lines || []).join('\n');
    $('log').scrollTop = $('log').scrollHeight;
    $('jobstate').textContent = running ? 'running…' : j.state;
    const done = $('jobdone'); done.textContent = ''; done.hidden = true;
    if (j.state === 'failed') {
      done.hidden = false;
      done.append(el('p', {className: 'err', textContent: j.error}));
      if (/SSO|sso/.test(j.error)) done.append(el('p', {className: 'muted', textContent: 'Sign in in a terminal (aws sso login --profile NAME) or tick the box under “More options”, then start again.'}));
    } else if (j.state === 'done') {
      done.hidden = false;
      const s = state.scans.find((x) => x.id === j.scan);
      done.append(el('p', {className: 'ok', textContent: 'Scan finished.'}));
      if (j.scan && j.id !== shownJob) { shownJob = j.id; if (wasRunning) openMap(j.scan); }
      if (s) {
        const b = el('button', {className: 'primary', textContent: 'Generate report'});
        b.addEventListener('click', () => pick(s));
        done.append(b);
      }
    }
  }
  if (running) wasRunning = true;
  if (running && !poll) poll = setInterval(refresh, 1500);
  if (!running && poll) { clearInterval(poll); poll = null; }
}
$('go').addEventListener('click', async () => {
  try {
    await api('POST', '/api/scan', {
      profile: $('profile').value.trim(), regions: $('regions').value.trim(), services: $('services').value.trim(),
      tfstate: $('tfstate').value.trim(), prowler: $('prowler').value.trim(), sso_login: $('sso').checked,
    });
    await refresh();
  } catch (e) { $('jobstate').textContent = e.message; $('jobstate').className = 'err'; }
});
$('stop').addEventListener('click', async () => { await api('POST', '/api/job/cancel', {}); refresh(); });

// ---- audit ------------------------------------------------------------------
function pick(s) {
  chosen = s.id;
  $('auditbox').hidden = false;
  $('auditfor').textContent = `Scan of ${s.account || s.profile} taken ${new Date(s.time).toLocaleString()}`;
  $('a-out').textContent = '';
  show('reports');
  $('auditbox').scrollIntoView();
}
$('a-ai').addEventListener('change', async () => {
  $('aipreview').hidden = !$('a-ai').checked;
  if (!$('a-ai').checked) return;
  $('aiwhere').textContent = 'Preparing…';
  try {
    const p = await api('POST', '/api/ai/preview', {scan: chosen});
    $('aiwhere').textContent = p.local
      ? `${p.model} runs on this machine. ${p.bytes} bytes of facts are given to it.`
      : `${p.bytes} bytes (findings and totals, names/account numbers/ARNs removed) would be sent to ${p.model}.`;
    $('aipayload').textContent = p.system + '\n\n' + p.user;
  } catch (e) {
    $('aiwhere').textContent = e.message; $('aiwhere').className = 'err';
  }
});
const readLogo = (f) => new Promise((res, rej) => {
  if (!f) return res('');
  if (f.size > 256 * 1024) return rej(new Error('logo is larger than 256 KiB'));
  const r = new FileReader();
  r.onload = () => res(String(r.result).split(',')[1] || '');
  r.onerror = () => rej(new Error('cannot read the logo'));
  r.readAsDataURL(f);
});
$('a-go').addEventListener('click', async () => {
  const st = $('a-state'); st.className = 'muted'; st.textContent = 'working…';
  $('a-go').disabled = true;
  try {
    const logo = await readLogo($('a-logo').files[0]);
    const r = await api('POST', '/api/audit', {
      scan: chosen, client: $('a-client').value, consultant: $('a-consultant').value,
      anonymize: $('a-anon').checked, ai: $('a-ai').checked, ai_consent: $('a-consent').checked, logo_b64: logo,
    });
    st.textContent = '';
    const out = $('a-out'); out.textContent = '';
    out.append(el('p', {className: 'ok', textContent: 'Written to ' + r.path}));
    if (r.note) out.append(el('p', {className: 'err', textContent: r.note}));
    const ul = el('ul');
    for (const f of r.files) ul.append(el('li', {}, el('a', {href: `/out/${encodeURIComponent(r.dir)}/${f}`, target: '_blank', rel: 'noopener', textContent: f})));
    out.append(ul);
    if (r.anonymized) out.append(el('p', {className: 'muted', textContent: 'Identifiers are anonymised; the raw report and scan were not written here.'}));
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
  $('a-go').disabled = false;
});

// ---- notes ------------------------------------------------------------------
function renderNotes() {
  const tb = document.querySelector('#notetable tbody'); tb.textContent = '';
  state.notes.forEach((n, i) => {
    const m = Object.entries(n.match || {}).map(([k, v]) => `${k}=${v}`).join(', ');
    const rm = el('button', {textContent: 'Remove'});
    rm.addEventListener('click', () => { state.notes.splice(i, 1); renderNotes(); });
    tb.append(el('tr', {}, el('td', {textContent: m}), el('td', {textContent: n.note}), el('td', {textContent: n.until || ''}), el('td', {}, rm)));
  });
}
async function loadNotes() {
  try { state.notes = (await api('GET', '/api/context')).notes || []; renderNotes(); } catch (e) { /* ignore */ }
}
$('n-add').addEventListener('click', () => {
  const v = $('n-value').value.trim(), t = $('n-text').value.trim();
  if (!v || !t) { $('n-state').className = 'err'; $('n-state').textContent = 'a match value and a note are required'; return; }
  const n = {match: {[$('n-field').value]: v}, note: t};
  if ($('n-until').value) n.until = $('n-until').value;
  state.notes.push(n); renderNotes();
  $('n-value').value = ''; $('n-text').value = ''; $('n-state').textContent = '';
});
$('n-save').addEventListener('click', async () => {
  try {
    const r = await api('PUT', '/api/context', {notes: state.notes});
    $('n-state').className = 'ok'; $('n-state').textContent = `saved ${r.notes} note(s); applied the next time a report is opened`;
  } catch (e) { $('n-state').className = 'err'; $('n-state').textContent = e.message; }
});

// ---- settings ---------------------------------------------------------------
function fillSettings(l) {
  $('s-provider').value = l.provider || ''; $('s-model').value = l.model || ''; $('s-base').value = l.base_url || '';
  $('s-keyenv').value = (l.key_ref || '').startsWith('env:') ? l.key_ref.slice(4) : '';
  $('s-profile').value = l.profile || ''; $('s-region').value = l.region || ''; $('s-lang').value = l.language || '';
  $('s-key').value = '';
  $('s-keystate').textContent = 'Key: ' + (l.key_ref || 'none') + ' — ' + l.key_state;
}
$('s-save').addEventListener('click', async () => {
  const st = $('s-state'); st.className = 'muted'; st.textContent = '';
  try {
    const l = await api('PUT', '/api/settings', {
      provider: $('s-provider').value, model: $('s-model').value, base_url: $('s-base').value,
      key_env: $('s-keyenv').value, key: $('s-key').value, profile: $('s-profile').value,
      region: $('s-region').value, language: $('s-lang').value,
    });
    fillSettings(l); st.className = 'ok'; st.textContent = 'saved';
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
});
$('s-test').addEventListener('click', async () => {
  const st = $('s-state'); st.className = 'muted'; st.textContent = 'asking…';
  try {
    const r = await api('POST', '/api/llm/test', {});
    st.className = 'ok'; st.textContent = `${r.model} (${r.local ? 'local' : 'remote'}) answered: ${r.answer}`;
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
});

(async () => {
  const t = location.hash.slice(1);
  if (['scan', 'map', 'reports', 'ai', 'notes', 'settings'].includes(t)) show(t);
  await refresh(); await loadNotes();
  try { fillSettings((await api('GET', '/api/settings'))); } catch (e) { /* ignore */ }
})();

// ---- models -----------------------------------------------------------------
async function saveSettings() {
  return api('PUT', '/api/settings', {
    provider: $('s-provider').value, model: $('s-model').value, base_url: $('s-base').value,
    key_env: $('s-keyenv').value, key: $('s-key').value, profile: $('s-profile').value,
    region: $('s-region').value, language: $('s-lang').value,
  });
}
$('s-models-btn').addEventListener('click', async () => {
  const st = $('s-state'); st.className = 'muted'; st.textContent = 'loading…';
  try {
    fillSettings(await saveSettings());
    const r = await api('GET', '/api/llm/models');
    const dl = $('s-models'); dl.textContent = '';
    r.models.forEach((m) => dl.append(el('option', {value: m})));
    if (!$('s-model').value && r.suggested) $('s-model').placeholder = 'suggested: ' + r.suggested;
    st.className = 'ok';
    st.textContent = `${r.models.length} models available` + (r.suggested ? `; suggested: ${r.suggested} (type in the field to choose another)` : '');
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
});

// ---- AI analysis ------------------------------------------------------------
function renderAIScans() {
  const sel = $('ai-scan'); const keep = sel.value; sel.textContent = '';
  state.scans.forEach((s) => sel.append(el('option', {value: s.id,
    textContent: `${new Date(s.time).toLocaleString()} · ${s.account || s.profile} · ${s.findings} findings`})));
  if (keep) sel.value = keep;
}
let aiRemote = true;
async function aiPreview() {
  $('ai-where').textContent = ''; $('ai-det').hidden = true; $('ai-consent-row').hidden = true;
  if (!$('ai-scan').value) return;
  try {
    const p = await api('POST', '/api/ai/preview', {scan: $('ai-scan').value});
    aiRemote = !p.local;
    $('ai-where').textContent = p.local
      ? `${p.model} runs on this machine; ${p.bytes} bytes of facts are given to it.`
      : `${p.bytes} bytes (findings and totals, names/account numbers/ARNs removed) would be sent to ${p.model}.`;
    $('ai-payload').textContent = p.system + '\n\n' + p.user;
    $('ai-det').hidden = false; $('ai-consent-row').hidden = p.local;
  } catch (e) { $('ai-where').className = 'err'; $('ai-where').textContent = e.message; }
}
$('ai-scan').addEventListener('change', aiPreview);
document.querySelector('#nav [data-tab=ai]').addEventListener('click', aiPreview);
$('ai-go').addEventListener('click', async () => {
  const st = $('ai-state'); st.className = 'muted'; st.textContent = 'asking the model… this can take a minute';
  $('ai-go').disabled = true; $('ai-out').hidden = true;
  try {
    const r = await api('POST', '/api/ai/report', {scan: $('ai-scan').value, question: $('ai-q').value, consent: $('ai-consent').checked});
    st.textContent = '';
    const out = $('ai-out'); out.textContent = ''; out.hidden = false;
    out.append(el('p', {className: 'muted', textContent: `Written by ${r.model}` + (r.removed ? `; ${r.removed} statement(s) removed during validation` : '')}));
    if (r.narrative) {
      if (r.narrative.headline) out.append(el('p', {}, el('b', {textContent: r.narrative.headline})));
      (r.narrative.paragraphs || []).forEach((t) => out.append(el('p', {textContent: t})));
    }
    if (r.answer) out.append(el('p', {textContent: r.answer.answer}));
    out.append(el('p', {}, el('a', {href: '/ai/' + encodeURIComponent(r.file), target: '_blank', rel: 'noopener', textContent: 'Open as a document (print or save)'}),
      document.createTextNode('  ·  ' + r.path)));
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
  $('ai-go').disabled = false;
});

// ---- map in the same window -------------------------------------------------
let mapScan = '';
function mapURL(id) {
  const [acct, file] = id.split('/');
  return `/scan/${encodeURIComponent(acct)}/${encodeURIComponent(file)}/report`;
}
function openMap(id) { mapScan = id; show('map'); }
function loadMap() {
  const sel = $('map-scan');
  sel.textContent = '';
  state.scans.forEach((s) => sel.append(el('option', {value: s.id,
    textContent: `${new Date(s.time).toLocaleString()} · ${s.account || s.profile} · ${s.resources} resources`})));
  $('map-empty').hidden = state.scans.length > 0;
  if (!state.scans.length) { $('mapframe').removeAttribute('src'); return; }
  if (!mapScan || !state.scans.some((s) => s.id === mapScan)) mapScan = state.scans[0].id;
  sel.value = mapScan;
  $('map-new').href = mapURL(mapScan);
  const want = mapURL(mapScan);
  if (!$('mapframe').src.endsWith(want)) $('mapframe').src = want;
}
$('map-scan').addEventListener('change', () => { mapScan = $('map-scan').value; loadMap(); });

// The map is an offline document with no network access of its own. When it
// is shown here it asks this page to put a question to the model.
window.addEventListener('message', async (ev) => {
  if (ev.origin !== location.origin || ev.source !== $('mapframe').contentWindow) return;
  const m = ev.data;
  if (!m || m.t !== 'infralens-ask' || typeof m.node !== 'string') return;
  const reply = (body) => ev.source.postMessage(Object.assign({t: 'infralens-answer', nonce: m.nonce}, body), location.origin);
  const send = (consent) => fetch('/api/ai/node', {
    method: 'POST', headers: {'X-Infralens': '1', 'Content-Type': 'application/json'},
    body: JSON.stringify({scan: mapScan, node: m.node, question: String(m.q || ''), consent}),
  });
  try {
    let r = await send(false);
    let j = await r.json();
    if (r.status === 409 && j.needs_consent) {
      const ok = confirm(`${j.bytes} bytes of facts about this one resource (names, ARNs and account numbers removed) will be sent to ${j.model}.\n\nFirst lines:\n${String(j.payload).split('\n').slice(0, 12).join('\n')}\n\nSend?`);
      if (!ok) return reply({error: 'not sent: you declined'});
      r = await send(true); j = await r.json();
    }
    if (!r.ok) return reply({error: j.error || r.statusText});
    reply({answer: j.answer, findings: j.findings, model: j.model, removed: j.removed, based_on: j.based_on});
  } catch (e) { reply({error: String(e.message || e)}); }
});
