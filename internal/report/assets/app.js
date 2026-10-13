(function () {
'use strict';

const D = scanData;
const $ = id => document.getElementById(id);
const nodes = D.nodes || [];
// A waste candidate the owner has acknowledged (context file) is shown as such
// and is not counted as waste; the note says why.
nodes.forEach(n => { if (n.ack && n.status === 'orphan_waste') n.status = 'acked'; });
const edges = D.edges || [];
// Scans saved before type_services existed still render: fall back to the known mapping.
const typeSvc = D.type_services && Object.keys(D.type_services).length ? D.type_services : {
  aws_instance: 'Amazon Elastic Compute Cloud - Compute', aws_ebs_volume: 'EC2 - Other', aws_ebs_snapshot: 'EC2 - Other',
  aws_eip: 'EC2 - Other', aws_nat_gateway: 'EC2 - Other', aws_lb: 'Amazon Elastic Load Balancing',
  aws_ecs_cluster: 'Amazon Elastic Container Service', aws_ecs_service: 'Amazon Elastic Container Service',
  aws_rds_instance: 'Amazon Relational Database Service', aws_opensearch_domain: 'Amazon OpenSearch Service',
  aws_kinesis_stream: 'Amazon Kinesis', aws_cloudwatch_log_group: 'AmazonCloudWatch',
  aws_cloudwatch_log_group_rollup: 'AmazonCloudWatch', aws_s3_bucket: 'Amazon Simple Storage Service',
  aws_lambda_function: 'AWS Lambda', aws_vpc_endpoint: 'Amazon Virtual Private Cloud', aws_redshift_cluster: 'Amazon Redshift',
  aws_memorydb_cluster: 'Amazon MemoryDB', aws_elasticache_cluster: 'Amazon ElastiCache', aws_dynamodb_table: 'Amazon DynamoDB',
  aws_sqs_queue: 'Amazon Simple Queue Service', aws_firehose_stream: 'Amazon Kinesis Firehose', aws_cloudfront_distribution: 'Amazon CloudFront',
};
const byId = new Map(nodes.map(n => [n.id, n]));

// ---------- formatting ----------
const usd = v => '$' + (v || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const usdc = v => {
  v = v || 0;
  if (v >= 10000) return '$' + (v / 1000).toFixed(0) + 'k';
  if (v >= 1000) return '$' + (v / 1000).toFixed(1) + 'k';
  if (v >= 100) return '$' + v.toFixed(0);
  return '$' + v.toFixed(2);
};
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text; // textContent only: tags and names are untrusted
  return e;
}

// ---------- vocabulary ----------
const TIER = {
  aws_lb: 0,
  aws_ecs_cluster: 1, aws_ecs_service: 1, aws_instance: 1,
  aws_rds_instance: 2, aws_opensearch_domain: 2, aws_kinesis_stream: 2,
  aws_nat_gateway: 3, aws_eip: 3, aws_ebs_volume: 3, aws_ebs_snapshot: 3,
  aws_s3_bucket: 4, aws_cloudwatch_log_group: 4, aws_cloudwatch_log_group_rollup: 4,
  aws_lambda_function: 1, aws_vpc_endpoint: 3, aws_redshift_cluster: 2, aws_memorydb_cluster: 2,
  aws_elasticache_cluster: 2, aws_dynamodb_table: 2, aws_sqs_queue: 2, aws_firehose_stream: 2,
  aws_cloudfront_distribution: 0,
};
const TIER_NAME = ['Entry points', 'Compute', 'Data', 'Network & disks', 'Storage & logs'];
const TYPE_LABEL = {
  aws_lb: 'Load balancer', aws_ecs_cluster: 'ECS cluster', aws_ecs_service: 'ECS service', aws_instance: 'EC2 instance',
  aws_rds_instance: 'RDS instance', aws_opensearch_domain: 'OpenSearch domain', aws_kinesis_stream: 'Kinesis stream',
  aws_nat_gateway: 'NAT gateway', aws_eip: 'Elastic IP', aws_ebs_volume: 'EBS volume', aws_ebs_snapshot: 'EBS snapshot',
  aws_s3_bucket: 'S3 bucket', aws_cloudwatch_log_group: 'Log group', aws_cloudwatch_log_group_rollup: 'Small log groups',
  aws_lambda_function: 'Lambda function', aws_vpc_endpoint: 'VPC endpoint', aws_redshift_cluster: 'Redshift cluster',
  aws_memorydb_cluster: 'MemoryDB cluster', aws_elasticache_cluster: 'ElastiCache cluster', aws_dynamodb_table: 'DynamoDB table',
  aws_sqs_queue: 'SQS queue', aws_firehose_stream: 'Firehose stream', aws_cloudfront_distribution: 'CloudFront distribution',
};
const TYPE_PLURAL = {
  aws_lb: 'load balancers', aws_ecs_service: 'ECS services', aws_ecs_cluster: 'ECS clusters', aws_instance: 'EC2 instances',
  aws_rds_instance: 'RDS instances', aws_opensearch_domain: 'OpenSearch domains', aws_kinesis_stream: 'Kinesis streams',
  aws_nat_gateway: 'NAT gateways', aws_eip: 'Elastic IPs', aws_ebs_volume: 'EBS volumes', aws_ebs_snapshot: 'EBS snapshots',
  aws_s3_bucket: 'S3 buckets', aws_cloudwatch_log_group: 'log groups', aws_cloudwatch_log_group_rollup: 'log group rollups',
  aws_lambda_function: 'Lambda functions', aws_vpc_endpoint: 'VPC endpoints', aws_redshift_cluster: 'Redshift clusters',
  aws_memorydb_cluster: 'MemoryDB clusters', aws_elasticache_cluster: 'ElastiCache clusters', aws_dynamodb_table: 'DynamoDB tables',
  aws_sqs_queue: 'SQS queues', aws_firehose_stream: 'Firehose streams', aws_cloudfront_distribution: 'CloudFront distributions',
};
const tierOf = t => (t in TIER ? TIER[t] : 4);
const typeLabel = t => TYPE_LABEL[t] || t.replace(/^aws_/, '').replace(/_/g, ' ');
const SEVERITY = { orphan_waste: 3, shadow_it: 2, acked: 1, unknown: 1, managed: 0 };
const worse = (a, b) => ((SEVERITY[a] || 0) >= (SEVERITY[b] || 0) ? a : b);

const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const COLOR = () => ({
  orphan_waste: css('--waste'), shadow_it: css('--shadow'), managed: css('--managed'),
  unknown: css('--unknown'), mixed: css('--unknown'), acked: css('--unknown'),
});

// ---------- state ----------
const state = {
  view: 'map', basis: 'list', status: 'all', region: '', q: '',
  expanded: new Set(), selected: null, tab: 'findings',
};
// The URL hash carries the view so that a link reproduces what you see.
let hashState = {};
try {
  hashState = JSON.parse(decodeURIComponent((location.hash || '').slice(1)) || '{}') || {};
  if (hashState.basis === 'billed') state.basis = 'billed';
  if (Array.isArray(hashState.expand)) hashState.expand.forEach(x => state.expanded.add(String(x)));
  if (typeof hashState.q === 'string') state.q = hashState.q.toLowerCase();
  if (['waste', 'shadow_it', 'managed', 'drift', 'costly', 'noowner'].includes(hashState.status)) state.status = hashState.status === 'waste' ? 'orphan_waste' : hashState.status;
  if (typeof hashState.region === 'string') state.region = hashState.region;
  if (hashState.theme === 'dark' || hashState.theme === 'light') document.documentElement.dataset.theme = hashState.theme;
} catch (e) { /* the hash is a convenience only */ }
function saveHash() {
  const h = {};
  if (state.basis !== 'list') h.basis = state.basis;
  if (state.expanded.size) h.expand = [...state.expanded];
  if (state.selected) h.select = state.selected;
  if (state.q) h.q = state.q;
  if (state.status !== 'all') h.status = state.status === 'orphan_waste' ? 'waste' : state.status;
  if (state.region) h.region = state.region;
  if (state.view !== 'map') h.view = state.view;
  if (hashState.theme) h.theme = hashState.theme;
  try { history.replaceState(null, '', '#' + encodeURIComponent(JSON.stringify(h))); } catch (e) { /* file:// may refuse */ }
}

// ---------- cost basis ----------
// "by bill": list-price estimates scaled so that each service sums to the
// last full month's Cost Explorer usage. An apportionment, not a measurement.
const estBySvc = {};
nodes.forEach(n => { const s = typeSvc[n.type]; if (s) estBySvc[s] = (estBySvc[s] || 0) + n.monthly_cost; });
const billedBySvc = {};
(D.service_costs || []).forEach(s => { billedBySvc[s.service] = s.previous_month_cost; });
function ratio(svc) {
  const e = estBySvc[svc], b = billedBySvc[svc];
  return e > 0 && b !== undefined ? b / e : 1;
}
const hasLedger = !!(D.ledger && D.ledger.services);
if (hasLedger && !hashState.basis) state.basis = 'billed';
function cost(n) {
  // With a cost ledger, MonthlyCost is real money allocated from the bill
  // where a usage type could be tied to the resource, and list_cost keeps the
  // catalogue estimate; "list" shows the catalogue price instead.
  if (hasLedger) return state.basis === 'list' ? (n.list_cost || n.monthly_cost) : n.monthly_cost;
  if (state.basis === 'list') return n.monthly_cost;
  const s = typeSvc[n.type];
  const scaled = s ? n.monthly_cost * ratio(s) : n.monthly_cost;
  // Apportioning can scale an estimate up. A waste figure is a saving we
  // claim, so it is never allowed above its list price.
  return n.status === 'orphan_waste' ? Math.min(scaled, n.monthly_cost) : scaled;
}

// ---------- hierarchy ----------
// container (VPC or "outside VPC") > group (ECS cluster or same-type bucket) > resource
const NOVPC = 'novpc';
const containerOf = n => n.vpc_id || NOVPC;
const groups = new Map();      // id -> {id,label,kind,members:[n],head,container,tier,type}
const groupOf = new Map();     // node id -> group id

(function buildGroups() {
  // 1. ECS clusters own their services
  const contains = new Map();
  edges.forEach(e => {
    if (e.label !== 'contains') return;
    if (!contains.has(e.source)) contains.set(e.source, []);
    contains.get(e.source).push(e.target);
  });
  contains.forEach((kids, headId) => {
    const head = byId.get(headId);
    const members = kids.map(k => byId.get(k)).filter(Boolean);
    if (!head || !members.length) return;
    const tally = {};
    members.forEach(m => { const c = containerOf(m); tally[c] = (tally[c] || 0) + 1; });
    const container = Object.keys(tally).sort((a, b) => tally[b] - tally[a])[0];
    const g = { id: head.id, label: head.name || head.id, kind: 'cluster', members, head, container, tier: 1, type: head.type };
    groups.set(g.id, g);
    members.forEach(m => groupOf.set(m.id, g.id));
    groupOf.set(head.id, g.id);
  });
  // 2. many same-type resources in one container collapse together
  const bucket = new Map();
  nodes.forEach(n => {
    if (groupOf.has(n.id)) return;
    const k = containerOf(n) + '|' + n.type;
    if (!bucket.has(k)) bucket.set(k, []);
    bucket.get(k).push(n);
  });
  bucket.forEach((list, k) => {
    if (list.length <= 5) return;
    const [container, type] = k.split('|');
    const g = {
      id: 'grp:' + k, label: (TYPE_PLURAL[type] || type), kind: 'bucket', members: list, head: null,
      container, tier: tierOf(type), type,
    };
    groups.set(g.id, g);
    list.forEach(m => groupOf.set(m.id, g.id));
  });
})();

function groupStats(g) {
  let c = 0, st = g.head ? g.head.status : 'managed', waste = 0, shadow = 0, wasteCost = 0;
  g.members.forEach(m => {
    c += cost(m);
    st = worse(st, m.status);
    if (m.status === 'orphan_waste') { waste++; wasteCost += cost(m); }
    if (m.status === 'shadow_it') shadow++;
  });
  return { cost: c, status: st, waste, shadow, wasteCost };
}

// ---------- filtering ----------
const regions = [...new Set(nodes.map(n => n.region).filter(Boolean))].sort();
let topCache = { key: '', set: null };
function topCostly() {
  const key = state.basis + ':' + (D.timestamp || '');
  if (topCache.key !== key) {
    const live = nodes.filter(n => !n.type.endsWith('_rollup')).slice().sort((a, b) => cost(b) - cost(a)).slice(0, 25);
    topCache = { key, set: new Set(live.map(n => n.id)) };
  }
  return topCache.set;
}
const FOCUS = {
  drift: n => !!(n.iac && n.iac.drift && n.iac.drift.length),
  costly: n => topCostly().has(n.id),
  noowner: n => !n.owner,
};
function nodeMatches(n) {
  if (FOCUS[state.status]) { if (!FOCUS[state.status](n)) return false; }
  else if (state.status !== 'all' && n.status !== state.status) return false;
  if (state.region && n.region !== state.region) return false;
  if (state.q) {
    const q = state.q;
    const hay = [n.name, n.id, n.type, typeLabel(n.type), n.region, n.managed_by,
      ...Object.values(n.tags || {}), ...Object.values(n.attrs || {})];
    if (!hay.some(v => v && String(v).toLowerCase().includes(q))) return false;
  }
  return true;
}
const filtering = () => state.status !== 'all' || state.region || state.q;

// ---------- sizes & layout ----------
const nodeDiameter = (c, max) => 22 + 46 * Math.sqrt(Math.max(c, 0) / (max || 1));

function visibleItems() {
  const items = [];
  const seen = new Set();
  groups.forEach(g => {
    const open = state.expanded.has(g.id);
    items.push({ kind: open ? 'open' : 'group', g, container: g.container, tier: g.tier });
    g.members.forEach(m => seen.add(m.id));
    if (g.head) seen.add(g.head.id);
  });
  nodes.forEach(n => {
    if (seen.has(n.id)) return;
    items.push({ kind: 'node', n, container: containerOf(n), tier: tierOf(n.type) });
  });
  return items;
}

function computeLayout(items) {
  const pos = new Map();
  const containers = new Map();
  items.forEach(it => {
    if (!containers.has(it.container)) containers.set(it.container, []);
    containers.get(it.container).push(it);
  });

  let maxCost = 1;
  items.forEach(it => {
    const c = it.kind === 'node' ? cost(it.n) : groupStats(it.g).cost;
    it._cost = c;
    if (c > maxCost) maxCost = c;
  });

  const PAD = 26, HEAD = 34, GAPX = 38, GAPY = 20, COLH = 640, CW = 118, CH = 62;
  const boxes = [];
  containers.forEach((list, key) => {
    list.forEach(it => {
      if (it.kind === 'node') {
        it.d = nodeDiameter(it._cost, maxCost);
        it.w = Math.max(it.d, 110); it.h = it.d + 30;
      } else if (it.kind === 'group') {
        it.d = Math.max(54, nodeDiameter(it._cost, maxCost));
        it.w = 180; it.h = it.d + 4;
      } else {
        const m = it.g.members.slice().sort((a, b) => cost(b) - cost(a));
        it.members = m;
        it.cols = Math.min(8, Math.max(2, Math.ceil(Math.sqrt(m.length * 2))));
        const rows = Math.ceil(m.length / it.cols);
        it.w = it.cols * CW + 2 * 18; it.h = rows * CH + 2 * 18 + 24;
      }
    });
    // tiers become columns; long columns wrap
    const byTier = new Map();
    list.forEach(it => { if (!byTier.has(it.tier)) byTier.set(it.tier, []); byTier.get(it.tier).push(it); });
    let x = 0, contentH = 0;
    [...byTier.keys()].sort((a, b) => a - b).forEach(t => {
      const col = byTier.get(t).sort((a, b) => b._cost - a._cost);
      let y = 0, colW = 0, startX = x;
      col.forEach(it => {
        if (y > 0 && y + it.h > COLH) { x += colW + GAPX; colW = 0; y = 0; }
        it.x = x; it.y = y;
        y += it.h + GAPY;
        colW = Math.max(colW, it.w);
        contentH = Math.max(contentH, y - GAPY);
      });
      x += colW + GAPX;
      void startX;
    });
    const contentW = Math.max(x - GAPX, 60);
    boxes.push({ key, list, w: contentW + 2 * PAD, h: contentH + 2 * PAD + HEAD, cost: list.reduce((s, i) => s + i._cost, 0) });
  });

  // Flow containers into rows. Several row widths are tried and the one that
  // gives the largest on-screen scale for the current stage proportions wins.
  boxes.sort((a, b) => b.cost - a.cost);
  const GAPC = 60;
  const flow = rowW => {
    let cx = 0, cy = 0, rowH = 0, W = 0;
    const out = [];
    boxes.forEach(b => {
      if (cx > 0 && cx + b.w > rowW) { cx = 0; cy += rowH + GAPC; rowH = 0; }
      out.push([b, cx, cy]);
      cx += b.w + GAPC; rowH = Math.max(rowH, b.h); W = Math.max(W, cx - GAPC);
    });
    return { out, W, H: cy + rowH };
  };
  const stage = $('stage');
  const sw = stage.clientWidth || 1200, sh = stage.clientHeight || 700;
  const cands = new Set([Math.max(...boxes.map(b => b.w), 1)]);
  let acc = 0;
  boxes.forEach(b => { acc += b.w + GAPC; cands.add(acc - GAPC); });
  let best = null;
  cands.forEach(rw => {
    const f = flow(rw);
    const sc = Math.min(sw / f.W, sh / f.H);
    if (!best || sc > best.sc) best = { f, sc };
  });
  best.f.out.forEach(([b, bx, by]) => {
    b.ox = bx; b.oy = by;
    b.list.forEach(it => {
      const ox = b.ox + PAD, oy = b.oy + PAD + HEAD;
      if (it.kind === 'open') {
        it.members.forEach((m, i) => {
          pos.set(m.id, {
            x: ox + it.x + 18 + (i % it.cols) * CW + CW / 2,
            y: oy + it.y + 24 + 18 + Math.floor(i / it.cols) * CH + 20,
          });
        });
      } else {
        pos.set(it.kind === 'node' ? it.n.id : it.g.id, { x: ox + it.x + it.w / 2, y: oy + it.y + it.d / 2 });
      }
    });
  });
  return { pos, maxCost };
}

// ---------- cytoscape ----------
let cy = null;
let tipEl = $('tip');

function containerLabel(key, list) {
  const total = list.reduce((s, c) => s + c, 0);
  if (key === NOVPC) return 'Outside any VPC · regional & account services · ' + usdc(total);
  const first = nodes.find(n => n.vpc_id === key);
  return key + (first ? ' · ' + first.region : '') + ' · ' + usdc(total);
}

function buildElements() {
  const items = visibleItems();
  const { pos, maxCost } = computeLayout(items);
  const colors = COLOR();
  const els = [];
  const newIds = new Set(((D.diff && D.diff.added) || []).map(c => c.id));

  // container compounds
  const perContainer = new Map();
  items.forEach(it => {
    if (!perContainer.has(it.container)) perContainer.set(it.container, []);
    perContainer.get(it.container).push(it._cost);
  });
  perContainer.forEach((costs, key) => {
    els.push({ data: { id: 'c:' + key, label: containerLabel(key, costs), kind: 'container' }, classes: 'container' });
  });

  const rep = new Map(); // node id -> element id it is drawn as
  items.forEach(it => {
    if (it.kind === 'node') {
      const n = it.n;
      rep.set(n.id, n.id);
      els.push({
        data: {
          id: n.id, kind: 'node', parent: 'c:' + it.container,
          label: (n.name && n.name !== n.id ? n.name : n.id) + '\n' + typeLabel(n.type) + ' · ' + usdc(cost(n)),
          size: nodeDiameter(cost(n), maxCost), color: colors[n.status] || colors.unknown, status: n.status,
          isNew: newIds.has(n.id) ? 1 : 0,
        },
        position: pos.get(n.id),
      });
    } else if (it.kind === 'group') {
      const s = groupStats(it.g);
      it.g.members.forEach(m => rep.set(m.id, it.g.id));
      if (it.g.head) rep.set(it.g.head.id, it.g.id);
      const bits = [it.g.members.length + ' ' + (TYPE_PLURAL[it.g.members[0].type] || 'resources')];
      if (s.waste) bits.push(s.waste + ' waste');
      if (s.shadow) bits.push(s.shadow + ' no IaC');
      if (filtering()) bits.push(it.g.members.filter(nodeMatches).length + ' match');
      els.push({
        data: {
          id: it.g.id, kind: 'group', parent: 'c:' + it.container,
          label: it.g.label + '\n' + bits.join(' · ') + '\n' + usdc(s.cost),
          size: it.d, color: colors[s.status] || colors.unknown, status: s.status,
          mixed: (s.waste || s.shadow) ? 1 : 0, isNew: 0,
        },
        position: pos.get(it.g.id), classes: 'group',
      });
    } else {
      const g = it.g, s = groupStats(g);
      els.push({
        data: { id: g.id, kind: 'open', parent: 'c:' + it.container, label: g.label + ' · ' + usdc(s.cost), status: s.status },
        classes: 'open',
      });
      if (g.head) rep.set(g.head.id, g.id);
      it.members.forEach(m => {
        rep.set(m.id, m.id);
        els.push({
          data: {
            id: m.id, kind: 'node', parent: g.id, label: (m.name || m.id) + '\n' + usdc(cost(m)),
            size: Math.min(34, Math.max(14, nodeDiameter(cost(m), maxCost) * 0.7)),
            color: colors[m.status] || colors.unknown, status: m.status, isNew: newIds.has(m.id) ? 1 : 0,
          },
          position: pos.get(m.id),
        });
      });
    }
  });

  // edges, aggregated at the level that is currently drawn
  const agg = new Map();
  edges.forEach(e => {
    if (e.label === 'contains') return;
    const a = rep.get(e.source), b = rep.get(e.target);
    if (!a || !b || a === b) return;
    const k = a + '>' + b;
    agg.set(k, (agg.get(k) || 0) + 1);
  });
  agg.forEach((count, k) => {
    const [a, b] = k.split('>');
    els.push({ data: { id: 'e:' + k, source: a, target: b, count, label: count > 1 ? String(count) : '' } });
  });
  return els;
}

function cyStyle() {
  const text = css('--text'), muted = css('--muted'), line = css('--line'), accent = css('--accent'), panel = css('--panel');
  return [
    { selector: 'node', style: {
        label: 'data(label)', color: text, 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 6,
        'text-wrap': 'wrap', 'text-max-width': 112, 'min-zoomed-font-size': 7,
        'border-width': 0, 'overlay-opacity': 0, 'text-outline-color': css('--stage'), 'text-outline-width': 2,
    } },
    { selector: 'node[size]', style: { width: 'data(size)', height: 'data(size)' } },
    { selector: 'node[color]', style: { 'background-color': 'data(color)' } },
    { selector: 'node[isNew = 1]', style: { 'border-width': 3, 'border-color': css('--new'), 'border-style': 'dashed' } },
    { selector: 'node.group', style: {
        shape: 'round-rectangle', width: 180, 'background-color': panel,
        'border-width': 3, 'text-valign': 'center', 'text-halign': 'center',
        'text-wrap': 'wrap', 'text-max-width': 168, 'font-size': 13, 'font-weight': 600,
        'text-outline-width': 0, 'min-zoomed-font-size': 5,
    } },
    { selector: 'node.group[color]', style: { 'border-color': 'data(color)' } },
    { selector: 'node.container', style: {
        shape: 'round-rectangle', 'background-color': panel, 'background-opacity': 0.55,
        'border-color': line, 'border-width': 1.5, 'border-style': 'dashed', padding: 34,
        label: 'data(label)', 'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -8,
        color: muted, 'font-size': 15, 'font-weight': 700, 'text-wrap': 'none', 'text-outline-width': 0,
        'min-zoomed-font-size': 0,
    } },
    { selector: 'node.open', style: {
        shape: 'round-rectangle', 'background-color': css('--panel2'), 'background-opacity': 0.8,
        'border-color': accent, 'border-width': 1.5, padding: 18,
        'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -6,
        color: accent, 'font-size': 13, 'font-weight': 700, 'text-wrap': 'none', 'text-outline-width': 0,
        'min-zoomed-font-size': 0,
    } },
    { selector: 'edge', style: {
        width: 'mapData(count, 1, 40, 1, 5)', 'line-color': muted, 'target-arrow-color': muted, 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier', 'arrow-scale': 0.9, opacity: 0.5, label: 'data(label)', 'font-size': 11, color: muted,
        'text-background-color': css('--stage'), 'text-background-opacity': 0.9, 'text-background-padding': 2,
        'min-zoomed-font-size': 9, 'overlay-opacity': 0,
    } },
    { selector: '.faded', style: { opacity: 0.14 } },
    { selector: 'node.container.faded, node.open.faded', style: { opacity: 1 } },
    { selector: '.dim', style: { opacity: 0.12 } },
    { selector: 'node.container.dim, node.open.dim', style: { opacity: 1 } },
    { selector: 'node:selected', style: { 'border-width': 4, 'border-color': accent, 'border-style': 'solid' } },
    { selector: 'edge.hl', style: { opacity: 0.95, width: 2.5, 'line-color': accent, 'target-arrow-color': accent } },
  ];
}

let scrollbarsUpdate = () => {};
// The map scrolls like a page: wheel pans, Ctrl/Cmd+wheel zooms, and two
// scrollbars show where the viewport sits inside the drawing.
function initScroll() {
  const box = $('cy'), sbx = $('sbx'), sby = $('sby');
  const PAD = 120;
  const geom = () => {
    const els = cy.elements();
    const ext = cy.extent();
    if (!els.length) return null;
    const bb = els.boundingBox();
    const x1 = Math.min(bb.x1 - PAD, ext.x1), x2 = Math.max(bb.x2 + PAD, ext.x2);
    const y1 = Math.min(bb.y1 - PAD, ext.y1), y2 = Math.max(bb.y2 + PAD, ext.y2);
    return { ext, x1, x2, y1, y2 };
  };
  const place = (bar, thumb, start, size, total, vertical) => {
    const track = vertical ? bar.clientHeight : bar.clientWidth;
    const len = Math.max(24, track * Math.min(1, size / total));
    const off = (track - len) * (total - size > 0 ? (start / (total - size)) : 0);
    thumb.style[vertical ? 'top' : 'left'] = Math.max(0, Math.min(track - len, off)) + 'px';
    thumb.style[vertical ? 'height' : 'width'] = len + 'px';
  };
  const update = () => {
    const visible = box.style.display !== 'none';
    const g = visible && geom();
    sbx.style.display = sby.style.display = g ? '' : 'none';
    if (!g) return;
    const w = g.x2 - g.x1, h = g.y2 - g.y1;
    sbx.style.visibility = g.ext.w >= w - 1 ? 'hidden' : '';
    sby.style.visibility = g.ext.h >= h - 1 ? 'hidden' : '';
    place(sbx, sbx.firstElementChild, g.ext.x1 - g.x1, g.ext.w, w, false);
    place(sby, sby.firstElementChild, g.ext.y1 - g.y1, g.ext.h, h, true);
  };
  cy.on('viewport add remove position', update);
  window.addEventListener('resize', update);
  window.requestAnimationFrame(update);
  scrollbarsUpdate = update;

  box.addEventListener('wheel', ev => {
    ev.preventDefault();
    if (ev.ctrlKey || ev.metaKey) {
      const r = box.getBoundingClientRect();
      const f = Math.exp(-ev.deltaY * 0.0025);
      cy.zoom({ level: Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * f)),
        renderedPosition: { x: ev.clientX - r.left, y: ev.clientY - r.top } });
    } else {
      const k = ev.deltaMode === 1 ? 16 : 1;
      cy.panBy({ x: -ev.deltaX * k, y: -ev.deltaY * k });
    }
  }, { passive: false });

  const drag = (bar, vertical) => {
    const thumb = bar.firstElementChild;
    thumb.addEventListener('pointerdown', ev => {
      ev.preventDefault(); thumb.setPointerCapture(ev.pointerId); bar.classList.add('drag');
      let last = vertical ? ev.clientY : ev.clientX;
      const move = e2 => {
        const g = geom(); if (!g) return;
        const now = vertical ? e2.clientY : e2.clientX;
        const track = vertical ? bar.clientHeight : bar.clientWidth;
        const total = vertical ? g.y2 - g.y1 : g.x2 - g.x1;
        const model = (now - last) * (total / track); // model units per pixel of track
        last = now;
        const z = cy.zoom();
        cy.panBy(vertical ? { x: 0, y: -model * z } : { x: -model * z, y: 0 });
      };
      const up = () => { bar.classList.remove('drag'); thumb.removeEventListener('pointermove', move); thumb.removeEventListener('pointerup', up); };
      thumb.addEventListener('pointermove', move); thumb.addEventListener('pointerup', up);
    });
  };
  drag(sbx, false); drag(sby, true);
}
function initCy() {
  cy = cytoscape({
    container: $('cy'), elements: [], style: cyStyle(), minZoom: 0.04, maxZoom: 3,
    boxSelectionEnabled: false, autoungrabify: true, userZoomingEnabled: false,
  });
  initScroll();

  cy.on('mouseover', 'node', e => {
    const n = e.target;
    if (n.hasClass('container') || n.hasClass('open')) return;
    showTip(tipFor(n.id()), e.originalEvent);
  });
  cy.on('mousemove', 'node', e => { if (!tipEl.hidden) moveTip(e.originalEvent); });
  cy.on('mouseout', 'node', hideTip);
  cy.on('tap', 'node', e => {
    const n = e.target;
    if (n.hasClass('container')) return;
    hideTip();
    select(n.id(), false);
  });
  cy.on('dbltap', 'node.group', e => { toggleGroup(e.target.id()); });
  cy.on('tap', 'node.open', e => { if (e.originalEvent && e.originalEvent.detail >= 2) toggleGroup(e.target.id()); });
  cy.on('tap', e => { if (e.target === cy) clearSelection(); });
}

function render(opts) {
  opts = opts || {};
  saveHash();
  const els = buildElements();
  const keep = cy.zoom(), pan = cy.pan();
  cy.batch(() => {
    cy.elements().remove();
    cy.add(els);
  });
  cy.layout({ name: 'preset', fit: false, positions: n => (n.position().x || n.position().y ? n.position() : { x: 0, y: 0 }) }).run();
  if (opts.fit || !render.done) {
    cy.fit(undefined, 50);
  } else {
    cy.zoom(keep); cy.pan(pan);
  }
  render.done = true;
  applyFilter();
  if (state.selected && cy.getElementById(state.selected).length) {
    cy.getElementById(state.selected).select();
    highlight(state.selected);
  }
  const empty = !nodes.length;
  $('empty').style.display = empty ? 'flex' : 'none';
}

function applyFilter() {
  cy.nodes().removeClass('faded');
  if (!filtering()) return;
  cy.nodes('[kind = "node"]').forEach(c => {
    const n = byId.get(c.id());
    if (n && !nodeMatches(n)) c.addClass('faded');
  });
  cy.nodes('[kind = "group"]').forEach(c => {
    const g = groups.get(c.id());
    if (g && !g.members.some(nodeMatches)) c.addClass('faded');
  });
  cy.edges().forEach(e => {
    if (e.source().hasClass('faded') || e.target().hasClass('faded')) e.addClass('faded');
  });
}

// when a filter is active open the groups that hold matches, so they are visible
function expandForMatches() {
  if (!filtering()) return false;
  let changed = false, opened = 0;
  groups.forEach(g => {
    if (opened >= 8 || state.expanded.has(g.id)) return;
    const hits = g.members.filter(nodeMatches).length;
    // Opening a big group for one or two hits buries them; those stay closed
    // and show their match count on the group itself.
    if (hits > 0 && g.members.length <= 40) { state.expanded.add(g.id); changed = true; opened++; }
  });
  return changed;
}

function toggleGroup(id) {
  if (state.expanded.has(id)) state.expanded.delete(id); else state.expanded.add(id);
  render();
  const e = cy.getElementById(id);
  if (e.length) cy.animate({ center: { eles: e }, duration: 250 });
}

// ---------- selection ----------
function highlight(id) {
  cy.elements().removeClass('dim hl');
  const e = cy.getElementById(id);
  if (!e.length) return;
  cy.elements().addClass('dim');
  // a group stands for everything inside it, so its members are part of the selection
  const core = e.union(e.descendants());
  const touching = core.connectedEdges();
  const hood = core.union(touching).union(touching.connectedNodes());
  hood.removeClass('dim');
  touching.addClass('hl');
  hood.nodes().ancestors().removeClass('dim');
}

function clearSelection() {
  state.selected = null;
  cy.elements().removeClass('dim hl').unselect();
  setTab('findings');
}

function select(id, center) {
  state.selected = id;
  saveHash();
  const real = byId.get(id);
  if (real && groupOf.has(id)) {
    const gid = groupOf.get(id);
    if (!state.expanded.has(gid) && gid !== id) { state.expanded.add(gid); render(); }
  }
  const e = cy.getElementById(id);
  if (e.length) {
    cy.elements().unselect();
    e.select();
    highlight(id);
    if (center) cy.animate({ center: { eles: e }, zoom: Math.max(cy.zoom(), 0.9), duration: 300 });
  }
  renderSelection(id);
  setTab('selection');
}

// ---------- tooltip ----------
function tipFor(id) {
  const box = el('div');
  const n = byId.get(id);
  if (n) {
    box.append(el('div', 't', n.name || n.id));
    box.append(el('div', 'p', usd(cost(n)) + ' /mo'));
    const m = el('div', 'm');
    m.textContent = typeLabel(n.type) + ' · ' + (n.region || '') + ' · ' + statusText(n);
    box.append(m);
    if (n.ack) { const a = el('div', 'm', 'Acknowledged: ' + n.ack.note + (n.ack.until ? ' (until ' + n.ack.until + ')' : '')); a.style.marginTop = '4px'; box.append(a); }
    if (n.waste_reason) { const w = el('div', 'warn', n.waste_reason); w.style.marginTop = '4px'; box.append(w); }
    const ev = (n.evidence || []).filter(x => !/^tag |^no tags|^no IaC/.test(x))[0];
    if (ev) { const x = el('div', 'm', ev); x.style.marginTop = '2px'; box.append(x); }
    if (n.iac) {
      const i = el('div', 'm', 'In code: ' + n.iac.source + ' · ' + n.iac.origin + (n.iac.drift && n.iac.drift.length ? ' · DRIFT' : ''));
      i.style.marginTop = '2px';
      box.append(i);
    }
    if (n.owner) { const o = el('div', 'm', 'Owner: ' + n.owner + ' (' + n.owner_source + ')'); o.style.marginTop = '2px'; box.append(o); }
    const basis = el('div', 'm', basisNote(n));
    basis.style.marginTop = '4px';
    box.append(basis);
    return box;
  }
  const g = groups.get(id);
  if (g) {
    const s = groupStats(g);
    box.append(el('div', 't', g.label));
    box.append(el('div', 'p', usd(s.cost) + ' /mo'));
    box.append(el('div', 'm', g.members.length + ' ' + (TYPE_PLURAL[g.members[0].type] || 'resources') +
      (s.waste ? ' · ' + s.waste + ' waste (' + usd(s.wasteCost) + ')' : '') + (s.shadow ? ' · ' + s.shadow + ' no IaC' : '')));
    const h = el('div', 'm', 'double-click to expand'); h.style.marginTop = '4px'; box.append(h);
  }
  return box;
}
const statusText = n => ({ orphan_waste: 'waste candidate', shadow_it: 'no IaC marker', managed: 'managed', unknown: 'unclassified', acked: 'acknowledged' }[n.status] || n.status) +
  (n.confidence ? ' (' + n.confidence + ')' : '');
function basisNote(n) {
  if (hasLedger) {
    if (state.basis === 'list') return 'catalogue price (an estimate from size and usage)';
    if (n.cost_basis === 'allocated') return 'allocated from last month\'s bill: real money, only the usage types attributable to this resource' + (n.cost_note ? ' (' + n.cost_note.replace(/^allocated from last month's bill by usage: /, '') + ')' : '');
    if (n.cost_basis === 'n/a') return 'no price available';
    return 'catalogue estimate: no usage type of the bill could be tied to this resource';
  }
  if (state.basis === 'list') return n.cost_source === 'n/a' ? 'cost not estimated' : 'list-price estimate';
  return 'apportioned to last month\'s bill (' + (typeSvc[n.type] || 'no service') + ')' + (n.status === 'orphan_waste' ? ', capped at list price' : '');
}
function showTip(content, ev) {
  tipEl.replaceChildren(content);
  tipEl.hidden = false;
  moveTip(ev);
}
function moveTip(ev) {
  if (!ev) return;
  const pad = 14, r = tipEl.getBoundingClientRect();
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - pad;
  tipEl.style.left = Math.max(8, x) + 'px';
  tipEl.style.top = Math.max(8, y) + 'px';
}
function hideTip() { tipEl.hidden = true; }

// ---------- side panel ----------
function setTab(t) {
  state.tab = t;
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  ['findings', 'selection', 'money', 'commitments', 'summary', 'notes'].forEach(k => { $('tab-' + k).hidden = k !== t; });
}

function row(n) {
  const r = el('div', 'row');
  r.tabIndex = 0;
  const colors = COLOR();
  const dot = el('span', 'dot'); dot.style.background = colors[n.status] || colors.unknown;
  const mid = el('div');
  mid.append(el('div', 'nm', n.name || n.id));
  mid.append(el('div', 'sub', typeLabel(n.type) + ' · ' + (n.region || '') + (n.waste_reason ? ' · ' + n.waste_reason : '')));
  r.append(dot, mid, el('div', 'amt', usdc(cost(n))));
  const go = () => { if (state.view !== 'map') setView('map'); select(n.id, true); };
  r.addEventListener('click', go);
  r.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  r.addEventListener('mouseenter', ev => showTip(tipFor(n.id), ev));
  r.addEventListener('mousemove', moveTip);
  r.addEventListener('mouseleave', hideTip);
  return r;
}

const PILLARS = [
  ['security', 'Security'], ['cost', 'Cost'], ['reliability', 'Reliability'],
  ['performance', 'Performance'], ['iac', 'IaC'], ['ops', 'Operations'],
];
const SOURCE_LABEL = {
  own: 'InfraLens', 'trusted-advisor': 'Trusted Advisor', 'cost-hub': 'Cost Optimization Hub',
  'security-hub': 'Security Hub', 'compute-optimizer': 'Compute Optimizer', prowler: 'Prowler',
};
const findings = D.findings || [];
state.pillar = state.pillar || 'all';

function findingRow(f) {
  const r = el('div', 'row');
  r.tabIndex = 0;
  const dot = el('span', 'dot');
  dot.style.background = ({ critical: '#7f1d1d', high: css('--waste'), medium: css('--shadow'), low: css('--unknown'), info: css('--line') })[f.severity] || css('--unknown');
  const mid = el('div');
  mid.append(el('div', 'nm', f.title));
  const bits = [SOURCE_LABEL[f.source] || f.source];
  if (f.affected > 1) bits.push(f.affected + ' resources');
  else if (f.resource_name) bits.push(f.resource_name);
  if (f.ack) bits.push('acknowledged');
  mid.append(el('div', 'sub', bits.join(' · ')));
  r.append(dot, mid, el('div', 'amt', f.monthly_cost ? usdc(f.monthly_cost) : ''));
  const go = () => renderFindingDetail(f);
  r.addEventListener('click', go);
  r.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  return r;
}

function renderFindingDetail(f) {
  const root = $('tab-selection');
  root.replaceChildren();
  root.append(el('div', 'nm', f.title));
  const chips = el('div');
  chips.style.margin = '6px 0';
  chips.append(el('span', 'chip ' + f.severity, f.severity), document.createTextNode(' '),
    el('span', 'chip src', (PILLARS.find(p => p[0] === f.pillar) || [0, f.pillar])[1]), document.createTextNode(' '),
    el('span', 'chip src', SOURCE_LABEL[f.source] || f.source));
  root.append(chips);
  if (f.monthly_cost) {
    const big = el('div', 'big', usd(f.monthly_cost) + ' /mo');
    big.style.margin = '6px 0 0';
    root.append(big, el('div', 'note', f.pillar === 'cost' ? 'size of the cost at stake, not a promised saving' : 'cost attached to the affected resources'));
  }
  if (f.ack) {
    const a = el('div', 'note', 'Acknowledged by the owner: ' + f.ack.note + (f.ack.until ? ' (until ' + f.ack.until + ')' : ''));
    a.style.margin = '8px 0';
    root.append(a);
  }
  if ((f.evidence || []).length) {
    root.append(el('h4', null, 'Evidence'));
    const ul = el('ul', 'ev');
    f.evidence.forEach(e => ul.append(el('li', null, e)));
    root.append(ul);
  }
  if (f.recommendation) {
    root.append(el('h4', null, 'What to do'));
    root.append(el('div', null, f.recommendation));
  }
  const res = f.resources && f.resources.length ? f.resources : (f.resource_id ? [f.resource_id] : []);
  if (res.length) {
    root.append(el('h4', null, 'Affected' + (f.affected > res.length ? ' · showing ' + res.length + ' of ' + f.affected : ' · ' + res.length)));
    res.slice(0, 40).forEach(id => {
      const d = el('div');
      if (byId.has(id)) {
        const b = el('button', 'link', byId.get(id).name || id);
        b.addEventListener('click', () => { if (state.view !== 'map') setView('map'); select(id, true); });
        d.append(b);
      } else {
        d.append(el('span', null, id));
      }
      root.append(d);
    });
  }
  const meta = el('div');
  kv(meta, 'Rule', f.rule); kv(meta, 'Reference', f.reference); kv(meta, 'Region', f.region);
  kv(meta, 'Confidence', f.confidence); kv(meta, 'Effort', f.effort); kv(meta, 'Id', f.id);
  root.append(el('h4', null, 'Details'), meta);
  setTab('selection');
}

function renderFindings() {
  const root = $('tab-findings');
  root.replaceChildren();
  if (!findings.length) { renderLegacyFindings(root); return; }

  const open = findings.filter(f => !f.ack);
  const bar = el('div');
  const mk = (key, label, n) => {
    const p = el('span', 'pill' + (state.pillar === key ? ' on' : ''), label + ' · ' + n);
    p.addEventListener('click', () => { state.pillar = key; renderFindings(); });
    bar.append(p);
  };
  mk('all', 'All', open.length);
  PILLARS.forEach(([k, label]) => {
    const n = open.filter(f => f.pillar === k).length;
    if (n) mk(k, label, n);
  });
  root.append(bar);

  const shown = findings.filter(f => state.pillar === 'all' || f.pillar === state.pillar);
  const live = shown.filter(f => !f.ack), acked = shown.filter(f => f.ack);
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  sevOrder.forEach(sev => {
    const list = live.filter(f => f.severity === sev);
    if (!list.length) return;
    root.append(el('h4', null, sev + ' · ' + list.length));
    list.forEach(f => root.append(findingRow(f)));
  });
  if (!live.length) root.append(el('div', 'note', 'Nothing open in this layer from the sources that ran.'));
  if (acked.length) {
    root.append(el('h4', null, 'Acknowledged · ' + acked.length));
    acked.forEach(f => root.append(findingRow(f)));
  }
  const n = el('div', 'note');
  n.style.marginTop = '14px';
  n.textContent = 'Findings come from this tool and from AWS services that were enabled (source shown). The same issue can appear from two sources. Verify with the owner before acting.';
  root.append(n);
}

function renderLegacyFindings(root) {
  const waste = nodes.filter(n => n.status === 'orphan_waste').sort((a, b) => cost(b) - cost(a));
  const shadow = nodes.filter(n => n.status === 'shadow_it').sort((a, b) => cost(b) - cost(a));
  const wsum = waste.reduce((s, n) => s + cost(n), 0);
  root.append(el('h4', null, 'Waste candidates · ' + waste.length + ' · ' + usd(wsum) + '/mo'));
  if (!waste.length) root.append(el('div', 'note', 'No waste candidates found by the checks that ran.'));
  waste.forEach(n => root.append(row(n)));
  root.append(el('h4', null, 'No IaC marker · ' + shadow.length));
  shadow.forEach(n => root.append(row(n)));
  const acked = nodes.filter(n => n.status === 'acked').sort((a, b) => cost(b) - cost(a));
  if (acked.length) {
    root.append(el('h4', null, 'Acknowledged · ' + acked.length));
    acked.forEach(n => {
      const r = row(n);
      r.querySelector('.sub').textContent = n.ack.note + (n.ack.until ? ' · until ' + n.ack.until : '');
      root.append(r);
    });
  }
}

function renderMoney() {
  const root = $('tab-money');
  root.replaceChildren();
  if (!hasLedger) {
    root.append(el('div', 'note', 'This scan has no cost ledger (cost allocation was off or Cost Explorer was not reachable). Figures are catalogue estimates.'));
    return;
  }
  const L = D.ledger;
  const pct = L.billed ? Math.round(L.allocated / L.billed * 100) : 0;
  const head = el('div');
  head.append(el('div', 'big', usd(L.allocated) + ' of ' + usd(L.billed)));
  head.append(el('div', 'note', 'of ' + (L.month || 'last month') + '\'s bill was tied to resources (' + pct + '%). It is real money, split by measured usage (hours, GB, requests). The rest could not be tied to a resource and is listed below.'));
  root.append(head);
  const bar = el('div', 'bar'); const i = el('i'); i.style.width = pct + '%'; bar.append(i);
  root.append(bar);

  root.append(el('h4', null, 'By service'));
  const t = el('table', 'led');
  const hr = t.insertRow();
  ['Service', 'Billed', 'Tied', 'Not tied'].forEach(h => { const c = document.createElement('th'); c.textContent = h; hr.append(c); });
  L.services.slice(0, 18).forEach(s => {
    const r = t.insertRow();
    r.insertCell().textContent = s.service.replace(/^Amazon |^AWS /, '');
    r.insertCell().textContent = usdc(s.billed);
    r.insertCell().textContent = usdc(s.allocated);
    const rest = s.billed - s.allocated;
    const c = r.insertCell(); c.textContent = rest >= 1 ? usdc(rest) : '–';
    if (rest > 0.4 * s.billed && rest > 100) c.style.color = 'var(--shadow)';
  });
  root.append(t);

  root.append(el('h4', null, 'Largest usage not tied to a resource'));
  const lines = [];
  L.services.forEach(s => (s.unallocated || []).forEach(u => lines.push({ svc: s.service, ...u })));
  lines.sort((a, b) => b.cost - a.cost).slice(0, 14).forEach(u => {
    const r = el('div', 'row'); r.style.cursor = 'default'; r.style.gridTemplateColumns = 'minmax(0,1fr) auto';
    const m = el('div');
    m.append(el('div', 'nm', u.usage), el('div', 'sub', u.svc.replace(/^Amazon |^AWS /, '') + (u.region ? ' · ' + u.region : '') + ' · ' + u.reason));
    r.append(m, el('div', 'amt', usdc(u.cost)));
    root.append(r);
  });
  root.append(el('div', 'note',
    'Where the second figure is large, the service is priced by usage or requests the account does not break down per resource (data transfer, S3 requests, metric streams, Aurora I/O). Only the payer account can enable per-resource cost data.'));
}

function kv(parent, k, v) {
  if (v === undefined || v === null || v === '') return;
  const dl = parent.querySelector('dl') || parent.appendChild(el('dl', 'kv'));
  dl.append(el('dt', null, k), el('dd', null, String(v)));
}

function neighborLinks(id, parent) {
  const rel = [];
  edges.forEach(e => {
    if (e.source === id && byId.has(e.target)) rel.push([e.label || 'to', byId.get(e.target)]);
    if (e.target === id && byId.has(e.source)) rel.push([e.label ? e.label + ' (in)' : 'from', byId.get(e.source)]);
  });
  if (!rel.length) return;
  parent.append(el('h4', null, 'Connections · ' + rel.length));
  rel.slice(0, 30).forEach(([label, n]) => {
    const b = el('button', 'link', n.name || n.id);
    b.addEventListener('click', () => select(n.id, true));
    const d = el('div');
    d.append(b, el('span', 'note', '  ' + label + ' · ' + usdc(cost(n))));
    parent.append(d);
  });
  if (rel.length > 30) parent.append(el('div', 'note', '… and ' + (rel.length - 30) + ' more'));
}

// iacCheckState says what was actually compared, so "not found" is never read
// as "created by hand" when nothing was compared at all.
function iacCheckState(n) {
  const I = D.iac;
  if (n.iac) {
    const drift = n.iac.drift_checked
      ? (n.iac.drift && n.iac.drift.length ? ' Live attributes differ from state (see below).' : ' Compared attributes match state.')
      : ' Attribute comparison is not available for this type.';
    return { kind: 'confirmed', text: 'Confirmed in code: found in ' + (n.iac.source || 'state') + '.' + drift };
  }
  if (!I || !(I.sources || []).length) {
    return { kind: 'none', text: 'Not checked: no Terraform state or CloudFormation stack was provided to this scan. A missing marker is not evidence of how this resource was created.' };
  }
  if (!(I.supported_types || []).includes(n.type)) {
    return { kind: 'unsupported', text: 'Cannot be compared: this resource type is not matched against state or stacks by this tool. No conclusion about how it was created.' };
  }
  const read = (I.sources || []).length + ' source(s) read';
  if (n.managed_by) return { kind: 'tag-only', text: 'Claimed by tag (' + n.managed_by + ') but not found in what was read (' + read + '). The state may be elsewhere, or the tag may be stale.' };
  return { kind: 'not-found', text: 'Checked (' + read + ') and not found, and it carries no IaC tag. It may be created by hand, or its state was not provided.' };
}

function renderSelection(id) {
  const root = $('tab-selection');
  root.replaceChildren();
  const n = byId.get(id);
  const grp = groups.get(id);
  if (n) {
    const gs = grp ? groupStats(grp) : null;
    root.append(el('div', 'nm', n.name || n.id));
    const chip = el('span', 'chip ' + (gs ? gs.status : n.status), gs ? (gs.waste || gs.shadow ? 'contains findings' : 'all clear') : statusText(n));
    root.append(chip);
    const big = el('div', 'big', usd(gs ? gs.cost : cost(n)) + ' /mo');
    big.style.margin = '8px 0 0';
    root.append(big, el('div', 'note', gs ? 'sum of ' + grp.members.length + ' ' + (TYPE_PLURAL[grp.members[0].type] || 'resources') + ' · ' + basisNote(n) : basisNote(n)));
    if (gs) {
      const b = el('button', null, state.expanded.has(grp.id) ? 'Collapse' : 'Expand');
      b.style.margin = '10px 0';
      b.addEventListener('click', () => toggleGroup(grp.id));
      root.append(b);
      root.append(el('h4', null, 'Most expensive inside'));
      grp.members.slice().sort((a, b) => cost(b) - cost(a)).slice(0, 8).forEach(m => root.append(row(m)));
    }
    if (n.ack) { const a = el('div', 'note', 'Acknowledged by the owner: ' + n.ack.note + (n.ack.until ? ' (until ' + n.ack.until + ')' : '')); a.style.margin = '8px 0'; root.append(a); }
    if (n.waste_reason) { const w = el('div', 'warn', n.waste_reason); w.style.margin = '8px 0'; root.append(w); }
    if ((n.evidence || []).length) {
      root.append(el('h4', null, 'Evidence'));
      const ul = el('ul', 'ev');
      n.evidence.forEach(e => ul.append(el('li', null, e)));
      root.append(ul);
    }
    root.append(el('h4', null, 'Details'));
    const d = el('div');
    kv(d, 'Type', typeLabel(n.type));
    kv(d, 'Region', n.region);
    kv(d, 'Managed by', n.managed_by || 'no IaC marker');
    kv(d, 'Owner', n.owner ? n.owner + ' (' + n.owner_source + ')' : 'none found');
    kv(d, 'VPC', n.vpc_id); kv(d, 'Subnet', n.subnet_id);
    kv(d, 'ID', n.id);
    Object.entries(n.attrs || {}).forEach(([k, v]) => kv(d, k, v));
    root.append(d);
    if (!grp) {
      root.append(el('h4', null, 'Infrastructure as code — what was checked'));
      const st = iacCheckState(n);
      const box = el('div', st.kind === 'confirmed' ? 'note' : 'warn', st.text);
      box.style.margin = '4px 0 8px';
      root.append(box);
    }
    if (n.iac) {
      const c = el('div');
      kv(c, 'Source', n.iac.source);
      kv(c, 'Origin', n.iac.origin);
      kv(c, 'Address', n.iac.address);
      kv(c, 'Module', n.iac.module);
      kv(c, 'Drift check', n.iac.drift_checked ? (n.iac.drift && n.iac.drift.length ? 'differs from state' : 'matches state') : 'not available for this type');
      root.append(c);
      (n.iac.drift || []).forEach(x => {
        const r = el('div', 'warn', x.attr + ': state ' + x.state + ' → live ' + x.live);
        r.style.marginTop = '3px';
        root.append(r);
      });
    }
    if (!grp && window.parent !== window && location.protocol.startsWith('http')) {
      root.append(el('h4', null, 'Ask AI about this resource'));
      const q = el('input'); q.type = 'text'; q.placeholder = 'optional question; empty = explain this resource';
      q.style.width = '100%';
      const b = el('button', null, 'Ask');
      b.style.margin = '6px 0';
      const out = el('div', 'note');
      const nonce = String(Math.random()).slice(2);
      b.addEventListener('click', () => {
        out.textContent = 'asking…';
        const onMsg = ev => {
          const m = ev.data;
          if (ev.source !== window.parent || ev.origin !== location.origin || !m || m.t !== 'infralens-answer' || m.nonce !== nonce) return;
          window.removeEventListener('message', onMsg);
          out.replaceChildren();
          if (m.error) { out.textContent = m.error; return; }
          out.append(el('div', null, m.answer || ''));
          const meta = [m.model, m.based_on + ' finding(s) given as facts', m.removed ? m.removed + ' statement(s) removed by validation' : ''].filter(Boolean).join(' · ');
          out.append(el('div', 'm', 'Written by ' + meta + '. It cannot know your plans.'));
          (m.findings || []).forEach(t => out.append(el('div', 'm', '• ' + t)));
        };
        window.addEventListener('message', onMsg);
        window.parent.postMessage({ t: 'infralens-ask', node: id, q: q.value, nonce }, location.origin);
      });
      root.append(q, b, out);
    }
    if (!grp) {
      root.append(el('h4', null, 'How this figure is obtained'));
      const c = el('div');
      kv(c, 'Shown', usd(cost(n)) + ' /mo');
      kv(c, 'Basis', ({ allocated: 'allocated from the bill', estimated: 'catalogue estimate', 'n/a': 'no price available' })[n.cost_basis] || (n.cost_source === 'n/a' ? 'no price available' : 'catalogue estimate'));
      if (hasLedger && D.ledger.month) kv(c, 'Billing period', D.ledger.month);
      if (n.list_cost) kv(c, 'Catalogue price', usd(n.list_cost) + ' /mo');
      Object.entries(n.drivers || {}).forEach(([k, v]) => kv(c, 'Measured: ' + k, Number(v).toLocaleString('en-US', { maximumFractionDigits: 1 })));
      root.append(c);
      if (n.cost_note) root.append(el('div', 'note', n.cost_note));
      if (n.cost_basis !== 'allocated') root.append(el('div', 'note', 'An estimate, not money from the invoice. Reservations and Savings Plans bought elsewhere are not visible from this account.'));
    }
    const tags = Object.entries(n.tags || {});
    if (tags.length) {
      root.append(el('h4', null, 'Tags'));
      const t = el('div');
      tags.forEach(([k, v]) => kv(t, k, v));
      root.append(t);
    }
    neighborLinks(id, root);
    return;
  }
  const g = groups.get(id);
  if (g) {
    const s = groupStats(g);
    root.append(el('div', 'nm', g.label));
    root.append(el('span', 'chip ' + s.status, s.waste || s.shadow ? 'contains findings' : 'all clear'));
    const big = el('div', 'big', usd(s.cost) + ' /mo');
    big.style.margin = '8px 0 0';
    root.append(big);
    root.append(el('div', 'note', g.members.length + ' resources' + (s.waste ? ' · ' + s.waste + ' waste' : '') + (s.shadow ? ' · ' + s.shadow + ' no IaC' : '')));
    const b = el('button', null, state.expanded.has(g.id) ? 'Collapse' : 'Expand');
    b.style.margin = '10px 0';
    b.addEventListener('click', () => toggleGroup(g.id));
    root.append(b);
    root.append(el('h4', null, 'Most expensive'));
    g.members.slice().sort((a, b) => cost(b) - cost(a)).slice(0, 15).forEach(m => root.append(row(m)));
  }
}

function renderSummary() {
  const root = $('tab-summary');
  root.replaceChildren();
  if (D.iac) {
    const I = D.iac;
    root.append(el('h4', null, 'Infrastructure as code'));
    const lines = [];
    if (!I.sources || !I.sources.length) {
      lines.push('No state or stack was read, so IaC coverage is unverified; only tags are used.');
    } else {
      lines.push('Read: ' + I.sources.join('; '));
      lines.push(I.state_files + ' state file(s), ' + I.stacks + ' stack(s), ' + I.instances + ' resources claimed.');
      lines.push('Of ' + I.considered + ' inventoried resources that state can describe: ' + I.matched + ' confirmed in code, ' +
        I.tag_only + ' tagged but not found, ' + I.unmanaged + ' with neither.');
      if (I.drift_checked) lines.push('Drift compared for ' + I.drift_checked + ' resources (' + (I.drift_types || []).map(t => t.replace('aws_', '')).join(', ') + '): ' + I.drift_found + ' differ.');
      if (I.not_in_aws) lines.push(I.not_in_aws + ' state entries have no live resource in the scanned regions.');
      if (I.duplicates) lines.push(I.duplicates + ' resources are in more than one state or stack.');
    }
    (I.notes || []).forEach(x => lines.push('note: ' + x));
    root.append(el('pre', 'txt', lines.join('\n')));
  }
  if (D.diff) {
    const d = D.diff;
    root.append(el('h4', null, 'Since ' + new Date(d.baseline).toLocaleString()));
    const lines = [];
    const add = (t, cs, f) => { if (cs && cs.length) { lines.push(t + ' (' + cs.length + ')'); cs.slice(0, 20).forEach(c => lines.push('  ' + f(c))); if (cs.length > 20) lines.push('  … ' + (cs.length - 20) + ' more'); } };
    add('new', d.added, c => '+ ' + usd(c.cost_to) + '  ' + typeLabel(c.type) + '  ' + c.name);
    add('gone', d.removed, c => '- ' + usd(c.cost_from) + '  ' + typeLabel(c.type) + '  ' + c.name);
    add('changed', d.changed, c => c.kind === 'status' ? '~ ' + c.name + ': ' + c.from + ' → ' + c.to : '~ ' + c.name + ': ' + usd(c.cost_from) + ' → ' + usd(c.cost_to));
    if (!lines.length) lines.push('no material changes');
    lines.push('');
    lines.push('cost delta ' + usd(d.delta_cost) + '/mo · waste delta ' + usd(d.delta_waste) + '/mo · new waste ' + usd(d.new_waste_cost) + '/mo');
    (d.notes || []).forEach(x => lines.push('note: ' + x));
    root.append(el('pre', 'txt', lines.join('\n')));
  }
  root.append(el('h4', null, 'Summary'));
  root.append(el('pre', 'txt', D.summary || ''));
  if (D.ai_analysis) {
    root.append(el('h4', null, 'AI audit'));
    root.append(el('pre', 'txt', D.ai_analysis));
  }
}

function renderCommitments() {
  const root = $('tab-commitments');
  root.replaceChildren();
  const cs = D.commitments || [];
  const intro = el('div', 'note',
    'Facts first. Suggestions depend on plans this tool cannot know (a migration, a resize, a shutdown). ' +
    'Tell it with --context and a finding becomes an acknowledged note instead of a prompt.');
  intro.style.marginBottom = '10px';
  root.append(intro);
  if (!cs.length) {
    root.append(el('div', 'note', 'No reservation or coverage data was collected (the reservations and coverage checks did not run, or the account has none).'));
    return;
  }
  const fmt = d => (d ? new Date(d).toISOString().slice(0, 10) : '');
  const order = { coverage: 0, reservation: 1, savings_plan: 2 };
  const byService = new Map();
  cs.forEach(c => { if (!byService.has(c.service)) byService.set(c.service, []); byService.get(c.service).push(c); });
  [...byService.keys()].sort().forEach(svc => {
    root.append(el('h4', null, svc));
    byService.get(svc).slice().sort((a, b) => (order[a.kind] - order[b.kind]) || String(a.end).localeCompare(String(b.end))).forEach(c => {
      const card = el('div', 'row'); card.style.cursor = 'default'; card.style.gridTemplateColumns = 'minmax(0,1fr)';
      const body = el('div');
      const head = el('div', 'nm', c.kind === 'coverage' ? 'Coverage' : (c.kind === 'savings_plan' ? 'Savings plan ' : 'Reservation ') + (c.kind === 'coverage' ? '' : '· ' + c.detail));
      head.style.whiteSpace = 'normal';
      body.append(head);
      const sub = [];
      if (c.kind === 'coverage') sub.push(c.detail);
      if (c.state) sub.push(c.state);
      if (c.region) sub.push(c.region);
      if (c.end) sub.push('ends ' + fmt(c.end));
      if (sub.length) { const s = el('div', 'sub', sub.join(' · ')); s.style.whiteSpace = 'normal'; body.append(s); }
      (c.facts || []).forEach(f => { const d = el('div', 'note', '• ' + f); d.style.marginTop = '3px'; body.append(d); });
      if (c.ack) {
        const a = el('div', 'note', 'Acknowledged: ' + c.ack.note + (c.ack.until ? ' (until ' + c.ack.until + ')' : ''));
        a.style.marginTop = '4px'; a.style.color = 'var(--accent)'; body.append(a);
      } else {
        (c.suggestions || []).forEach(s => {
          const d = el('div', 'note', 'Depends on your plans: ' + s);
          d.style.marginTop = '5px'; d.style.fontStyle = 'italic'; body.append(d);
        });
      }
      card.append(body);
      root.append(card);
    });
  });
}

function renderNotes() {
  const root = $('tab-notes');
  root.replaceChildren();
  const w = D.warnings || [];
  root.append(el('h4', null, 'Warnings · ' + w.length));
  if (!w.length) root.append(el('div', 'note', 'All checks ran without errors.'));
  w.forEach(x => root.append(el('div', 'warn', x)));
  const skipped = D.skipped || [];
  if (skipped.length) {
    root.append(el('h4', null, 'Not applicable · ' + skipped.length));
    skipped.forEach(x => root.append(el('div', 'note', x)));
  }
  const unscanned = (D.service_costs || []).filter(s => !s.scanned && s.previous_month_cost >= 50);
  if (unscanned.length) {
    root.append(el('h4', null, 'Billed but not scanned'));
    unscanned.slice(0, 20).forEach(s => {
      const r = el('div', 'row'); r.style.cursor = 'default';
      r.append(el('span'), el('div', 'nm', s.service), el('div', 'amt', usdc(s.previous_month_cost)));
      root.append(r);
    });
  }
  root.append(el('h4', null, 'About the numbers'));
  root.append(el('div', 'note',
    'List price is an estimate from instance sizes, storage and traffic. It does not include Savings Plans or reservations, ' +
    'which live in the payer account. "By bill" scales each service\'s estimates to last full month\'s Cost Explorer usage; ' +
    'it spreads the bill over resources, it is not a measurement per resource.'));
}

// ---------- KPIs, legend ----------
function renderChrome() {
  const total = nodes.reduce((s, n) => s + cost(n), 0);
  const waste = nodes.filter(n => n.status === 'orphan_waste');
  const wsum = waste.reduce((s, n) => s + cost(n), 0);
  const shadow = nodes.filter(n => n.status === 'shadow_it').length;
  const sc = D.service_costs || [];
  const billed = sc.reduce((s, x) => s + x.previous_month_cost, 0);
  const scanned = sc.filter(x => x.scanned).reduce((s, x) => s + x.previous_month_cost, 0);
  const explained = sc.filter(x => x.scanned).reduce((s, x) => s + Math.min(x.estimated || 0, x.previous_month_cost), 0);

  const k = $('kpis');
  k.replaceChildren();
  const add = (v, l, cls) => { const d = el('div', 'kpi ' + (cls || '')); d.append(el('b', null, v), el('small', null, l)); k.append(d); };
  add(String(nodes.length), 'resources');
  add(usdc(total), hasLedger ? (state.basis === 'list' ? 'cost /mo (catalogue price)' : 'cost /mo (from the bill)') : (state.basis === 'list' ? 'est. cost /mo (list price)' : 'cost /mo (by bill)'));
  const ackedN = nodes.filter(n => n.status === 'acked').length;
  add(usdc(wsum), waste.length + ' waste candidates' + (ackedN ? ' · ' + ackedN + ' acknowledged' : ''), 'waste');
  add(String(shadow), 'no IaC marker', 'shadow');
  if (hasLedger && D.ledger.billed > 0) {
    add(Math.round(D.ledger.allocated / D.ledger.billed * 100) + '%',
      'of the ' + usdc(D.ledger.billed) + ' bill tied to resources (' + Math.round(scanned / billed * 100) + '% has a check)');
  } else if (billed > 0) {
    add(Math.round(scanned / billed * 100) + '% · ' + Math.round(explained / billed * 100) + '%',
      'has a check · estimates explain (of ' + usdc(billed) + ' billed)');
  }

  const meta = [D.account || D.profile, (D.regions || []).length + ' regions', new Date(D.timestamp).toLocaleString()];
  $('meta').textContent = meta.filter(Boolean).join(' · ');

  const c = COLOR();
  const lg = $('legend');
  lg.replaceChildren();
  const item = (color, text, cls) => { const d = el('div'); const i = el('i', cls); if (color) i.style.background = color; d.append(i, document.createTextNode(text)); lg.append(d); };
  item(c.orphan_waste, 'waste candidate');
  item(c.shadow_it, 'no IaC marker');
  item(c.managed, 'managed');
  item(c.unknown, 'unclassified / cost unknown');
  if (D.diff && (D.diff.added || []).length) item(null, 'new since last scan', 'ring');
  const note = el('div'); note.textContent = 'size = monthly cost · double-click a group to expand'; lg.append(note);
}

// ---------- cost map (treemap) ----------
function squarify(items, x, y, w, h) {
  const out = [];
  const total = items.reduce((s, i) => s + i.v, 0);
  if (!total || w <= 0 || h <= 0) return out;
  const scale = (w * h) / total;
  let rest = items.slice().sort((a, b) => b.v - a.v).map(i => ({ ...i, a: i.v * scale }));
  let rx = x, ry = y, rw = w, rh = h;
  const worst = (row, side) => {
    const s = row.reduce((t, i) => t + i.a, 0);
    const mx = Math.max(...row.map(i => i.a)), mn = Math.min(...row.map(i => i.a));
    return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
  };
  while (rest.length) {
    const side = Math.min(rw, rh);
    const row = [rest[0]];
    let i = 1;
    while (i < rest.length && worst(row.concat(rest[i]), side) <= worst(row, side)) { row.push(rest[i]); i++; }
    rest = rest.slice(row.length);
    const s = row.reduce((t, r) => t + r.a, 0);
    if (rw >= rh) {
      const cw = s / rh; let cyy = ry;
      row.forEach(r => { const hh = r.a / cw; out.push({ ...r, x: rx, y: cyy, w: cw, h: hh }); cyy += hh; });
      rx += cw; rw -= cw;
    } else {
      const ch = s / rw; let cxx = rx;
      row.forEach(r => { const ww = r.a / ch; out.push({ ...r, x: cxx, y: ry, w: ww, h: ch }); cxx += ww; });
      ry += ch; rh -= ch;
    }
  }
  return out;
}

function renderTreemap() {
  const svg = $('tm');
  const W = svg.clientWidth || 1000, H = svg.clientHeight || 600;
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  svg.replaceChildren();
  const NS = 'http://www.w3.org/2000/svg';
  const mk = (tag, attrs) => { const e = document.createElementNS(NS, tag); Object.entries(attrs || {}).forEach(([k, v]) => e.setAttribute(k, v)); return e; };
  const colors = COLOR();

  // level 1: containers (+ "not scanned"), level 2: group/bucket or single, level 3: resources
  const cont = new Map();
  nodes.forEach(n => {
    const c = cost(n);
    if (c <= 0 || (filtering() && !nodeMatches(n))) return;
    const ck = containerOf(n);
    if (!cont.has(ck)) cont.set(ck, new Map());
    const gk = groupOf.get(n.id) || n.id;
    const m = cont.get(ck);
    if (!m.has(gk)) m.set(gk, []);
    m.get(gk).push(n);
  });
  const top = [];
  cont.forEach((gm, ck) => {
    let v = 0; gm.forEach(l => l.forEach(n => { v += cost(n); }));
    top.push({ key: ck, v, kids: gm, label: ck === NOVPC ? 'Outside any VPC' : ck });
  });
  const unscanned = (D.service_costs || []).filter(s => !s.scanned && s.previous_month_cost >= 50);
  const uv = unscanned.reduce((s, x) => s + x.previous_month_cost, 0);
  if (uv > 0 && !filtering()) top.push({ key: '__un', v: uv, label: 'Billed but not scanned', unscanned });

  const hdr = 20;
  squarify(top, 4, 4, W - 8, H - 8).forEach(t => {
    const gC = mk('g');
    gC.append(mk('rect', { x: t.x, y: t.y, width: Math.max(t.w - 2, 0), height: Math.max(t.h - 2, 0), fill: css('--panel'), stroke: css('--line'), rx: 4 }));
    if (t.w > 90 && t.h > 30) { const tx = mk('text', { x: t.x + 6, y: t.y + 14, class: 'hd' }); tx.textContent = t.label + ' · ' + usdc(t.v); gC.append(tx); }
    svg.append(gC);
    const ix = t.x + 3, iy = t.y + hdr, iw = t.w - 8, ih = t.h - hdr - 5;
    if (iw <= 4 || ih <= 4) return;

    if (t.unscanned) {
      squarify(t.unscanned.map(s => ({ v: s.previous_month_cost, s })), ix, iy, iw, ih).forEach(l => {
        const r = mk('rect', { class: 'leaf', x: l.x, y: l.y, width: Math.max(l.w - 1, 0), height: Math.max(l.h - 1, 0), fill: css('--unknown'), opacity: 0.45 });
        r.addEventListener('mouseenter', ev => {
          const b = el('div'); b.append(el('div', 't', l.s.service), el('div', 'p', usd(l.s.previous_month_cost) + ' last month'), el('div', 'm', 'billed usage, no scanner yet'));
          showTip(b, ev);
        });
        r.addEventListener('mousemove', moveTip); r.addEventListener('mouseleave', hideTip);
        svg.append(r);
        if (l.w > 70 && l.h > 24) { const tx = mk('text', { x: l.x + 5, y: l.y + 14 }); tx.textContent = l.s.service.replace(/^Amazon |^AWS /, ''); svg.append(tx); }
      });
      return;
    }

    const kids = [];
    t.kids.forEach((list, gk) => {
      const v = list.reduce((s, n) => s + cost(n), 0);
      kids.push({ gk, list, v });
    });
    squarify(kids, ix, iy, iw, ih).forEach(g => {
      const grp = groups.get(g.gk);
      let leafArea = { x: g.x, y: g.y, w: g.w, h: g.h };
      if (grp && g.w > 70 && g.h > 34) {
        const tx = mk('text', { x: g.x + 4, y: g.y + 12, class: 'hd' });
        tx.textContent = grp.label + ' · ' + usdc(g.v);
        svg.append(tx);
        leafArea = { x: g.x, y: g.y + 16, w: g.w, h: g.h - 16 };
      }
      squarify(g.list.map(n => ({ v: cost(n), n })), leafArea.x, leafArea.y, leafArea.w, leafArea.h).forEach(l => {
        const r = mk('rect', { class: 'leaf', x: l.x, y: l.y, width: Math.max(l.w - 1, 0), height: Math.max(l.h - 1, 0), fill: colors[l.n.status] || colors.unknown });
        r.addEventListener('mouseenter', ev => showTip(tipFor(l.n.id), ev));
        r.addEventListener('mousemove', moveTip);
        r.addEventListener('mouseleave', hideTip);
        r.addEventListener('click', () => { hideTip(); setView('map'); select(l.n.id, true); });
        svg.append(r);
        if (l.w > 64 && l.h > 22) {
          const tx = mk('text', { x: l.x + 5, y: l.y + 14 });
          const name = l.n.name || l.n.id;
          tx.textContent = name.length > Math.floor(l.w / 6.5) ? name.slice(0, Math.max(3, Math.floor(l.w / 6.5) - 1)) + '…' : name;
          svg.append(tx);
        }
      });
    });
  });
  if (!top.length) {
    const tx = mk('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle' });
    tx.style.fill = css('--muted');
    tx.textContent = 'nothing with a cost estimate matches the current filter';
    svg.append(tx);
  }
}

// ---------- wiring ----------
function setView(v) {
  state.view = v;
  saveHash();
  document.querySelectorAll('#views button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
  $('cy').style.display = v === 'map' ? '' : 'none';
  $('tm').style.display = v === 'costs' ? '' : 'none';
  $('legend').style.display = v === 'map' ? '' : 'none';
  ['expandAll', 'collapseAll', 'fit'].forEach(i => { $(i).style.display = v === 'map' ? '' : 'none'; });
  if (v === 'costs') renderTreemap(); else { cy.resize(); applyFilter(); }
  scrollbarsUpdate();
}

function refreshAll(opts) {
  hideTip();
  renderChrome();
  renderFindings();
  renderSummary();
  if (state.view === 'costs') renderTreemap();
  else {
    if (expandForMatches()) render(opts); else { render(opts); }
  }
  if (state.selected) renderSelection(state.selected);
}

function init() {
  if (window.parent !== window) document.documentElement.classList.add('framed');
  const sel = $('region');
  sel.append(new Option('all regions', ''));
  regions.forEach(r => sel.append(new Option(r, r)));
  if (regions.length < 2) sel.style.display = 'none';

  initCy();
  renderNotes();
  renderCommitments();
  renderMoney();
  if (hasLedger) {
    const lb = { list: ['catalogue price', 'An estimate from instance sizes, storage and observed usage at list prices.'],
      billed: ['from the bill', 'Real money from last full month\'s Cost Explorer usage, split between resources by measured usage. Resources with no attributable usage keep the catalogue estimate.'] };
    document.querySelectorAll('#basis button').forEach(x => { x.textContent = lb[x.dataset.b][0]; x.title = lb[x.dataset.b][1]; });
  }
  document.querySelectorAll('#basis button').forEach(b => b.classList.toggle('on', b.dataset.b === state.basis));

  const driftBtn = document.querySelector('#status [data-f=drift]');
  if (driftBtn && !(D.iac && D.iac.drift_checked)) {
    driftBtn.disabled = true;
    driftBtn.title = 'No drift comparison was made: scan with --tfstate (or read CloudFormation stacks) to enable it';
  }
  document.querySelectorAll('#views button').forEach(b => b.addEventListener('click', () => setView(b.dataset.view)));
  document.querySelectorAll('#tabs button').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
  document.querySelectorAll('#status button').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#status button').forEach(x => x.classList.toggle('on', x === b));
    state.status = b.dataset.f;
    refreshAll();
  }));
  document.querySelectorAll('#basis button').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('#basis button').forEach(x => x.classList.toggle('on', x === b));
    state.basis = b.dataset.b;
    refreshAll({ fit: true });
  }));
  sel.addEventListener('change', () => { state.region = sel.value; refreshAll(); });
  let t = null;
  $('search').addEventListener('input', e => {
    clearTimeout(t);
    t = setTimeout(() => { state.q = e.target.value.trim().toLowerCase(); refreshAll(); }, 180);
  });
  $('expandAll').addEventListener('click', () => {
    const big = nodes.length > 400;
    if (big && !confirm('Expanding every group draws all ' + nodes.length + ' resources and can be slow. Continue?')) return;
    groups.forEach(g => state.expanded.add(g.id));
    render({ fit: true });
  });
  $('collapseAll').addEventListener('click', () => { state.expanded.clear(); render({ fit: true }); });
  $('fit').addEventListener('click', () => cy.fit(undefined, 50));
  $('dlaudit').addEventListener('click', () => {
    let doc = '';
    try { doc = JSON.parse($('auditdoc').textContent); } catch (e) { /* none */ }
    if (!doc) { alert('This page carries no audit document.'); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([doc], { type: 'text/html' }));
    a.download = 'audit.html';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  document.addEventListener('keydown', e => {
    if (e.key === '/' && document.activeElement !== $('search')) { e.preventDefault(); $('search').focus(); }
    if (e.key === 'Escape') { $('search').blur(); clearSelection(); }
  });
  window.addEventListener('resize', () => { if (state.view === 'costs') renderTreemap(); else cy.resize(); });

  // reflect restored state in the controls
  document.querySelectorAll('#status button').forEach(b => b.classList.toggle('on', b.dataset.f === state.status));
  if (state.region) sel.value = state.region;
  if (state.q) $('search').value = state.q;

  setView(hashState.view === 'costs' ? 'costs' : 'map');
  refreshAll({ fit: true });
  if (typeof hashState.select === 'string' && (byId.has(hashState.select) || groups.has(hashState.select))) {
    select(hashState.select, true);
  }
  if (typeof hashState.tip === 'string') {
    // deterministic hover for screenshots/docs: show the tooltip of that node
    const e = cy.getElementById(hashState.tip);
    if (e.length && state.view === 'map') {
      const p = e.renderedPosition(), r = $('cy').getBoundingClientRect();
      showTip(tipFor(hashState.tip), { clientX: r.left + p.x, clientY: r.top + p.y });
    }
  }
  if (['findings', 'selection', 'money', 'commitments', 'summary', 'notes'].includes(hashState.tab)) setTab(hashState.tab);
  document.body.dataset.ready = '1';
}

init();
})();
