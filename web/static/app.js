'use strict';

const POLL_MS = 30000;
const SVG_NS = 'http://www.w3.org/2000/svg';

const TYPES = {
  trail:    { label: 'CloudTrail trail',   abbr: 'CT',  color: 'var(--svc-trail)' },
  detector: { label: 'GuardDuty detector', abbr: 'GD',  color: 'var(--svc-detector)' },
  rule:     { label: 'EventBridge rule',   abbr: 'EB',  color: 'var(--svc-rule)' },
  bucket:   { label: 'S3 bucket',          abbr: 'S3',  color: 'var(--svc-bucket)' },
  topic:    { label: 'SNS topic',          abbr: 'SNS', color: 'var(--svc-topic)' },
  queue:    { label: 'SQS queue',          abbr: 'SQS', color: 'var(--svc-queue)' },
  function: { label: 'Lambda function',    abbr: 'λ',   color: 'var(--svc-function)' },
  role:     { label: 'IAM role',           abbr: 'IAM', color: 'var(--svc-role)' },
  external: { label: 'External resource',  abbr: '?',   color: 'var(--svc-external)' },
};
const TYPE_ORDER = ['trail', 'detector', 'rule', 'bucket', 'topic', 'queue', 'function', 'role', 'external'];

const COLUMNS = [
  { title: 'Sources',     sub: 'CloudTrail · GuardDuty · EventBridge' },
  { title: 'Log storage', sub: 'S3 buckets' },
  { title: 'Fan-out',     sub: 'SNS topics · SQS queues' },
  { title: 'Processing',  sub: 'Lambda functions' },
  { title: 'Identity',    sub: 'IAM roles' },
];

const SEVERITIES = [
  { key: 'critical', label: 'Critical' },
  { key: 'high',     label: 'High' },
  { key: 'medium',   label: 'Medium' },
  { key: 'error',    label: 'Tool errors' },
];

// Diagram geometry
const PAD = 20, HEADER_H = 64, ROW_H = 58, COL_W = 300, NODE_W = 232, ICON = 34;

const state = {
  status: null,
  graph: null,
  alerts: [],
  seenAlertIds: null,
  selectedId: null,
  account: store('account'),
  region: store('region') || '',
  connectedOnly: store('connectedOnly') === '1',
  versions: [],
  version: null,  // null follows the live state; otherwise a pinned history version id
  showDiff: store('showDiff') !== '0',
  severities: new Set(SEVERITIES.map(s => s.key)),
  resourceFilter: null,
  expandedAlerts: new Set(),
  alertLimit: 300,
};

const $ = id => document.getElementById(id);

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(`asg.${key}`);
    localStorage.setItem(`asg.${key}`, value);
  } catch { /* storage unavailable */ }
  return null;
}

function el(tag, attrs = {}, ...children) {
  const node = tag.startsWith('svg:')
    ? document.createElementNS(SVG_NS, tag.slice(4))
    : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.setAttribute('class', v);
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) node.append(c);
  return node;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: 'no-store' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

// ---------- Formatting ----------

function ago(epochSeconds) {
  if (!epochSeconds) return 'never';
  const s = Math.max(0, Date.now() / 1000 - epochSeconds);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function bytes(n) {
  if (n == null) return null;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function short(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) return v.length ? v.join(', ') : 'None';
  if (typeof v === 'object') {
    const parts = Object.entries(v).filter(([, x]) => x !== '' && x != null).map(([k, x]) => `${k}: ${typeof x === 'object' ? JSON.stringify(x) : x}`);
    return parts.length ? parts.join(', ') : 'None';
  }
  return String(v);
}

function nameFromArn(arn) {
  return String(arn || '').split(/[:/]/).pop();
}

/** Key facts shown in the hover tooltip and the detail panel. */
function summarize(node) {
  const d = node.details || {};
  const rows = [];
  const add = (k, v) => { const s = short(v); if (s != null) rows.push([k, s]); };

  if (node.external) {
    add('ARN', node.id);
    add('Note', 'Referenced by a monitored resource but not tracked by the monitor');
    return rows;
  }
  if (d.accessible === false) add('Access', d.error || 'Not accessible');

  switch (node.type) {
    case 'trail':
      add('Logging', d.is_logging === false ? 'STOPPED' : d.is_logging);
      add('Home region', d.home_region);
      add('Multi-region', d.is_multi_region);
      add('Global events', d.include_global_events);
      add('S3 bucket', d.s3_bucket);
      add('Key prefix', d.s3_key_prefix);
      add('Selectors', `${(d.event_selectors || []).length} basic, ${(d.advanced_event_selectors || []).length} advanced`);
      break;
    case 'detector': {
      const sources = Object.entries(d.data_sources || {})
        .filter(([, v]) => JSON.stringify(v).includes('ENABLED')).map(([k]) => k);
      add('Status', d.status);
      add('Detector ID', d.detector_id);
      add('Publishing', d.finding_publishing_frequency);
      add('Destinations', (d.publishing_destinations || []).length);
      add('Suppression rules', Object.keys(d.suppression_rules || {}).length);
      add('Data sources on', sources);
      break;
    }
    case 'rule':
      add('State', d.state);
      add('Schedule', d.schedule_expression);
      add('Event pattern', d.event_pattern);
      add('Event bus', d.event_bus_name);
      add('Targets', (d.targets || []).map(t => nameFromArn(t.Arn)));
      add('Description', d.description);
      break;
    case 'bucket':
      add('Region', d.region);
      add('Encryption', d.encryption && (d.encryption.SSEAlgorithm || d.encryption));
      add('KMS key', d.encryption && d.encryption.KMSMasterKeyID);
      add('Versioning', d.versioning);
      add('Size', bytes(d.bucket_size_bytes));
      add('Notifications', (d.event_notifications || []).length);
      add('Source trail', d.source_trail_arn && nameFromArn(d.source_trail_arn));
      break;
    case 'queue':
      add('Region', d.region);
      add('Encryption', d.encryption);
      add('Lambda triggers', (d.lambda_event_sources || []).length);
      add('URL', d.url);
      break;
    case 'topic':
      add('Region', d.region);
      add('Encryption', d.encryption);
      add('Subscriptions', (d.subscriptions || []).length);
      add('Feeds from', (d.sources || []).map(s => s.name));
      break;
    case 'function':
      add('Runtime', d.runtime);
      add('Handler', d.handler);
      add('Memory', d.memory_size && `${d.memory_size} MB`);
      add('Timeout', d.timeout && `${d.timeout} s`);
      add('Role', d.role && nameFromArn(d.role));
      add('Layers', (d.layers || []).length || null);
      add('Triggered by', (d.sources || []).map(s => s.name));
      break;
    case 'role':
      add('Used by', (d.sources || []).map(s => s.name || s.service || s.principal));
      add('Managed policies', (d.attached_managed_policies || []).map(p => p.policy_name));
      add('Inline policies', Object.keys(d.inline_policies || {}));
      add('Max session', d.max_session_duration && `${d.max_session_duration / 3600} h`);
      add('Path', d.path);
      break;
  }
  return rows;
}

/** One short status shown under the resource name, flagged when it's a bad state. */
function statusLine(node) {
  const d = node.details || {};
  if (node.external) return { text: 'not monitored' };
  if (d.accessible === false) return { text: 'not accessible', bad: true };
  switch (node.type) {
    case 'trail': return d.is_logging === false ? { text: 'LOGGING STOPPED', bad: true } : { text: `${d.home_region || node.region} · logging` };
    case 'detector': return d.status !== 'ENABLED' ? { text: d.status || 'unknown', bad: true } : { text: `${node.region} · enabled` };
    case 'rule': return d.state !== 'ENABLED' ? { text: `${node.region} · ${d.state}`, bad: true } : { text: node.region };
    case 'role': return { text: 'global' };
    default: return { text: node.region };
  }
}

// ---------- Tabs ----------

function selectTab(name, focus) {
  for (const t of ['pipeline', 'alerts']) {
    const on = t === name;
    $(`tab-${t}`).setAttribute('aria-selected', on);
    $(`tab-${t}`).tabIndex = on ? 0 : -1;
    $(`view-${t}`).hidden = !on;
  }
  if (focus) $(`tab-${name}`).focus();
  hideTooltip();
  if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
}

$('tab-pipeline').addEventListener('click', () => selectTab('pipeline'));
$('tab-alerts').addEventListener('click', () => selectTab('alerts'));
document.querySelector('.tabs').addEventListener('keydown', e => {
  if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    selectTab($('tab-pipeline').getAttribute('aria-selected') === 'true' ? 'alerts' : 'pipeline', true);
  }
});

// ---------- Data loading ----------

async function refresh() {
  const btn = $('refresh-btn');
  btn.classList.add('spinning');
  try {
    state.status = await getJSON('/api/status');
    const accounts = state.status.accounts.map(a => a.accountId);
    if (!accounts.includes(state.account)) state.account = accounts[0] || null;

    const history = state.account ? await getJSON(`/api/history?account=${state.account}`) : { versions: [] };
    state.versions = history.versions;
    if (state.version && !state.versions.some(v => v.id === state.version && !v.live)) state.version = null;

    const versionParam = state.version ? `&version=${encodeURIComponent(state.version)}` : '';
    const [graph, alertData] = await Promise.all([
      state.account ? getJSON(`/api/graph?account=${state.account}${versionParam}`) : Promise.resolve(null),
      getJSON('/api/alerts'),
    ]);
    state.graph = graph;
    const previous = state.seenAlertIds;
    state.alerts = alertData.alerts.map(a => ({ ...a, isNew: previous !== null && !previous.has(a.eventID) }));
    state.seenAlertIds = new Set(state.alerts.map(a => a.eventID));

    renderAccountControls();
    renderHistory();
    renderDiagram();
    renderAlerts();
    renderStatus();
  } catch (err) {
    $('status-text').textContent = `Refresh failed: ${err.message}`;
  } finally {
    btn.classList.remove('spinning');
  }
}

function renderStatus() {
  const s = state.status;
  const account = s.accounts.find(a => a.accountId === state.account);
  $('status-text').textContent =
    `State ${account ? ago(account.updated) : '—'} · Log ${s.logExists ? ago(s.logUpdated) : 'not found'}`;
  const total = state.alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
  const pill = $('alert-count');
  pill.hidden = total === 0;
  pill.textContent = total;
  pill.setAttribute('aria-label', `${total} critical or high alerts`);
}

function renderAccountControls() {
  const accountSel = $('account-select');
  accountSel.replaceChildren(...state.status.accounts.map(a =>
    el('option', { value: a.accountId, text: a.accountId, selected: a.accountId === state.account })));
  accountSel.disabled = !state.status.accounts.length;

  const regionSel = $('region-select');
  const regions = state.graph ? state.graph.regions : [];
  if (state.region && !regions.includes(state.region)) state.region = '';
  regionSel.replaceChildren(
    el('option', { value: '', text: 'All regions' }),
    ...regions.map(r => el('option', { value: r, text: r, selected: r === state.region })));

  $('connected-only').checked = state.connectedOnly;
}

$('account-select').addEventListener('change', e => {
  state.account = e.target.value;
  state.selectedId = null;
  store('account', state.account);
  refresh();
});
$('region-select').addEventListener('change', e => {
  state.region = e.target.value;
  store('region', state.region);
  renderDiagram();
});
$('connected-only').addEventListener('change', e => {
  state.connectedOnly = e.target.checked;
  store('connectedOnly', state.connectedOnly ? '1' : '0');
  renderDiagram();
});
$('refresh-btn').addEventListener('click', refresh);

// ---------- History ----------

function utc(epochSeconds) {
  return new Date(epochSeconds * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

function versionLabel(v) {
  const what = v.changes === null ? 'first recorded' : `${v.changes} change${v.changes === 1 ? '' : 's'}`;
  return `${utc(v.time)} · ${v.live ? `live, ${what}` : what}`;
}

function renderHistory() {
  const select = $('version-select');
  const current = state.version || (state.versions[0] && state.versions[0].id);
  select.replaceChildren(...state.versions.map(v =>
    el('option', { value: v.id, text: versionLabel(v), selected: v.id === current })));
  select.disabled = state.versions.length < 2;

  const idx = state.versions.findIndex(v => v.id === current);
  const atOldest = idx < 0 || idx >= state.versions.length - 1;
  const atNewest = idx <= 0;
  const olderBtn = $('version-older'), newerBtn = $('version-newer');
  olderBtn.setAttribute('aria-disabled', String(atOldest));
  olderBtn.title = atOldest ? 'Already showing the oldest recorded version' : 'Older version';
  olderBtn.setAttribute('aria-label', olderBtn.title);
  newerBtn.setAttribute('aria-disabled', String(atNewest));
  newerBtn.title = atNewest ? 'Already showing the newest version' : 'Newer version';
  newerBtn.setAttribute('aria-label', newerBtn.title);
  $('show-diff').checked = state.showDiff;
  document.querySelectorAll('.diff-legend').forEach(e => { e.hidden = !state.showDiff; });

  const banner = $('history-banner');
  const g = state.graph;
  banner.hidden = !g || g.live;
  if (g && !g.live) {
    const since = g.previousTime ? `, ${g.changeCount} change${g.changeCount === 1 ? '' : 's'} since ${utc(g.previousTime)}` : ', the first recorded version';
    $('history-banner-text').textContent = `Viewing the pipeline as of ${utc(g.updated)}${since}. Alert badges count only alerts up to this time.`;
  }
}

function pickVersion(id) {
  const v = state.versions.find(x => x.id === id);
  state.version = !v || v.live ? null : id;
  refresh();
}

$('version-select').addEventListener('change', e => pickVersion(e.target.value));
$('version-older').addEventListener('click', () => {
  const idx = state.versions.findIndex(v => v.id === (state.version || state.versions[0].id));
  if (idx < state.versions.length - 1) pickVersion(state.versions[idx + 1].id);
});
$('version-newer').addEventListener('click', () => {
  const idx = state.versions.findIndex(v => v.id === state.version);
  if (idx > 0) pickVersion(state.versions[idx - 1].id);
});
$('history-live').addEventListener('click', () => pickVersion(null));
$('show-diff').addEventListener('change', e => {
  state.showDiff = e.target.checked;
  store('showDiff', state.showDiff ? '1' : '0');
  renderHistory();
  renderDiagram();
});

// ---------- Diagram ----------

function visibleGraph() {
  // Removed resources only exist as ghosts for the change highlight
  const nodes = state.graph.nodes.filter(n => state.showDiff || n.change !== 'removed');
  const edges = state.graph.edges.filter(e => state.showDiff || e.change !== 'removed');
  const byId = new Map(nodes.map(n => [n.id, n]));
  const inRegion = n => !state.region || n.region === state.region ||
    (n.type === 'trail' && n.details && n.details.is_multi_region);

  let keep = new Set(nodes.filter(n => n.region !== 'global' && inRegion(n) && !n.external).map(n => n.id));
  // Global/unmonitored resources show up when something in view points at them
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of edges) {
      const t = byId.get(e.target);
      if (keep.has(e.source) && !keep.has(e.target) && t && (t.region === 'global' || t.external || !state.region)) {
        keep.add(e.target); grew = true;
      }
    }
  }
  if (!state.region) nodes.forEach(n => keep.add(n.id));

  let visEdges = edges.filter(e => keep.has(e.source) && keep.has(e.target));
  if (state.connectedOnly) {
    const linked = new Set(visEdges.flatMap(e => [e.source, e.target]));
    keep = new Set([...keep].filter(id => linked.has(id)));
  }
  visEdges = visEdges.filter(e => keep.has(e.source) && keep.has(e.target));
  return { nodes: nodes.filter(n => keep.has(n.id)), edges: visEdges, byId };
}

/** Order each column by the average position of upstream nodes to reduce crossings. */
function layout(nodes, edges) {
  const cols = COLUMNS.map(() => []);
  for (const n of nodes) cols[Math.min(n.stage, COLUMNS.length - 1)].push(n);
  const pos = new Map();
  const incoming = new Map();
  for (const e of edges) (incoming.get(e.target) || incoming.set(e.target, []).get(e.target)).push(e.source);

  cols.forEach((col, ci) => {
    const typeRank = n => TYPE_ORDER.indexOf(n.type);
    const bary = n => {
      const ys = (incoming.get(n.id) || []).map(s => pos.get(s)).filter(p => p && p.col < ci).map(p => p.row);
      return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity;
    };
    col.sort((a, b) => ci === 0
      ? typeRank(a) - typeRank(b) || a.name.localeCompare(b.name)
      : bary(a) - bary(b) || typeRank(a) - typeRank(b) || a.name.localeCompare(b.name));
    col.forEach((n, row) => pos.set(n.id, {
      col: ci, row,
      x: PAD + ci * COL_W,
      y: HEADER_H + row * ROW_H,
    }));
  });
  const rows = Math.max(1, ...cols.map(c => c.length));
  return { pos, width: PAD * 2 + COLUMNS.length * COL_W - (COL_W - NODE_W), height: HEADER_H + rows * ROW_H + PAD };
}

function edgePath(a, b) {
  const sx = a.x + NODE_W, sy = a.y + ROW_H / 2 - 4;
  const ty = b.y + ROW_H / 2 - 4;
  if (b.col > a.col) {
    const tx = b.x - 4;
    const dx = Math.max(40, (tx - sx) / 2);
    return `M${sx},${sy} C${sx + dx},${sy} ${tx - dx},${ty} ${tx},${ty}`;
  }
  // Same column (e.g. SNS → SQS) or backwards: loop out to the right and back in
  const tx = b.x + NODE_W;
  const bulge = sx + 40 + Math.min(40, Math.abs(ty - sy) / 6);
  return `M${sx},${sy} C${bulge},${sy} ${bulge},${ty} ${tx + 6},${ty}`;
}

function truncate(s, max) {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function renderDiagram() {
  const svg = $('diagram');
  const empty = $('diagram-empty');
  svg.replaceChildren();

  if (!state.status.accounts.length) {
    svg.style.display = 'none';
    empty.hidden = false;
    empty.replaceChildren(
      el('strong', { text: 'No monitor state found' }),
      el('div', { text: `Nothing in ${state.status.stateDir}. Start the monitor (e.g. ` },
        el('code', { text: 'python aws-security-guard.py --profile <name>' }),
        ') and the pipeline appears after its first scan.'));
    showDetail(null);
    return;
  }

  const { nodes, edges, byId } = visibleGraph();
  if (!nodes.length) {
    svg.style.display = 'none';
    empty.hidden = false;
    empty.replaceChildren(el('strong', { text: 'No resources in view' }),
      el('div', { text: 'Try another region or turn off "Connected resources only".' }));
    return;
  }
  svg.style.display = '';
  empty.hidden = true;

  const { pos, width, height } = layout(nodes, edges);
  svg.setAttribute('width', width);
  svg.setAttribute('height', height);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  svg.append(el('svg:defs', {},
    ['arrow', 'arrow-hot'].map(id => el('svg:marker', {
      id, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse',
    }, el('svg:path', { d: 'M0,0 L10,5 L0,10 z' })))));

  COLUMNS.forEach((c, i) => {
    const x = PAD + i * COL_W;
    svg.append(
      el('svg:rect', { class: 'col-bg', x: x - 8, y: 8, width: NODE_W + 16, height: height - 16, rx: 10 }),
      el('svg:text', { class: 'col-title', x, y: 32, text: c.title }),
      el('svg:text', { class: 'col-sub', x, y: 48, text: c.sub }));
  });

  const edgeLayer = el('svg:g', { class: 'edges' });
  const nodeLayer = el('svg:g', { class: 'nodes' });
  svg.append(edgeLayer, nodeLayer);

  const edgeEls = [];
  for (const e of edges) {
    const d = edgePath(pos.get(e.source), pos.get(e.target));
    const change = state.showDiff && e.change ? ` change-${e.change}` : '';
    const path = el('svg:path', { class: `edge${change}`, d, 'marker-end': 'url(#arrow)' });
    const hit = el('svg:path', { class: 'edge-hit', d });
    const src = byId.get(e.source), dst = byId.get(e.target);
    hit.addEventListener('mousemove', ev => showTooltip(ev, edgeTooltip(src, dst, e.label, state.showDiff && e.change)));
    hit.addEventListener('mouseleave', hideTooltip);
    edgeLayer.append(path, hit);
    edgeEls.push({ edge: e, path });
  }

  for (const n of nodes) {
    const p = pos.get(n.id);
    const meta = TYPES[n.type] || TYPES.external;
    const status = statusLine(n);
    const alertCount = (n.alertIds || []).length;
    const cy = p.y + ROW_H / 2 - 4;
    const change = state.showDiff ? n.change : null;

    const g = el('svg:g', {
      class: `node${n.external ? ' external' : ''}${change ? ` change-${change}` : ''}${n.id === state.selectedId ? ' selected' : ''}`,
      tabindex: 0, role: 'button',
      'aria-expanded': String(n.id === state.selectedId),
      'aria-label': `${meta.label} ${n.name}, ${status.text}${change ? `, ${change} in this version` : ''}${alertCount ? `, ${alertCount} alerts` : ''}`,
      'data-id': n.id,
    },
      el('svg:rect', { class: 'hit', x: p.x - 4, y: p.y + 2, width: NODE_W + 8, height: ROW_H - 12, rx: 8 }),
      el('svg:rect', { class: 'icon', x: p.x, y: cy - ICON / 2, width: ICON, height: ICON, rx: 8, style: `fill: ${meta.color}` }),
      el('svg:text', { class: 'icon-text', x: p.x + ICON / 2, y: cy + 4, 'text-anchor': 'middle', text: meta.abbr }),
      el('svg:text', { class: 'label', x: p.x + ICON + 10, y: cy - 2, text: truncate(n.name, change ? 18 : 25) }),
      el('svg:text', { class: status.bad ? 'sublabel status-off' : 'sublabel', x: p.x + ICON + 10, y: cy + 14, text: truncate(status.text, 30) }),
    );
    if (change) {
      g.append(el('svg:text', { class: 'change-tag', x: p.x + NODE_W, y: cy - 2, 'text-anchor': 'end', text: CHANGE_TAGS[change] }));
    }
    if (alertCount) {
      g.append(
        el('svg:circle', { class: 'badge', cx: p.x + ICON, cy: cy - ICON / 2, r: 9 }),
        el('svg:text', { class: 'badge-text', x: p.x + ICON, y: cy - ICON / 2 + 3.5, 'text-anchor': 'middle', text: alertCount > 99 ? '99+' : alertCount }));
    }

    const highlight = on => {
      const linked = new Set([n.id]);
      for (const { edge, path } of edgeEls) {
        const hot = edge.source === n.id || edge.target === n.id;
        if (hot) { linked.add(edge.source); linked.add(edge.target); }
        path.classList.toggle('hot', on && hot);
        path.classList.toggle('dim', on && !hot);
        path.setAttribute('marker-end', on && hot ? 'url(#arrow-hot)' : 'url(#arrow)');
      }
      nodeLayer.querySelectorAll('.node').forEach(other =>
        other.classList.toggle('dim', on && !linked.has(other.dataset.id)));
    };
    g.addEventListener('mouseenter', () => highlight(true));
    g.addEventListener('mousemove', ev => showTooltip(ev, nodeTooltip(n)));
    g.addEventListener('mouseleave', () => { highlight(false); hideTooltip(); });
    g.addEventListener('focus', () => { highlight(true); showTooltipAt(g, nodeTooltip(n)); });
    g.addEventListener('blur', () => { highlight(false); hideTooltip(); });
    g.addEventListener('click', () => selectNode(n.id));
    g.addEventListener('keydown', ev => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectNode(n.id); }
    });
    nodeLayer.append(g);
  }

  showDetail(state.selectedId && state.graph.nodes.find(n => n.id === state.selectedId));
}

// ---------- Tooltip ----------

const CHANGE_TAGS = { added: 'NEW', changed: 'CHANGED', removed: 'REMOVED' };

function changeNote(n) {
  if (!state.showDiff || !n.change) return null;
  const text = {
    added: 'Added in this version',
    removed: 'Removed in this version (showing its last known state)',
    changed: `Changed in this version: ${(n.changedFields || []).join(', ')}`,
  }[n.change];
  return el('div', { class: `tt-change change-text-${n.change}`, text });
}

function nodeTooltip(n) {
  const meta = TYPES[n.type] || TYPES.external;
  const alertCount = (n.alertIds || []).length;
  return [
    el('div', { class: 'tt-type', text: meta.label }),
    el('div', { class: 'tt-name', text: n.name }),
    changeNote(n),
    el('dl', {}, summarize(n).flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: truncate(v, 160) })])),
    alertCount ? el('div', { class: 'tt-alert', text: `${alertCount} alert${alertCount === 1 ? '' : 's'}` }) : null,
    el('div', { class: 'tt-hint', text: 'Click for full details' }),
  ];
}

function edgeTooltip(src, dst, label, change) {
  return [
    el('div', { class: 'tt-type', text: label }),
    el('div', { class: 'tt-name', text: `${src.name} → ${dst.name}` }),
    change ? el('div', { class: `tt-change change-text-${change}`, text: `Connection ${change} in this version` }) : null,
  ];
}

function showTooltip(ev, content) {
  const tt = $('tooltip');
  tt.replaceChildren(...content);
  tt.hidden = false;
  const { innerWidth: vw, innerHeight: vh } = window;
  const r = tt.getBoundingClientRect();
  let x = ev.clientX + 16, y = ev.clientY + 16;
  if (x + r.width > vw - 8) x = ev.clientX - r.width - 16;
  if (y + r.height > vh - 8) y = Math.max(8, vh - r.height - 8);
  tt.style.left = `${Math.max(8, x)}px`;
  tt.style.top = `${y}px`;
}

function showTooltipAt(target, content) {
  const r = target.getBoundingClientRect();
  showTooltip({ clientX: r.right - 8, clientY: r.top }, content);
}

function hideTooltip() { $('tooltip').hidden = true; }

// ---------- Detail panel ----------

function selectNode(id) {
  state.selectedId = state.selectedId === id ? null : id;
  document.querySelectorAll('#diagram .node').forEach(g => {
    const isSelected = g.dataset.id === state.selectedId;
    g.classList.toggle('selected', isSelected);
    g.setAttribute('aria-expanded', String(isSelected));
  });
  showDetail(state.selectedId && state.graph.nodes.find(n => n.id === state.selectedId));
}

function showDetail(node) {
  const panel = $('detail-panel');
  if (!node) { panel.hidden = true; return; }
  panel.hidden = false;
  const meta = TYPES[node.type] || TYPES.external;
  $('detail-type').textContent = meta.label + (node.external ? ' · not monitored' : '');
  $('detail-name').textContent = node.name;
  $('detail-change').replaceChildren(...[changeNote(node)].filter(Boolean));
  $('detail-summary').replaceChildren(...summarize(node).flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })]));

  const byId = new Map(state.graph.nodes.map(n => [n.id, n]));
  const upstream = state.graph.edges.filter(e => e.target === node.id);
  const downstream = state.graph.edges.filter(e => e.source === node.id);
  const linkList = (title, list, pick) => list.length ? [
    el('h3', { text: title }),
    el('ul', { class: 'conn-list' }, list.map(e => {
      const other = byId.get(pick(e));
      return el('li', {}, el('button', {
        class: 'link-btn', type: 'button',
        text: `${other ? other.name : nameFromArn(pick(e))} (${e.label})`,
        onclick: () => { selectNode(pick(e)); focusNode(pick(e)); },
      }));
    })),
  ] : [];
  $('detail-links').replaceChildren(el('div', { class: 'conn-list' },
    linkList('Receives from', upstream, e => e.source),
    linkList('Sends to', downstream, e => e.target)));

  const alertIds = node.alertIds || [];
  const btn = $('detail-alerts-btn');
  btn.hidden = alertIds.length === 0;
  btn.textContent = `View ${alertIds.length} alert${alertIds.length === 1 ? '' : 's'}`;
  btn.onclick = () => {
    state.resourceFilter = { name: node.name, ids: new Set(alertIds) };
    renderAlerts();
    selectTab('alerts');
  };
  $('detail-raw').textContent = JSON.stringify(node.details, null, 2);
}

function focusNode(id) {
  const g = [...document.querySelectorAll('#diagram .node')].find(x => x.dataset.id === id);
  if (g) { g.scrollIntoView({ block: 'nearest', inline: 'nearest' }); g.focus(); }
}

$('detail-close').addEventListener('click', () => {
  const id = state.selectedId;
  selectNode(id);
  // Closing the panel hides the button focus was on; return focus to the node
  // that opened it instead of letting it fall back to <body>.
  focusNode(id);
});

// ---------- Alerts ----------

/** Clipboard API only exists on https/localhost; fall back for plain-http LAN access. */
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = el('textarea', { readonly: true, style: 'position:fixed;opacity:0' });
  area.value = text;
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  if (!ok) throw new Error('copy failed');
}

function prettyLog(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

function serviceOf(a) {
  return String(a.eventSource || '').replace('.amazonaws.com', '');
}

function buildChips() {
  const fs = document.querySelector('.chips');
  for (const s of SEVERITIES) {
    const input = el('input', { type: 'checkbox', checked: true, value: s.key });
    input.addEventListener('change', () => {
      input.checked ? state.severities.add(s.key) : state.severities.delete(s.key);
      renderAlerts();
    });
    fs.append(el('label', { class: `chip sev-${s.key}` }, input, s.label, ' ', el('span', { class: 'n', 'data-sev': s.key })));
  }
}

function fillSelect(select, values, allLabel) {
  const current = select.value;
  select.replaceChildren(el('option', { value: '', text: allLabel }),
    ...values.map(v => el('option', { value: v, text: v, selected: v === current })));
}

function filteredAlerts() {
  const q = $('alert-search').value.trim().toLowerCase();
  const svc = $('alert-service').value;
  const acct = $('alert-account').value;
  return state.alerts.filter(a =>
    state.severities.has(a.severity) &&
    (!svc || serviceOf(a) === svc) &&
    (!acct || a.recipientAccountId === acct) &&
    (!state.resourceFilter || state.resourceFilter.ids.has(a.eventID)) &&
    (!q || JSON.stringify(a).toLowerCase().includes(q)));
}

function renderAlerts() {
  fillSelect($('alert-service'), [...new Set(state.alerts.map(serviceOf))].sort(), 'All services');
  fillSelect($('alert-account'), [...new Set(state.alerts.map(a => a.recipientAccountId))].sort(), 'All accounts');

  const counts = {};
  for (const a of state.alerts) counts[a.severity] = (counts[a.severity] || 0) + 1;
  document.querySelectorAll('.chip .n').forEach(n => { n.textContent = counts[n.dataset.sev] || 0; });

  const note = $('alert-filter-note');
  note.hidden = !state.resourceFilter;
  if (state.resourceFilter) $('alert-filter-text').textContent = `Showing alerts for ${state.resourceFilter.name}`;

  const list = filteredAlerts();
  const tbody = $('alert-rows');
  const empty = $('alerts-empty');
  tbody.replaceChildren();

  if (!state.status.logExists) {
    empty.hidden = false;
    empty.replaceChildren(el('strong', { text: 'No log file yet' }),
      el('div', { text: `Waiting for ${state.status.logFile}. The monitor writes it on the first detected change after its baseline scan.` }));
    return;
  }
  if (!list.length) {
    empty.hidden = false;
    empty.replaceChildren(el('strong', { text: state.alerts.length ? 'No alerts match these filters' : 'No alerts yet' }),
      el('div', { text: state.alerts.length ? 'Adjust the search, severity or service filters.' : 'The monitor has not logged any changes.' }));
    return;
  }
  empty.hidden = true;

  for (const a of list.slice(0, state.alertLimit)) {
    const open = state.expandedAlerts.has(a.eventID);
    const toggle = () => {
      open ? state.expandedAlerts.delete(a.eventID) : state.expandedAlerts.add(a.eventID);
      renderAlerts();
    };
    const detailId = `alert-${a.eventID}`;
    tbody.append(el('tr', { class: `row${a.isNew ? ' new' : ''}${open ? ' expanded' : ''}`, onclick: toggle },
      el('td', { class: 'time c-time', text: (a.eventTime || '').replace('T', ' ').replace('Z', '') }),
      el('td', { class: 'c-sev' }, el('span', { class: `sev sev-${a.severity}`, text: a.severity === 'error' ? 'tool error' : a.severity })),
      el('td', { class: 'c-event' }, el('button', {
        class: 'expander event-name', type: 'button', 'aria-expanded': open, 'aria-controls': detailId,
        text: a.eventName, onclick: ev => { ev.stopPropagation(); toggle(); },
      })),
      el('td', { class: 'resource c-resource', text: a.resource || '—' }),
      el('td', { class: 'c-service', text: serviceOf(a) }),
      el('td', { class: 'c-region', text: a.awsRegion }),
      el('td', { class: 'c-account', text: a.recipientAccountId }),
    ));
    if (open) {
      tbody.append(el('tr', { class: 'detail-row', id: detailId },
        el('td', { colspan: 7 },
          a.errorMessage ? el('div', { class: 'error-msg', text: `${a.errorCode || 'Error'}: ${a.errorMessage}` }) : null,
          el('div', { class: 'log-head' },
            el('span', { class: 'muted', text: 'Full log entry' }),
            el('button', {
              class: 'link-btn', type: 'button', text: 'Copy', 'aria-live': 'polite',
              onclick: ev => {
                ev.stopPropagation();
                copyText(a.raw).then(
                  () => { ev.target.textContent = 'Copied'; },
                  () => { ev.target.textContent = 'Copy failed'; });
              },
            })),
          el('pre', { text: prettyLog(a.raw) }))));
    }
  }
  if (list.length > state.alertLimit) {
    tbody.append(el('tr', {}, el('td', { colspan: 7 },
      el('button', { class: 'link-btn', type: 'button', text: `Show more (${list.length - state.alertLimit} hidden)`,
        onclick: () => { state.alertLimit += 300; renderAlerts(); } }))));
  }
}

let searchTimer;
$('alert-search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(renderAlerts, 150); });
$('alert-service').addEventListener('change', renderAlerts);
$('alert-account').addEventListener('change', renderAlerts);
$('alert-filter-clear').addEventListener('click', () => { state.resourceFilter = null; renderAlerts(); });

// ---------- Boot ----------

buildChips();
selectTab(location.hash === '#alerts' ? 'alerts' : 'pipeline');
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
