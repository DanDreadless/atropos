// Atropos: the Connections view. Loaded before app.js, whose helpers (h,
// api, $, fmtNs, fmtInt, showEvents, toast, fail) it uses only when called.
//
// Everything drawn comes from evidence, which may be hostile: labels are
// text nodes, never markup, and all SVG is built with createElementNS.
'use strict';

let connectionsLoaded = false;
// range: the period shown, { from, to } as BigInt nanoseconds (either may
// be null for open); null for the whole time.
// vb: the graph's zoomed view box, null for the whole graph; q and found:
// what was searched for and the nodes it found.
const CN = { mode: 'graph', kind: '', rep: null, pick: null, pos: null, selected: null, range: null, vb: null, q: '', found: null };

const SVGNS = 'http://www.w3.org/2000/svg';
function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, String(v));
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const CONF_WORDS = { strong: 'strong', possible: 'possible', 'one-end': 'one end only' };
const SEEN_WORDS = { both: 'both ends', source: 'the connecting end only', target: 'the end connected to only' };
// Each kind of connection: its name, and the short tag drawn on its arrows.
const KIND_WORDS = { rdp: 'Remote Desktop', smb: 'File share', exec: 'Started remotely', usb: 'The same USB device', file: 'The same file' };
const KIND_TAG = { rdp: 'RDP', smb: 'Share', exec: 'Exec', usb: 'USB', file: 'File' };
// How the summary counts each kind.
const kindCount = (k) => (k === 'usb' ? 'USB device on two hosts' : k === 'file' ? 'file on two hosts' : KIND_WORDS[k].toLowerCase());

function cnLabel(id) {
  const n = CN.rep && CN.rep.nodes.find((x) => x.id === id);
  return n ? n.label : id;
}

function setCnMode(m) {
  CN.mode = m;
  $('cnwrap').classList.toggle('graph', m === 'graph');
  $('cnzoom').hidden = m !== 'graph';
  for (const b of $('cnmode').children) b.classList.toggle('on', b.dataset.mode === m);
  drawConnections();
}

function setCnKind(k) {
  CN.kind = k;
  CN.selected = null;
  for (const b of $('cnkind').children) b.classList.toggle('on', b.dataset.kind === k);
  drawConnections();
}

// The connections and edges of the kind chosen, in the period chosen.
function kindConns() { return CN.rep ? CN.rep.connections.filter((c) => (!CN.kind || c.kind === CN.kind) && inRange(c)) : []; }
function kindEdges() {
  if (!CN.rep) return [];
  if (!CN.range) return CN.rep.edges.filter((e) => !CN.kind || e.kind === CN.kind);
  // The edges again, from the connections in the period.
  const m = new Map();
  for (const c of kindConns()) {
    const k = c.kind + '\0' + c.from + '\0' + c.to;
    let e = m.get(k);
    if (!e) m.set(k, e = { from: c.from, to: c.to, kind: c.kind, count: 0, strong: 0, possible: 0, one_end: 0, first_utc: c.start_utc, last_utc: c.start_utc });
    e.count++;
    if (c.confidence === 'strong') e.strong++; else if (c.confidence === 'possible') e.possible++; else e.one_end++;
    if (BigInt(c.start_utc) < BigInt(e.first_utc)) e.first_utc = c.start_utc;
    if (BigInt(c.start_utc) > BigInt(e.last_utc)) e.last_utc = c.start_utc;
  }
  return [...m.values()];
}

// The accounts and USB storage devices of a host, in the period chosen:
// what a host picked on the graph opens into.
function nodeLeaves(id) {
  const r = CN.range;
  return CN.rep && CN.rep.leaves ? CN.rep.leaves.filter((l) => l.node === id &&
    (!r || ((r.from == null || BigInt(l.last_utc) >= r.from) && (r.to == null || BigInt(l.first_utc) <= r.to)))) : [];
}

function leafWords(l) {
  if (l.kind === 'device') {
    return `USB storage device ${l.label}, ${l.detail}: ${l.events.length} record${l.events.length === 1 ? '' : 's'}, ${fmtNs(l.first_utc, 0)}` +
      (l.last_utc !== l.first_utc ? ` to ${fmtNs(l.last_utc, 0)}` : '') + ' UTC';
  }
  const parts = [];
  if (l.in) parts.push(`signed in here by ${l.in} connection${l.in === 1 ? '' : 's'}`);
  if (l.out) parts.push(`connected out by ${l.out}`);
  return `Account ${l.label}: ${parts.join(', ')}, ${fmtNs(l.first_utc, 0)}` + (l.last_utc !== l.first_utc ? ` to ${fmtNs(l.last_utc, 0)}` : '') + ' UTC';
}

// ---- the period shown ----
// A connection is in it when it, or its session, overlaps it. One with no
// time (a registry key's last write) is not.
function inRange(c) {
  const r = CN.range;
  if (!r) return true;
  if (c.undated) return false;
  const s = BigInt(c.start_utc), e = c.ended_utc ? BigInt(c.ended_utc) : s;
  return (r.from == null || e >= r.from) && (r.to == null || s <= r.to);
}

// parseUTC reads "2026-11-20", "2026-11-20 09:00", "2026-11-20 09:00:30"
// or, on the day of the first connection, "09:00": as BigInt nanoseconds,
// the start of what it names, or with end its last nanosecond. null for
// empty, undefined for what is not a time.
function parseUTC(s, end) {
  s = s.trim().replace(/\s*UTC$/i, '').replace(/Z$/, '');
  if (!s) return null;
  let m = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(s);
  if (!m) {
    const t = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(s);
    const first = CN.rep && CN.rep.connections.find((c) => !c.undated);
    if (!t || !first) return undefined;
    m = [s, ...fmtNs(first.start_utc, 0).slice(0, 10).split('-'), t[1], t[2], t[3]];
  }
  const [y, mo, d, hh, mi, ss] = m.slice(1).map((v) => (v == null ? null : Number(v)));
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh > 23 || mi > 59 || ss > 59) return undefined;
  const ms = Date.UTC(y, mo - 1, d, hh || 0, mi || 0, ss || 0);
  if (isNaN(ms) || new Date(ms).getUTCDate() !== d) return undefined;
  let ns = BigInt(ms) * 1000000n;
  if (end) ns += (ss != null ? 1000000000n : mi != null ? 60000000000n : 86400000000000n) - 1n;
  return ns;
}

function setCnRange(from, to) {
  CN.range = from == null && to == null ? null : { from, to };
  CN.selected = null;
  $('cnfrom').value = from == null ? '' : fmtNs(from, 0);
  $('cnto').value = to == null ? '' : fmtNs(to, 0);
  $('cnfrom').classList.remove('bad');
  $('cnto').classList.remove('bad');
  $('cnwhole').hidden = !CN.range;
  if (CN.rep) drawConnections();
}

// From what is typed in the two boxes.
function applyCnRange() {
  const from = parseUTC($('cnfrom').value, false), to = parseUTC($('cnto').value, true);
  $('cnfrom').classList.toggle('bad', from === undefined);
  $('cnto').classList.toggle('bad', to === undefined);
  if (from === undefined || to === undefined) { toast('A time is written 2026-11-20 09:00 (UTC), or 09:00 for the day of the first connection', true); return; }
  if (from != null && to != null && to < from) { $('cnto').classList.add('bad'); toast('The end of the period is before its start', true); return; }
  CN.range = from == null && to == null ? null : { from, to };
  CN.selected = null;
  $('cnwhole').hidden = !CN.range;
  if (CN.rep) drawConnections();
}

function rangeWords() {
  const r = CN.range;
  // To the minute when the period is in whole minutes.
  const f = (t, end) => ((end ? t + 1n : t) % 60000000000n === 0n ? fmtNs(t, 0).slice(0, 16) : fmtNs(t, 0));
  return r.from != null && r.to != null ? `from ${f(r.from)} to ${f(r.to, true)} UTC` : r.from != null ? `from ${f(r.from)} UTC on` : `up to ${f(r.to, true)} UTC`;
}

// Opens the tab on the connections an event of the timeline is part of,
// read again so that they include what was added since.
async function showEventConnections(id, what) {
  CN.pick = { event: Number(id), what };
  CN.kind = '';
  setCnRange(null, null);
  CN.selected = null;
  for (const b of $('cnkind').children) b.classList.toggle('on', b.dataset.kind === '');
  $('cnall').hidden = false;
  connectionsLoaded = true;
  setView('connections');
  await loadConnections();
}

async function loadConnections() {
  connectionsLoaded = true;
  $('cnsummary').replaceChildren('Reading…');
  try {
    CN.rep = await api('/api/analysis/connections');
    CN.pos = null;
    drawConnections();
  } catch (e) { $('cnsummary').replaceChildren('The connections could not be read'); fail(e); }
}

function drawSummary() {
  const r = CN.rep;
  for (const b of $('cnkind').children) {
    const k = b.dataset.kind;
    b.querySelector('i').textContent = fmtInt(r.connections.filter((c) => (!k || c.kind === k) && inRange(c)).length);
  }
  const conns = kindConns();
  const both = conns.filter((c) => c.seen_on === 'both').length;
  const undated = conns.filter((c) => c.undated).length;
  const hosts = r.nodes.filter((n) => n.in_case).length;
  const others = r.nodes.length - hosts;
  const byKind = Object.keys(KIND_WORDS).map((k) => [k, r.connections.filter((c) => c.kind === k && inRange(c)).length]).filter(([, n]) => n);
  const left = CN.range ? r.connections.filter((c) => (!CN.kind || c.kind === CN.kind) && c.undated).length : 0;
  $('cnsummary').replaceChildren(h('b', {}, fmtInt(conns.length)), conns.length === 1 ? ' connection' : ' connections',
    CN.kind ? ` (${kindCount(CN.kind)})` : '',
    CN.range ? ` ${rangeWords()}${left ? ` (${fmtInt(left)} with no time left out)` : ''}` : '',
    ` (${fmtInt(both)} seen at both ends${undated ? `, ${fmtInt(undated)} with no time` : ''}) between ${fmtInt(hosts)} host${hosts === 1 ? '' : 's'} and ${fmtInt(others)} other computer${others === 1 ? '' : 's'} or address${others === 1 ? '' : 'es'}`,
    !CN.kind && byKind.length > 1 ? ': ' + byKind.map(([k, n]) => `${fmtInt(n)} ${kindCount(k)}`).join(', ') : '',
    r.ready ? '' : ' (still reading some evidence)');
}

// pickConn narrows the list to a node or an edge; null shows everything.
function pickConn(p) {
  CN.pick = p;
  $('cnall').hidden = !p;
  drawConnections();
}

function pickedConns() {
  const all = kindConns();
  const p = CN.pick;
  if (!p) return all;
  if (p.event != null) return all.filter((c) => c.event_ids.includes(p.event) || (c.named || []).some((n) => n.id === p.event));
  if (p.node) return all.filter((c) => c.from === p.node || c.to === p.node);
  return all.filter((c) => c.from === p.from && c.to === p.to && c.kind === p.kind);
}

function drawConnections() {
  const r = CN.rep;
  const box = $('cncanvas');
  if (!r) { box.replaceChildren(); return; }
  drawSummary();
  if (!r.nodes.length) {
    box.replaceChildren(h('p', { class: 'anempty' }, 'No hosts are described yet. Describe them on the Details tab, with their addresses, then add their logs.'));
  } else if (CN.mode === 'graph') drawGraph(box, r);
  else drawLanes(box, r);
  drawLegend();
  drawConnRows();
  drawSide();
}

// connWhen is a connection's time as words: when, or why it has none.
function connWhen(c) {
  if (c.no_time) return c.start_utc === '0' ? `No time (${c.no_time})` : `No time (${c.no_time}; recorded on ${cnLabel(c.from)} ${fmtNs(c.start_utc, 0)} UTC)`;
  return c.undated ? 'No time (a registry key written ' + fmtNs(c.start_utc, 0) + ' UTC)' : fmtNs(c.start_utc, 0) + ' UTC';
}

function drawLegend() {
  $('cnlegend').replaceChildren(
    h('span', { class: 'cnkey strong' }, 'strong: both ends, within a minute, the same account'),
    h('span', { class: 'cnkey possible' }, 'possible: both ends, further apart or different accounts'),
    h('span', { class: 'cnkey oneend' }, 'one end only'),
    CN.rep && CN.rep.connections.some((c) => c.undated) ? h('span', { class: 'cnkey undated' }, CN.rep.connections.some((c) => c.undated && !c.no_time) ? 'no time: named only in the registry, or a file collected' : 'no time: a file collected') : '',
    CN.mode === 'lanes' && CN.rep && CN.rep.connections.some((c) => c.ended_utc) ? h('span', { class: 'cnkey session' }, 'bar: a Remote Desktop session, until logoff or disconnection') : '',
    CN.mode === 'lanes' ? h('span', {}, 'drag across the lanes to look at a period') : '',
    CN.mode === 'graph' ? h('span', { class: 'cnkey leaf' }, CN.pick && CN.pick.node && nodeLeaves(CN.pick.node).length ? 'small: an account or USB storage device of the host picked' : 'click a host for its accounts and USB storage devices') : '',
    h('span', { class: 'cnkeytags' }, Object.keys(KIND_TAG).map((k) => `${KIND_TAG[k]}: ${k === 'usb' ? 'the same USB device' : KIND_WORDS[k].toLowerCase()}`).join(' · ')),
    h('span', { class: 'cnkey nodehost' }, 'host of the case'),
    h('span', { class: 'cnkey nodeext' }, 'outside the case'));
}

function edgeClass(e) {
  return 'cnedge ' + (e.strong ? 'strong' : e.possible ? 'possible' : 'oneend');
}

// ---- the graph ----
// A small force layout, run to rest before drawing, from positions that
// depend only on the order of the nodes: the same case draws the same way.
function layoutGraph(r, w, hgt) {
  const n = r.nodes.length;
  const idx = Object.fromEntries(r.nodes.map((x, i) => [x.id, i]));
  const hostsN = r.nodes.filter((x) => x.in_case).length || 1;
  const pts = r.nodes.map((x, i) => {
    const inner = x.in_case;
    const k = inner ? i : i - hostsN;
    const m = inner ? hostsN : Math.max(1, n - hostsN);
    const a = (2 * Math.PI * k) / m + (inner ? -Math.PI / 2 : -Math.PI / 2 + Math.PI / m);
    const rad = (inner ? 0.28 : 0.44) * Math.min(w, hgt);
    return { x: w / 2 + rad * Math.cos(a), y: hgt / 2 + rad * Math.sin(a), vx: 0, vy: 0 };
  });
  const links = r.edges.map((e) => [idx[e.from], idx[e.to]]).filter(([a, b]) => a != null && b != null);
  const ideal = Math.min(w, hgt) / (n > 6 ? 3.2 : 2.6);
  for (let it = 0; it < 300; it++) {
    const cool = 1 - it / 300;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
        const d2 = Math.max(dx * dx + dy * dy, 25);
        const f = (ideal * ideal) / d2;
        pts[i].vx += dx * f * 0.05; pts[i].vy += dy * f * 0.05;
        pts[j].vx -= dx * f * 0.05; pts[j].vy -= dy * f * 0.05;
      }
    }
    for (const [a, b] of links) {
      const dx = pts[b].x - pts[a].x, dy = pts[b].y - pts[a].y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = ((d - ideal) / d) * 0.06;
      pts[a].vx += dx * f; pts[a].vy += dy * f;
      pts[b].vx -= dx * f; pts[b].vy -= dy * f;
    }
    for (const p of pts) {
      p.vx += (w / 2 - p.x) * 0.004; p.vy += (hgt / 2 - p.y) * 0.004;
      p.x += Math.max(-20, Math.min(20, p.vx * cool)); p.y += Math.max(-20, Math.min(20, p.vy * cool));
      p.vx *= 0.5; p.vy *= 0.5;
      p.x = Math.max(60, Math.min(w - 60, p.x)); p.y = Math.max(30, Math.min(hgt - 50, p.y)); // room for the label below
    }
  }
  return Object.fromEntries(r.nodes.map((x, i) => [x.id, { x: pts[i].x, y: pts[i].y }]));
}

function drawGraph(box, r) {
  const w = Math.max(320, box.clientWidth || 800), hgt = Math.max(360, box.clientHeight || 520);
  if (!CN.pos || CN.pos.w !== w || CN.pos.h !== hgt) { CN.pos = { w, h: hgt, at: layoutGraph(r, w, hgt) }; CN.vb = null; }
  const at = CN.pos.at;
  const vb = CN.vb || { x: 0, y: 0, w, h: hgt };
  const svg = sv('svg', { class: 'cngraph', viewBox: `${vb.x} ${vb.y} ${vb.w} ${vb.h}`, width: w, height: hgt, role: 'img', 'aria-label': 'Graph of connections' });
  const defs = sv('defs', {}, ...['strong', 'possible', 'oneend'].map((k) =>
    sv('marker', { id: 'cnarrow-' + k, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: 'userSpaceOnUse', orient: 'auto-start-reverse' },
      sv('path', { d: 'M0,0 L10,5 L0,10 z', class: 'cnarrowhead ' + k }))));
  svg.append(defs);
  const rad = (id) => (r.nodes.find((x) => x.id === id) || {}).in_case ? 22 : 11;
  const edges = kindEdges();
  const edgeEls = [];
  // Arrows between the same two computers (either way, or of several
  // kinds) fan out so that each shows.
  const pairKey = (e) => (e.from < e.to ? e.from + '\0' + e.to : e.to + '\0' + e.from);
  const siblings = {};
  for (const e of edges) (siblings[pairKey(e)] = siblings[pairKey(e)] || []).push(e);
  const pathFor = (e) => {
    const a = at[e.from], b = at[e.to];
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
    const sib = siblings[pairKey(e)];
    const k = sib.indexOf(e), n = sib.length;
    // Measured across the line from the lower id to the higher, whichever
    // way this arrow points.
    const bend = (k - (n - 1) / 2) * 56 * (e.from < e.to ? 1 : -1);
    const mx = (a.x + b.x) / 2 - (dy / d) * bend, my = (a.y + b.y) / 2 + (dx / d) * bend;
    const ra = rad(e.from) + 3, rb = rad(e.to) + 5;
    const ax = a.x + ((mx - a.x) / Math.hypot(mx - a.x, my - a.y)) * ra, ay = a.y + ((my - a.y) / Math.hypot(mx - a.x, my - a.y)) * ra;
    const bx = b.x - ((b.x - mx) / Math.hypot(b.x - mx, b.y - my)) * rb, by = b.y - ((b.y - my) / Math.hypot(b.x - mx, b.y - my)) * rb;
    // The label sits just outside its own curve, away from its siblings.
    const out = bend === 0 ? 0 : Math.sign(bend) * 14;
    const side = bend < 0 ? -1 : 1;
    return { d: `M${ax},${ay} Q${mx},${my} ${bx},${by}`, lx: (ax + 2 * mx + bx) / 4 - (dy / d) * out, ly: (ay + 2 * my + by) / 4 + (dx / d) * out,
      nx: -(dy / d) * side, ny: (dx / d) * side };
  };
  // Labels that would overlap another are moved further out from their
  // arrow, a step at a time, until they are clear.
  const spreadLabels = () => {
    const placed = [];
    for (const x of edgeEls) {
      const q = pathFor(x.e);
      const wd = 7 * x.lbl.textContent.length, ht = 14;
      let lx = q.lx, ly = q.ly;
      for (const s of [0, 1, -1, 2, -2, 3, -3, 4]) {
        lx = q.lx + q.nx * s * 14; ly = q.ly + q.ny * s * 14;
        if (!placed.some((b) => Math.abs(b.x - lx) < (b.w + wd) / 2 && Math.abs(b.y - ly) < ht)) break;
      }
      placed.push({ x: lx, y: ly, w: wd });
      x.lbl.setAttribute('x', lx); x.lbl.setAttribute('y', ly - 4);
    }
  };
  const picked = CN.pick ? pickedConns() : [];
  for (const e of edges) {
    const kind = e.strong ? 'strong' : e.possible ? 'possible' : 'oneend';
    const p = pathFor(e);
    const on = CN.pick && (CN.pick.event != null ? picked.some((c) => c.from === e.from && c.to === e.to && c.kind === e.kind)
      : CN.pick.from === e.from && CN.pick.to === e.to && CN.pick.kind === e.kind);
    const dim = CN.pick && (CN.pick.node ? e.from !== CN.pick.node && e.to !== CN.pick.node : !on);
    const kw = KIND_WORDS[e.kind] || e.kind;
    const title = `${cnLabel(e.from)} → ${cnLabel(e.to)}: ${e.count} ${kw.toLowerCase()} connection${e.count === 1 ? '' : 's'}` +
      ` (${e.strong} strong, ${e.possible} possible, ${e.one_end} seen at one end only), ` + (e.first_utc === '0' ? 'no time' : `${fmtNs(e.first_utc, 0)}` + (e.last_utc !== e.first_utc ? ` to ${fmtNs(e.last_utc, 0)}` : '') + ' UTC');
    const pick = { from: e.from, to: e.to, kind: e.kind };
    const path = sv('path', { d: p.d, class: edgeClass(e) + (on ? ' on' : '') + (dim ? ' dim' : ''), 'stroke-width': Math.min(6, 1.6 + Math.log2(e.count)), 'marker-end': `url(#cnarrow-${kind})` });
    const hit = sv('path', { d: p.d, class: 'cnhit', tabindex: 0, role: 'button', 'aria-label': title,
      onclick: (ev) => { ev.stopPropagation(); pickConn(pick); },
      onkeydown: (ev) => { if (ev.key === 'Enter') pickConn(pick); } }, sv('title', {}, title));
    const lbl = sv('text', { x: p.lx, y: p.ly - 4, class: 'cncount' + (dim ? ' dim' : '') }, `${KIND_TAG[e.kind] || e.kind} ${e.count}`);
    edgeEls.push({ e, path, hit, lbl });
    svg.append(path, hit, lbl);
  }
  spreadLabels();
  const conns = kindConns();
  for (const n of r.nodes) {
    const p = at[n.id];
    const on = CN.pick && (CN.pick.event != null ? picked.some((c) => c.from === n.id || c.to === n.id) : CN.pick.node === n.id);
    const cls = 'cnnode ' + (n.in_case ? 'host' : n.kind) + (on ? ' on' : '') + (CN.found && CN.found.has(n.id) ? ' found' : '');
    const count = conns.filter((c) => c.from === n.id || c.to === n.id).length;
    const title = `${n.label}${n.in_case ? ' (a host of the case)' : ''}: ${count} connection${count === 1 ? '' : 's'}` + (n.detail ? `. ${n.detail}` : '');
    const g = sv('g', { class: cls, transform: `translate(${p.x},${p.y})`, tabindex: 0, role: 'button', 'aria-label': title },
      sv('title', {}, title),
      sv('circle', { r: n.in_case ? 22 : 11 }),
      sv('text', { y: n.in_case ? 38 : 25, class: 'cnlabel' }, n.label));
    // Drag to move; a click without moving picks the node.
    let drag = null;
    g.addEventListener('pointerdown', (ev) => { drag = { x: ev.clientX, y: ev.clientY, moved: false }; g.setPointerCapture(ev.pointerId); ev.stopPropagation(); });
    g.addEventListener('pointermove', (ev) => {
      if (!drag) return;
      const scale = svg.viewBox.baseVal.width / svg.getBoundingClientRect().width;
      const dx = (ev.clientX - drag.x) * scale, dy = (ev.clientY - drag.y) * scale;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
      drag.x = ev.clientX; drag.y = ev.clientY;
      p.x = Math.max(20, Math.min(w - 20, p.x + dx)); p.y = Math.max(20, Math.min(hgt - 20, p.y + dy));
      g.setAttribute('transform', `translate(${p.x},${p.y})`);
      for (const x of edgeEls) {
        if (x.e.from !== n.id && x.e.to !== n.id) continue;
        const q = pathFor(x.e);
        x.path.setAttribute('d', q.d); x.hit.setAttribute('d', q.d);
      }
      spreadLabels();
      if (CN.pick && CN.pick.node === n.id) placeLeaves();
    });
    g.addEventListener('pointerup', (ev) => { const moved = drag && drag.moved; drag = null; ev.stopPropagation(); if (!moved) pickConn(on ? null : { node: n.id }); });
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') pickConn(on ? null : { node: n.id }); });
    g.addEventListener('click', (ev) => ev.stopPropagation());
    svg.append(g);
  }
  // A host picked opens into its accounts and USB storage devices, on the
  // side away from the middle; each opens its records on the timeline.
  const leafEls = [];
  const placeLeaves = () => {
    if (!leafEls.length) return;
    const p = at[CN.pick.node];
    const n = leafEls.length, arc = Math.min(Math.PI * 1.7, (n - 1) * 1.1), R = 115;
    const spots = (base) => leafEls.map((x, i) => {
      const a = base + (n > 1 ? -arc / 2 + (arc * i) / (n - 1) : 0);
      return { x: Math.max(60, Math.min(w - 60, p.x + R * Math.cos(a))), y: Math.max(16, Math.min(hgt - 24, p.y + R * Math.sin(a))) };
    });
    // The way round the host that is clearest of the other computers and
    // of the arrows' middles, where their labels are.
    const others = r.nodes.filter((o) => o.id !== CN.pick.node).map((o) => at[o.id]);
    for (const x of edgeEls) {
      const q = pathFor(x.e);
      others.push({ x: q.lx, y: q.ly });
    }
    let best = -Math.PI / 2, bestScore = -1;
    for (let k = 0; k < 24; k++) {
      const base = (2 * Math.PI * k) / 24;
      const score = Math.min(...spots(base).map((sp) => Math.min(200, ...others.map((o) => Math.hypot(o.x - sp.x, o.y - sp.y)))));
      if (score > bestScore + 1) { best = base; bestScore = score; }
    }
    spots(best).forEach((sp, i) => {
      const x = leafEls[i];
      x.line.setAttribute('x1', p.x); x.line.setAttribute('y1', p.y); x.line.setAttribute('x2', sp.x); x.line.setAttribute('y2', sp.y);
      x.g.setAttribute('transform', `translate(${sp.x},${sp.y})`);
    });
  };
  const host = CN.pick && CN.pick.node && r.nodes.find((n) => n.id === CN.pick.node && n.in_case);
  if (host) {
    const all = nodeLeaves(host.id);
    const shown = all.slice(0, 12);
    for (const l of shown) {
      const title = leafWords(l);
      const short = l.kind === 'account' ? l.label.replace(/^.*\\/, '') : l.label.replace(/ USB Device$/, '');
      const line = sv('line', { class: 'cnleafline' });
      const open = () => showEvents(l.events.map((e) => e.id));
      const g = sv('g', { class: 'cnleaf ' + l.kind, tabindex: 0, role: 'button', 'aria-label': title + '. Opens its records on the timeline.',
        onclick: (ev) => { ev.stopPropagation(); open(); }, onkeydown: (ev) => { if (ev.key === 'Enter') open(); } },
        sv('title', {}, title + '. Click for its records on the timeline.'),
        l.kind === 'device' ? sv('rect', { x: -6, y: -6, width: 12, height: 12, rx: 2 }) : sv('circle', { r: 6 }),
        sv('text', { y: 19, class: 'cnlabel' }, short.length > 20 ? short.slice(0, 19) + '…' : short));
      leafEls.push({ line, g });
      svg.insertBefore(line, svg.firstChild.nextSibling);
      svg.append(g);
    }
    if (all.length > shown.length) {
      const g = sv('text', { class: 'cnleafmore', x: at[host.id].x, y: at[host.id].y - 30 }, `+${all.length - shown.length} more in the list`);
      svg.append(g);
    }
    placeLeaves();
  }
  panGraph(svg, w, hgt);
  box.replaceChildren(svg);
}

// Dragging the background pans the graph and the wheel zooms it; a click
// on the background without moving shows everything again.
function panGraph(svg, w, hgt) {
  let drag = null;
  const scale = () => svg.viewBox.baseVal.width / (svg.getBoundingClientRect().width || w);
  const set = (vb) => { CN.vb = vb; svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.w} ${vb.h}`); };
  svg.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0 || ev.target.closest('.cnnode, .cnleaf, .cnhit')) return;
    drag = { x: ev.clientX, y: ev.clientY, moved: false, id: ev.pointerId };
  });
  svg.addEventListener('pointermove', (ev) => {
    if (!drag) return;
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
    if (!drag.moved) try { svg.setPointerCapture(drag.id); } catch (e) { /* a synthetic pointer */ }
    drag.moved = true;
    const k = scale(), vb = CN.vb || { x: 0, y: 0, w, h: hgt };
    set({ x: vb.x - dx * k, y: vb.y - dy * k, w: vb.w, h: vb.h });
    drag.x = ev.clientX; drag.y = ev.clientY;
    svg.classList.add('panning');
  });
  let panned = false;
  svg.addEventListener('pointerup', () => {
    panned = !!(drag && drag.moved);
    drag = null;
    svg.classList.remove('panning');
  });
  svg.addEventListener('click', () => {
    if (panned) { panned = false; return; }
    if (CN.pick) pickConn(null);
  });
  svg.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    const b = svg.getBoundingClientRect(), vb = CN.vb || { x: 0, y: 0, w, h: hgt };
    const fx = (ev.clientX - b.left) / b.width, fy = (ev.clientY - b.top) / b.height;
    set(zoomed(vb, ev.deltaY < 0 ? 1.2 : 1 / 1.2, vb.x + fx * vb.w, vb.y + fy * vb.h, w, hgt));
  }, { passive: false });
}

// zoomed is the view box vb zoomed by f about the point (cx, cy), no
// further out than the whole graph and no further in than eight times.
function zoomed(vb, f, cx, cy, w, hgt) {
  const nw = Math.min(w, Math.max(w / 8, vb.w / f)), nh = nw * (hgt / w);
  return { x: cx - (cx - vb.x) * (nw / vb.w), y: cy - (cy - vb.y) * (nh / vb.h), w: nw, h: nh };
}

function zoomGraph(how) {
  if (!CN.pos) return;
  const { w, h: hgt } = CN.pos;
  if (how === 'fit') CN.vb = null;
  else {
    const vb = CN.vb || { x: 0, y: 0, w, h: hgt };
    CN.vb = zoomed(vb, how === 'in' ? 1.3 : 1 / 1.3, vb.x + vb.w / 2, vb.y + vb.h / 2, w, hgt);
    if (CN.vb.w >= w) CN.vb = null;
  }
  drawConnections();
}

// ---- lanes ----
// One lane per computer, time across; an arrow for each connection, from
// the lane of the computer connecting to the lane of the one connected to.
function drawLanes(box, r) {
  const conns = kindConns();
  const lanes = r.nodes.filter((n) => n.in_case || r.connections.some((c) => c.from === n.id || c.to === n.id));
  const left = 150, right = 30, top = 28, laneH = 46;
  const w = Math.max(560, box.clientWidth || 800), hgt = top + lanes.length * laneH + 10;
  const y = Object.fromEntries(lanes.map((n, i) => [n.id, top + i * laneH + laneH / 2]));
  const svg = sv('svg', { class: 'cnlanes', viewBox: `0 0 ${w} ${hgt}`, width: w, height: hgt, role: 'img', 'aria-label': 'Connections in time, one lane per computer' });
  svg.append(sv('defs', {}, ...['strong', 'possible', 'oneend'].map((k) =>
    sv('marker', { id: 'cnlarrow-' + k, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: 'userSpaceOnUse', orient: 'auto-start-reverse' },
      sv('path', { d: 'M0,0 L10,5 L0,10 z', class: 'cnarrowhead ' + k })))));
  lanes.forEach((n, i) => {
    svg.append(sv('rect', { x: 0, y: top + i * laneH, width: w, height: laneH, class: 'cnlane' + (i % 2 ? ' odd' : '') }),
      sv('text', { x: 10, y: y[n.id] + 4, class: 'cnlanelabel' + (n.in_case ? ' host' : '') }, n.label));
  });
  if (!conns.length) { box.replaceChildren(svg); return; }
  // The time across is that of every kind, so it stays put when the kind
  // shown changes. Connections with no time (a registry key's last write
  // alone) do not set it: one written weeks before would squash the rest;
  // outside it they are drawn at its edge.
  // A period chosen is the time across, edge to edge.
  const timed = r.connections.filter((c) => !c.undated);
  const basis = timed.length ? timed : r.connections;
  let t0 = BigInt(basis[0].start_utc), t1 = t0;
  for (const c of basis) {
    const t = BigInt(c.start_utc); if (t < t0) t0 = t; if (t > t1) t1 = t;
    if (c.ended_utc) { const e = BigInt(c.ended_utc); if (e > t1) t1 = e; }
  }
  const rg = CN.range;
  if (rg && rg.from != null && rg.to != null) { t0 = rg.from; t1 = rg.to + 1n; } else {
    const pad = (t1 - t0) / 20n + 60000000000n;
    t0 -= pad; t1 += pad;
    if (rg && rg.from != null) t0 = rg.from;
    if (rg && rg.to != null) t1 = rg.to + 1n;
    if (t1 <= t0) t1 = t0 + 60000000000n;
  }
  const span = Number(t1 - t0);
  const x = (ns) => {
    let t = BigInt(ns);
    if (t < t0) t = t0; else if (t > t1) t = t1;
    return left + (Number(t - t0) / span) * (w - left - right);
  };
  // Time marks, on whole minutes, hours or days.
  const steps = [1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200, 21600, 43200, 86400, 604800].map((s) => s * 1e9);
  const step = steps.find((s) => span / s <= 8) || steps[steps.length - 1];
  const stepN = BigInt(step);
  const sameDay = fmtNs(t0, 0).slice(0, 10) === fmtNs(t1, 0).slice(0, 10);
  for (let t = (t0 / stepN + 1n) * stepN; t < t1; t += stepN) {
    const s = fmtNs(t, 0);
    svg.append(sv('line', { x1: x(t), x2: x(t), y1: top - 4, y2: hgt - 6, class: 'cntick' }),
      sv('text', { x: x(t), y: top - 9, class: 'cnticklabel' }, step < 60e9 ? s.slice(11, 19) : sameDay && step < 86400e9 ? s.slice(11, 16) : step < 86400e9 ? s.slice(5, 16) : s.slice(0, 10)));
  }
  // A Remote Desktop session's length, as a bar along the lane of the
  // computer connected to, under the arrows.
  for (const c of conns) {
    if (!c.ended_utc || y[c.to] == null) continue;
    const x1 = x(c.start_utc), x2 = Math.max(x1 + 2, x(c.ended_utc));
    const dim = CN.pick && !pickedConns().includes(c);
    svg.append(sv('rect', { x: x1, y: y[c.to] + 7, width: x2 - x1, height: 6, rx: 2, class: 'cnsession' + (dim ? ' dim' : '') },
      sv('title', {}, `Session on ${cnLabel(c.to)} from ${fmtNs(c.start_utc, 0)}${x1 <= left ? ' (before the period shown)' : ''} until ${c.end_how} at ${fmtNs(c.ended_utc, 0)} UTC (${sessionLength(c)})`)));
  }
  // A connection made before the period shown is there for its session:
  // its bar is drawn from the edge, not its arrow.
  const before = (c) => CN.range && CN.range.from != null && BigInt(c.start_utc) < CN.range.from;
  for (const c of conns) {
    if (y[c.from] == null || y[c.to] == null || before(c)) continue;
    const kind = c.confidence === 'strong' ? 'strong' : c.confidence === 'possible' ? 'possible' : 'oneend';
    const cx = x(c.start_utc), y1 = y[c.from], y2 = y[c.to];
    const dir = y2 > y1 ? 1 : -1;
    const on = CN.selected === c;
    const dim = CN.pick && !pickedConns().includes(c);
    const title = `${connWhen(c)}  ${KIND_WORDS[c.kind] || c.kind}  ${cnLabel(c.from)} → ${cnLabel(c.to)}${c.account ? '  ' + c.account : ''}: ${CONF_WORDS[c.confidence]}, seen at ${SEEN_WORDS[c.seen_on]}`;
    const g = sv('g', { class: 'cnconn ' + kind + (c.undated ? ' undated' : '') + (on ? ' on' : '') + (dim ? ' dim' : ''), tabindex: 0, role: 'button', 'aria-label': title,
      onclick: () => selectConn(c), onkeydown: (ev) => { if (ev.key === 'Enter') selectConn(c); } },
      sv('title', {}, title),
      sv('line', { x1: cx, x2: cx, y1: y1 + dir * 6, y2: y2 - dir * 8, class: 'cnconnline', 'marker-end': `url(#cnlarrow-${kind})` }),
      sv('text', { x: cx + 5, y: (y1 + y2) / 2 + 3, class: 'cnkindtag' }, KIND_TAG[c.kind] || c.kind),
      // A filled dot where that end's evidence was found, hollow where none was.
      sv('circle', { cx, cy: y1, r: 4.5, class: c.source ? 'cnend' : 'cnend missing' }),
      sv('circle', { cx, cy: y2, r: 4.5, class: c.target ? 'cnend' : 'cnend missing' }),
      sv('line', { x1: cx, x2: cx, y1, y2, class: 'cnhitline' }));
    svg.append(g);
  }
  brushLanes(svg, { left, right, top, w, hgt, t0, span });
  box.replaceChildren(svg);
}

// Dragging across the lanes, away from a connection, chooses that period.
function brushLanes(svg, a) {
  let start = null, band = null;
  const px = (ev) => {
    const b = svg.getBoundingClientRect();
    return Math.min(a.w - a.right, Math.max(a.left, (ev.clientX - b.left) * (a.w / (b.width || a.w))));
  };
  const at = (p) => a.t0 + BigInt(Math.round(((p - a.left) / (a.w - a.left - a.right)) * a.span));
  svg.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0 || ev.target.closest('.cnconn')) return;
    start = px(ev);
    band = sv('rect', { x: start, y: a.top - 4, width: 0, height: a.hgt - a.top, class: 'cnbrush' });
    svg.append(band);
    if (svg.setPointerCapture) try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* a synthetic pointer */ }
  });
  svg.addEventListener('pointermove', (ev) => {
    if (start == null) return;
    const p = px(ev);
    band.setAttribute('x', Math.min(start, p));
    band.setAttribute('width', Math.abs(p - start));
  });
  const done = (ev) => {
    if (start == null) return;
    const p = px(ev), s = start;
    start = null;
    band.remove();
    if (Math.abs(p - s) < 6) return;
    setCnRange(at(Math.min(s, p)), at(Math.max(s, p)));
  };
  svg.addEventListener('pointerup', done);
  svg.addEventListener('pointercancel', () => { if (band) band.remove(); start = null; });
}

// How long a session lasted, from the connection's start to its end.
function sessionLength(c) {
  const s = Math.max(0, Number((BigInt(c.ended_utc) - BigInt(c.start_utc)) / 1000000000n));
  if (s < 90) return `${s} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  const hrs = Math.floor(s / 3600), min = Math.round((s % 3600) / 60);
  return min ? `${hrs} h ${min} min` : `${hrs} h`;
}

function selectConn(c) {
  CN.selected = CN.selected === c ? null : c;
  drawConnections();
  if (CN.selected) {
    const row = document.querySelector('.cnrow.on');
    if (row) row.scrollIntoView({ block: 'nearest' });
  }
}

// ---- the list ----
function drawConnRows() {
  const r = CN.rep;
  const list = pickedConns();
  const out = [];
  if (CN.pick) {
    out.push(h('p', { class: 'hint cnpicked' }, CN.pick.event != null ? `Connections that event #${CN.pick.event} is part of (${CN.pick.what})`
      : CN.pick.node ? `Connections to and from ${cnLabel(CN.pick.node)}` : `${KIND_WORDS[CN.pick.kind] || ''} connections from ${cnLabel(CN.pick.from)} to ${cnLabel(CN.pick.to)}`));
  }
  for (const c of list) {
    const on = CN.selected === c;
    const ends = [];
    for (const [label, e] of [['On ' + cnLabel(c.from), c.source], ['On ' + cnLabel(c.to), c.target]]) {
      if (!e) { ends.push(h('div', { class: 'cnendrow dimc' }, label + ': nothing recorded in the evidence added')); continue; }
      if (!e.events.length) { ends.push(h('div', { class: 'cnendrow dimc' }, label + ': the file itself, collected as evidence (the reasons name the item); no record of it with a time')); continue; }
      const corrected = e.corrected_utc !== e.start_utc;
      ends.push(h('div', { class: 'cnendrow' },
        h('b', {}, label + ': '), `${e.events.length} event${e.events.length === 1 ? '' : 's'} from `, h('span', { class: 'mono' }, fmtNs(e.start_utc, 0)),
        corrected ? h('span', { class: 'dimc' }, ` by its clock, ${fmtNs(e.corrected_utc, 0)} corrected`) : '',
        e.account ? `  ·  ${e.account}` : '',
        h('ul', { class: 'cnevents' }, ...e.events.map((ev) => h('li', {}, h('span', { class: 'mono' }, fmtNs(ev.ts_utc, 0)), ' ', ev.what, ' ',
          h('button', { class: 'link', onclick: () => showEvents([ev.id]) }, `#${ev.id}`))))));
    }
    if (c.named && c.named.length) {
      ends.push(h('div', { class: 'cnendrow' },
        h('b', {}, `Also named in ${cnLabel(c.from)}'s registry: `), h('span', { class: 'dimc' }, 'the time is the key\'s last write, not a connection\'s'),
        h('ul', { class: 'cnevents' }, ...c.named.map((ev) => h('li', {}, h('span', { class: 'mono' }, fmtNs(ev.ts_utc, 0)), ' ', ev.what, ' ',
          h('button', { class: 'link', onclick: () => showEvents([ev.id]) }, `#${ev.id}`))))));
    }
    out.push(h('div', { class: 'anrow cnrow' + (on ? ' on' : '') },
      h('div', { class: 'anpath' },
        h('span', { class: 'mono' }, c.no_time && c.start_utc === '0' ? 'no time' : fmtNs(c.start_utc, 0)),
        h('span', { class: 'chip static cnkind' }, KIND_WORDS[c.kind] || c.kind),
        h('span', {}, cnLabel(c.from), ' → ', cnLabel(c.to)),
        c.account ? h('span', { class: 'dimc' }, c.account) : '',
        h('span', { class: 'chip static cnconf ' + (c.confidence === 'one-end' ? 'oneend' : c.confidence) }, CONF_WORDS[c.confidence]),
        c.ended_utc ? h('span', { class: 'chip static cnsess', title: `The session ${c.end_how === 'logged off' ? 'was logged off' : 'was disconnected, and no logoff was found'} at ${fmtNs(c.ended_utc, 0)} UTC` }, `${c.end_how === 'logged off' ? 'session' : 'until disconnected'} ${sessionLength(c)}`) : '',
        c.undated ? h('span', { class: 'chip static cnconf undated', title: c.no_time ? `No time: ${c.no_time}` : 'Only the registry names this connection, and its time is when a key was last written, not when the connection was made' }, 'no time') : '',
        h('span', { class: 'dimc' }, 'seen at ' + SEEN_WORDS[c.seen_on])),
      h('ul', { class: 'annotes' }, ...c.reasons.map((x) => h('li', {}, x))),
      on ? h('div', { class: 'cnends' }, ...ends) : '',
      h('div', { class: 'cnactions' },
        h('button', { class: 'link', onclick: () => selectConn(c) }, on ? 'Hide the events' : 'Each end\'s events'),
        c.event_ids.length ? h('button', { class: 'link', onclick: () => showEvents(c.event_ids) }, `Show the ${c.event_ids.length} event${c.event_ids.length === 1 ? '' : 's'} on the timeline`) : '')));
  }
  if (!list.length && CN.pick && CN.pick.event != null) {
    out.push(h('p', { class: 'anempty' }, `Event #${CN.pick.event} is not part of any connection. Network logons and connections to file sharing support a connection but are not shown on their own, and records of a host's own work (a service, task or WMI program with no network logon near it) are taken as local: the notes in the side panel list those.`));
  } else if (!list.length) out.push(h('p', { class: 'anempty' }, !r.events ? 'No records of connections have been found in the evidence yet. Add the hosts\' Security, System and Terminal Services logs.' : CN.kind ? 'No connections of this kind were found.' : 'No connections were found.'));
  $('cnrows').replaceChildren(...out);
}

function setupConnections() {
  $('cnmode').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) setCnMode(b.dataset.mode); });
  $('cnkind').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) setCnKind(b.dataset.kind); });
  $('cnrun').onclick = loadConnections;
  $('cnall').onclick = () => pickConn(null);
  for (const id of ['cnfrom', 'cnto']) {
    $(id).addEventListener('change', applyCnRange);
    $(id).addEventListener('keydown', (ev) => { if (ev.key === 'Enter') applyCnRange(); });
  }
  $('cnwhole').onclick = () => setCnRange(null, null);
  let ft;
  $('cnsearch').addEventListener('input', (ev) => { clearTimeout(ft); ft = setTimeout(() => findConns(ev.target.value), 200); });
  $('cnzoom').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) zoomGraph(b.dataset.zoom); });
  $('cnwrap').classList.add('graph');
  let rt;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => { if (S.view === 'connections' && CN.rep) { CN.pos = null; drawConnections(); } }, 200); });
}

// ---- the side panel ----
function drawSide() {
  const r = CN.rep;
  if (!r) return;
  drawSelected();
  $('cnnotes').replaceChildren(...r.notes.map((n) => h('li', {}, n)));
  $('cnnotescount').textContent = fmtInt(r.notes.length);
  const read = r.read || [];
  const done = read.filter((x) => x.done).length;
  $('cnreadcount').textContent = `${done} kinds, ${read.length - done} not yet`;
  $('cnread').replaceChildren(...read.map((x) => h('li', { class: x.done ? 'done' : 'todo' },
    h('span', { class: 'cntick', 'aria-label': x.done ? 'read' : 'not read yet' }, x.done ? '✓' : '–'),
    h('div', {}, h('b', {}, x.what),
      ...[['On the computer connecting', x.connecting], ['On the computer connected to', x.connected_to], ['', x.either]]
        .filter(([, l]) => l && l.length).map(([k, l]) => h('div', { class: 'cnreadline' }, k ? h('span', { class: 'dimc' }, k + ': ') : '', l.join('; '))),
      x.why ? h('div', { class: 'cnreadline dimc' }, x.done ? x.why : 'Not read yet: ' + x.why) : ''))));
  $('cnrules').replaceChildren(...(r.rules || []).map((n) => h('li', {}, n)));
}

// What is picked: a host with its names, addresses, accounts and devices;
// an arrow; or an event of the timeline.
function drawSelected() {
  const r = CN.rep, p = CN.pick, box = $('cnsel');
  const head = h('div', { class: 'cncardhead' }, 'Selected');
  if (!p) {
    box.replaceChildren(head, h('p', { class: 'hint cnselhint' }, 'Click a host or an arrow on the graph, or find one above. A host of the case opens into its accounts and USB storage devices; drag the background to move about, and the wheel or the buttons to zoom.'));
    return;
  }
  const list = pickedConns();
  const ids = [...new Set(list.flatMap((c) => c.event_ids))].sort((a, b) => a - b);
  const props = [];
  let name;
  if (p.node) {
    const n = r.nodes.find((x) => x.id === p.node) || { label: p.node };
    const hi = (r.hosts || []).find((x) => 'host:' + x.name === p.node);
    name = n.label;
    props.push(['Is', n.in_case ? 'a host of the case' : ({ address: 'an address outside the case', computer: 'a computer outside the case', loopback: 'this computer, by its loopback address' }[n.kind] || n.kind)]);
    if (hi) {
      if (hi.names && hi.names.length > 1) props.push(['Names', hi.names.join(', ')]);
      const ips = [...new Set([...(hi.ips || []), ...(hi.hive_ips || []).map((f) => f.value)])];
      if (ips.length) props.push(['Addresses', ips.join(', ')]);
      if (hi.clock_text) props.push(['Clock', hi.clock_text]);
    }
    if (n.detail) props.push(['Note', n.detail]);
    props.push(['Connections', `${fmtInt(list.filter((c) => c.to === p.node).length)} to it, ${fmtInt(list.filter((c) => c.from === p.node).length)} from it`]);
  } else if (p.event != null) {
    name = `Event #${p.event}`;
    props.push(['Is', p.what || '']);
    props.push(['Connections', fmtInt(list.length)]);
  } else {
    name = `${cnLabel(p.from)} → ${cnLabel(p.to)}`;
    props.push(['Kind', KIND_WORDS[p.kind] || p.kind]);
    props.push(['Connections', `${fmtInt(list.length)}: ${fmtInt(list.filter((c) => c.confidence === 'strong').length)} strong, ${fmtInt(list.filter((c) => c.confidence === 'possible').length)} possible, ${fmtInt(list.filter((c) => c.confidence === 'one-end').length)} at one end only`]);
  }
  const timed = list.filter((c) => !c.undated).map((c) => BigInt(c.start_utc)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (timed.length) props.push(['Time', fmtNs(timed[0], 0) + (timed.length > 1 && timed[timed.length - 1] !== timed[0] ? ' to ' + fmtNs(timed[timed.length - 1], 0) : '') + ' UTC']);
  const leaves = p.node ? nodeLeaves(p.node) : [];
  box.replaceChildren(head, h('div', { class: 'cnselname' }, name),
    h('dl', { class: 'cnprops' }, ...props.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
    leaves.length ? h('div', { class: 'cnleaves' }, ...[['account', 'Accounts of its connections'], ['device', 'USB storage devices in its SYSTEM hive']].map(([k, title]) => {
      const ls = leaves.filter((l) => l.kind === k);
      return ls.length ? h('div', {}, h('div', { class: 'cnsubhead' }, title), h('ul', { class: 'cnevents' }, ...ls.map((l) => h('li', {}, leafWords(l).replace(/^(Account|USB storage device) /, ''), ' ',
        h('button', { class: 'link', onclick: () => showEvents(l.events.map((e) => e.id)) }, `its ${l.events.length} record${l.events.length === 1 ? '' : 's'}`))))) : '';
    })) : '',
    ids.length ? h('div', { class: 'cnselact' }, h('button', { class: 'link', onclick: () => showEvents(ids) }, `Show their ${fmtInt(ids.length)} events on the timeline`)) : '');
}

// ---- finding ----
// Hosts and addresses by name, other names and addresses; accounts and
// devices by name and serial; connections by account and by what their
// reasons name (paths, hashes, shares, services).
function findConns(q) {
  q = q.trim().toLowerCase();
  CN.q = q;
  const r = CN.rep, out = [], found = new Set();
  if (r && q.length >= 2) {
    const has = (...xs) => xs.some((x) => x && String(x).toLowerCase().includes(q));
    for (const n of r.nodes) {
      const hi = (r.hosts || []).find((x) => 'host:' + x.name === n.id);
      if (has(n.label, ...(hi ? [...(hi.names || []), ...(hi.ips || []), ...(hi.hive_ips || []).map((f) => f.value)] : []))) {
        found.add(n.id);
        out.push({ label: n.label, what: n.in_case ? 'host' : 'outside the case', go: () => pickConn({ node: n.id }) });
      }
    }
    for (const l of r.leaves || []) {
      if (has(l.label, l.detail)) {
        found.add(l.node);
        out.push({ label: l.label, what: `${l.kind === 'device' ? 'USB device' : 'account'} on ${cnLabel(l.node)}`, go: () => pickConn({ node: l.node }) });
      }
    }
    for (const c of r.connections) {
      if (has(c.account, ...c.reasons)) {
        found.add(c.from); found.add(c.to);
        out.push({ label: `${c.undated ? 'no time' : fmtNs(c.start_utc, 0).slice(5, 16)}  ${cnLabel(c.from)} → ${cnLabel(c.to)}`, what: KIND_WORDS[c.kind] || c.kind, go: () => showConn(c) });
      }
    }
  }
  CN.found = q.length >= 2 ? found : null;
  const shown = out.slice(0, 40);
  $('cnfound').replaceChildren(...(q.length < 2 ? [] : !out.length ? [h('p', { class: 'hint' }, 'Nothing found.')]
    : [h('p', { class: 'hint' }, `${fmtInt(out.length)} found${out.length > shown.length ? `, the first ${shown.length} listed` : ''}`),
      h('ul', { class: 'cnfoundlist' }, ...shown.map((x) => h('li', {}, h('button', { class: 'cnfounditem', onclick: x.go }, h('span', {}, x.label), h('i', {}, x.what)))))]));
  if (CN.rep && CN.mode === 'graph') drawConnections();
}

// Opens one connection in the list, showing every kind and time if it is
// hidden by them.
function showConn(c) {
  CN.pick = null;
  $('cnall').hidden = true;
  if (CN.kind && CN.kind !== c.kind) setCnKind('');
  if (!inRange(c)) setCnRange(null, null);
  CN.selected = null;
  selectConn(c);
}
