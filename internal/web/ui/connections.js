// Atropos: the Connections view. Loaded before app.js, whose helpers (h,
// api, $, fmtNs, fmtInt, showEvents, toast, fail) it uses only when called.
//
// Everything drawn comes from evidence, which may be hostile: labels are
// text nodes, never markup, and all SVG is built with createElementNS.
'use strict';

let connectionsLoaded = false;
const CN = { mode: 'graph', rep: null, pick: null, pos: null, selected: null };

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

function cnLabel(id) {
  const n = CN.rep && CN.rep.nodes.find((x) => x.id === id);
  return n ? n.label : id;
}

function setCnMode(m) {
  CN.mode = m;
  for (const b of $('cnmode').children) b.classList.toggle('on', b.dataset.mode === m);
  drawConnections();
}

async function loadConnections() {
  connectionsLoaded = true;
  $('cnsummary').replaceChildren('Reading…');
  try {
    const r = await api('/api/analysis/connections');
    CN.rep = r;
    CN.pos = null;
    const both = r.connections.filter((c) => c.seen_on === 'both').length;
    const hosts = r.nodes.filter((n) => n.in_case).length;
    $('cnsummary').replaceChildren(h('b', {}, fmtInt(r.connections.length)), r.connections.length === 1 ? ' connection' : ' connections',
      ` (${fmtInt(both)} seen at both ends) between ${fmtInt(hosts)} host${hosts === 1 ? '' : 's'} and ${fmtInt(r.nodes.length - hosts)} other computer${r.nodes.length - hosts === 1 ? '' : 's'} or address${r.nodes.length - hosts === 1 ? '' : 'es'}`,
      r.ready ? '' : ' (still reading some evidence)');
    drawConnections();
  } catch (e) { $('cnsummary').replaceChildren('The connections could not be read'); fail(e); }
}

// pickConn narrows the list to a node or an edge; null shows everything.
function pickConn(p) {
  CN.pick = p;
  $('cnall').hidden = !p;
  drawConnections();
}

function pickedConns() {
  const all = CN.rep ? CN.rep.connections : [];
  const p = CN.pick;
  if (!p) return all;
  if (p.node) return all.filter((c) => c.from === p.node || c.to === p.node);
  return all.filter((c) => c.from === p.from && c.to === p.to);
}

function drawConnections() {
  const r = CN.rep;
  const box = $('cncanvas');
  if (!r) { box.replaceChildren(); return; }
  if (!r.nodes.length) {
    box.replaceChildren(h('p', { class: 'anempty' }, 'No hosts are described yet. Describe them on the Details tab, with their addresses, then add their logs.'));
  } else if (CN.mode === 'graph') drawGraph(box, r);
  else drawLanes(box, r);
  drawLegend();
  drawConnRows();
}

function drawLegend() {
  $('cnlegend').replaceChildren(
    h('span', { class: 'cnkey strong' }, 'strong: both ends, within a minute, the same account'),
    h('span', { class: 'cnkey possible' }, 'possible: both ends, further apart or different accounts'),
    h('span', { class: 'cnkey oneend' }, 'one end only'),
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
  const w = Math.max(480, box.clientWidth || 800), hgt = 380;
  if (!CN.pos || CN.pos.w !== w) CN.pos = { w, at: layoutGraph(r, w, hgt) };
  const at = CN.pos.at;
  const svg = sv('svg', { class: 'cngraph', viewBox: `0 0 ${w} ${hgt}`, width: w, height: hgt, role: 'img', 'aria-label': 'Graph of connections' });
  const defs = sv('defs', {}, ...['strong', 'possible', 'oneend'].map((k) =>
    sv('marker', { id: 'cnarrow-' + k, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 10, markerHeight: 10, markerUnits: 'userSpaceOnUse', orient: 'auto-start-reverse' },
      sv('path', { d: 'M0,0 L10,5 L0,10 z', class: 'cnarrowhead ' + k }))));
  svg.append(defs);
  const rad = (id) => (r.nodes.find((x) => x.id === id) || {}).in_case ? 22 : 11;
  const edgeEls = [];
  const pathFor = (e) => {
    const a = at[e.from], b = at[e.to];
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
    // Bend the edge when the other direction is drawn too, so both show.
    const twin = r.edges.some((x) => x.from === e.to && x.to === e.from);
    const bend = twin ? 28 : 0;
    const mx = (a.x + b.x) / 2 - (dy / d) * bend, my = (a.y + b.y) / 2 + (dx / d) * bend;
    const ra = rad(e.from) + 3, rb = rad(e.to) + 5;
    const ax = a.x + ((mx - a.x) / Math.hypot(mx - a.x, my - a.y)) * ra, ay = a.y + ((my - a.y) / Math.hypot(mx - a.x, my - a.y)) * ra;
    const bx = b.x - ((b.x - mx) / Math.hypot(b.x - mx, b.y - my)) * rb, by = b.y - ((b.y - my) / Math.hypot(b.x - mx, b.y - my)) * rb;
    return { d: `M${ax},${ay} Q${mx},${my} ${bx},${by}`, lx: (ax + 2 * mx + bx) / 4, ly: (ay + 2 * my + by) / 4 };
  };
  for (const e of r.edges) {
    const kind = e.strong ? 'strong' : e.possible ? 'possible' : 'oneend';
    const p = pathFor(e);
    const on = CN.pick && CN.pick.from === e.from && CN.pick.to === e.to;
    const dim = CN.pick && CN.pick.node && e.from !== CN.pick.node && e.to !== CN.pick.node;
    const title = `${cnLabel(e.from)} → ${cnLabel(e.to)}: ${e.count} Remote Desktop connection${e.count === 1 ? '' : 's'}` +
      ` (${e.strong} strong, ${e.possible} possible, ${e.one_end} seen at one end only), ${fmtNs(e.first_utc, 0)}` + (e.last_utc !== e.first_utc ? ` to ${fmtNs(e.last_utc, 0)}` : '') + ' UTC';
    const path = sv('path', { d: p.d, class: edgeClass(e) + (on ? ' on' : '') + (dim ? ' dim' : ''), 'stroke-width': Math.min(6, 1.6 + Math.log2(e.count)), 'marker-end': `url(#cnarrow-${kind})` });
    const hit = sv('path', { d: p.d, class: 'cnhit', tabindex: 0, role: 'button', 'aria-label': title,
      onclick: (ev) => { ev.stopPropagation(); pickConn({ from: e.from, to: e.to }); },
      onkeydown: (ev) => { if (ev.key === 'Enter') pickConn({ from: e.from, to: e.to }); } }, sv('title', {}, title));
    const lbl = sv('text', { x: p.lx, y: p.ly - 4, class: 'cncount' + (dim ? ' dim' : '') }, String(e.count));
    edgeEls.push({ e, path, hit, lbl });
    svg.append(path, hit, lbl);
  }
  for (const n of r.nodes) {
    const p = at[n.id];
    const on = CN.pick && CN.pick.node === n.id;
    const cls = 'cnnode ' + (n.in_case ? 'host' : n.kind) + (on ? ' on' : '');
    const count = r.connections.filter((c) => c.from === n.id || c.to === n.id).length;
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
      const scale = w / svg.getBoundingClientRect().width;
      const dx = (ev.clientX - drag.x) * scale, dy = (ev.clientY - drag.y) * scale;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
      drag.x = ev.clientX; drag.y = ev.clientY;
      p.x = Math.max(20, Math.min(w - 20, p.x + dx)); p.y = Math.max(20, Math.min(hgt - 20, p.y + dy));
      g.setAttribute('transform', `translate(${p.x},${p.y})`);
      for (const x of edgeEls) {
        if (x.e.from !== n.id && x.e.to !== n.id) continue;
        const q = pathFor(x.e);
        x.path.setAttribute('d', q.d); x.hit.setAttribute('d', q.d);
        x.lbl.setAttribute('x', q.lx); x.lbl.setAttribute('y', q.ly - 4);
      }
    });
    g.addEventListener('pointerup', (ev) => { const moved = drag && drag.moved; drag = null; ev.stopPropagation(); if (!moved) pickConn(on ? null : { node: n.id }); });
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') pickConn(on ? null : { node: n.id }); });
    svg.append(g);
  }
  svg.addEventListener('click', () => { if (CN.pick) pickConn(null); });
  box.replaceChildren(svg);
}

// ---- lanes ----
// One lane per computer, time across; an arrow for each connection, from
// the lane of the computer connecting to the lane of the one connected to.
function drawLanes(box, r) {
  const conns = r.connections;
  const lanes = r.nodes.filter((n) => n.in_case || conns.some((c) => c.from === n.id || c.to === n.id));
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
  let t0 = BigInt(conns[0].start_utc), t1 = t0;
  for (const c of conns) { const t = BigInt(c.start_utc); if (t < t0) t0 = t; if (t > t1) t1 = t; }
  const pad = (t1 - t0) / 20n + 60000000000n;
  t0 -= pad; t1 += pad;
  const span = Number(t1 - t0);
  const x = (ns) => left + (Number(BigInt(ns) - t0) / span) * (w - left - right);
  // Time marks, on whole minutes, hours or days.
  const steps = [60, 300, 600, 1800, 3600, 7200, 21600, 43200, 86400, 604800].map((s) => s * 1e9);
  const step = steps.find((s) => span / s <= 8) || steps[steps.length - 1];
  const stepN = BigInt(step);
  const sameDay = fmtNs(t0, 0).slice(0, 10) === fmtNs(t1, 0).slice(0, 10);
  for (let t = (t0 / stepN + 1n) * stepN; t < t1; t += stepN) {
    const s = fmtNs(t, 0);
    svg.append(sv('line', { x1: x(t), x2: x(t), y1: top - 4, y2: hgt - 6, class: 'cntick' }),
      sv('text', { x: x(t), y: top - 9, class: 'cnticklabel' }, sameDay && step < 86400e9 ? s.slice(11, 16) : step < 86400e9 ? s.slice(5, 16) : s.slice(0, 10)));
  }
  for (const c of conns) {
    if (y[c.from] == null || y[c.to] == null) continue;
    const kind = c.confidence === 'strong' ? 'strong' : c.confidence === 'possible' ? 'possible' : 'oneend';
    const cx = x(c.start_utc), y1 = y[c.from], y2 = y[c.to];
    const dir = y2 > y1 ? 1 : -1;
    const on = CN.selected === c;
    const dim = CN.pick && !pickedConns().includes(c);
    const title = `${fmtNs(c.start_utc, 0)} UTC  ${cnLabel(c.from)} → ${cnLabel(c.to)}${c.account ? '  ' + c.account : ''}: ${CONF_WORDS[c.confidence]}, seen at ${SEEN_WORDS[c.seen_on]}`;
    const g = sv('g', { class: 'cnconn ' + kind + (on ? ' on' : '') + (dim ? ' dim' : ''), tabindex: 0, role: 'button', 'aria-label': title,
      onclick: () => selectConn(c), onkeydown: (ev) => { if (ev.key === 'Enter') selectConn(c); } },
      sv('title', {}, title),
      sv('line', { x1: cx, x2: cx, y1: y1 + dir * 6, y2: y2 - dir * 8, class: 'cnconnline', 'marker-end': `url(#cnlarrow-${kind})` }),
      // A filled dot where that end's evidence was found, hollow where none was.
      sv('circle', { cx, cy: y1, r: 4.5, class: c.source ? 'cnend' : 'cnend missing' }),
      sv('circle', { cx, cy: y2, r: 4.5, class: c.target ? 'cnend' : 'cnend missing' }),
      sv('line', { x1: cx, x2: cx, y1, y2, class: 'cnhitline' }));
    svg.append(g);
  }
  box.replaceChildren(svg);
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
    out.push(h('p', { class: 'hint cnpicked' }, CN.pick.node ? `Connections to and from ${cnLabel(CN.pick.node)}` : `Connections from ${cnLabel(CN.pick.from)} to ${cnLabel(CN.pick.to)}`));
  }
  for (const c of list) {
    const on = CN.selected === c;
    const ends = [];
    for (const [label, e] of [['On ' + cnLabel(c.from), c.source], ['On ' + cnLabel(c.to), c.target]]) {
      if (!e) { ends.push(h('div', { class: 'cnendrow dimc' }, label + ': nothing recorded in the evidence added')); continue; }
      const corrected = e.corrected_utc !== e.start_utc;
      ends.push(h('div', { class: 'cnendrow' },
        h('b', {}, label + ': '), `${e.events.length} event${e.events.length === 1 ? '' : 's'} from `, h('span', { class: 'mono' }, fmtNs(e.start_utc, 0)),
        corrected ? h('span', { class: 'dimc' }, ` by its clock, ${fmtNs(e.corrected_utc, 0)} corrected`) : '',
        e.account ? `  ·  ${e.account}` : '',
        h('ul', { class: 'cnevents' }, ...e.events.map((ev) => h('li', {}, h('span', { class: 'mono' }, fmtNs(ev.ts_utc, 0)), ' ', ev.what, ' ',
          h('button', { class: 'link', onclick: () => showEvents([ev.id]) }, `#${ev.id}`))))));
    }
    out.push(h('div', { class: 'anrow cnrow' + (on ? ' on' : '') },
      h('div', { class: 'anpath' },
        h('span', { class: 'mono' }, fmtNs(c.start_utc, 0)),
        h('span', {}, cnLabel(c.from), ' → ', cnLabel(c.to)),
        c.account ? h('span', { class: 'dimc' }, c.account) : '',
        h('span', { class: 'chip static cnconf ' + (c.confidence === 'one-end' ? 'oneend' : c.confidence) }, CONF_WORDS[c.confidence]),
        h('span', { class: 'dimc' }, 'seen at ' + SEEN_WORDS[c.seen_on])),
      h('ul', { class: 'annotes' }, ...c.reasons.map((x) => h('li', {}, x))),
      on ? h('div', { class: 'cnends' }, ...ends) : '',
      h('div', { class: 'cnactions' },
        h('button', { class: 'link', onclick: () => selectConn(c) }, on ? 'Hide the events' : 'Each end\'s events'),
        h('button', { class: 'link', onclick: () => showEvents(c.event_ids) }, `Show the ${c.event_ids.length} event${c.event_ids.length === 1 ? '' : 's'} on the timeline`))));
  }
  if (!list.length) out.push(h('p', { class: 'anempty' }, r.events ? 'No connections were found.' : 'No Remote Desktop records have been found in the evidence yet. Add the hosts\' Security and Terminal Services logs.'));
  out.push(h('div', { class: 'anhead' }, h('h3', {}, 'Notes'), h('ul', { class: 'annotes' }, ...r.notes.map((n) => h('li', {}, n)))));
  $('cnrows').replaceChildren(...out);
}

function setupConnections() {
  $('cnmode').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) setCnMode(b.dataset.mode); });
  $('cnrun').onclick = loadConnections;
  $('cnall').onclick = () => pickConn(null);
  let rt;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => { if (S.view === 'connections' && CN.rep) { CN.pos = null; drawConnections(); } }, 200); });
}
