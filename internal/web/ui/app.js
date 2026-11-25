// Atropos interface. No build step and no dependencies.
//
// Everything shown here comes from evidence, which may be hostile. Nothing is
// ever inserted as HTML: all text goes through textContent or createTextNode.
'use strict';

const $ = (id) => document.getElementById(id);

// h builds an element. Attributes starting "on" are listeners; children are
// nodes or strings (strings become text nodes).
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'title') el.title = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (res.status === 401) { signedOut(); throw new Error('Not signed in'); }
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) throw new Error((body && body.error) || `${res.status} ${res.statusText}`);
  return body;
}

// The server issues a new token each time it starts, so a page left open
// across a restart can no longer talk to it. Say so, once, plainly.
function signedOut() {
  if (document.querySelector('.signedout')) return;
  clearTimeout(pollTimer);
  document.body.append(h('div', { class: 'signedout' },
    h('b', {}, 'This browser is not signed in to Atropos'),
    h('span', {}, 'Open the full address that "atropos serve" printed when it started. It ends in ?token=…'),
    h('span', { class: 'hint' }, 'The token changes every time the server starts.')));
}

let toastTimer;
function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, bad ? 8000 : 3500);
}
const fail = (e) => toast(e.message || String(e), true);

// ---- time ----
// Timestamps are nanoseconds since 1970 and do not fit a JavaScript number,
// so the API sends them as strings and they are handled as BigInt throughout.
function fmtNs(ns, digits = 6) {
  if (ns == null || ns === '') return '';
  ns = BigInt(ns);
  // Stored times are never before 1980, so plain division is exact here.
  const sub = ns % 1000000000n;
  const d = new Date(Number(ns / 1000000000n) * 1000);
  if (isNaN(d) || ns < 0n) return String(ns);
  const iso = d.toISOString(); // YYYY-MM-DDTHH:MM:SS.000Z
  const frac = digits ? '.' + String(sub).padStart(9, '0').slice(0, digits) : '';
  return iso.slice(0, 10) + ' ' + iso.slice(11, 19) + frac;
}
const fmtInt = (n) => Number(n).toLocaleString('en-GB');
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}
function fmtSpan(ns) {
  let s = Number(BigInt(ns) / 1000000n) / 1000;
  if (s < 1) return (s * 1000).toFixed(0) + ' ms';
  if (s < 120) return s.toFixed(s < 10 ? 1 : 0) + ' s';
  if (s < 7200) return (s / 60).toFixed(0) + ' min';
  if (s < 172800) return (s / 3600).toFixed(1) + ' h';
  if (s < 86400 * 730) return (s / 86400).toFixed(0) + ' days';
  return (s / 86400 / 365.25).toFixed(1) + ' years';
}

const ZONES = {
  'native-utc': 'UTC by definition: the format stores this value in UTC.',
  'explicit-offset': 'The source value carried its own UTC offset.',
  'host-registry': 'Local time, converted using the time zone read from the host\'s own registry hive in the same submission.',
  'examiner-set': 'Local time, converted using a time zone stated by the examiner. The statement is in the audit log.',
  'assumed': 'ASSUMED. The source gave no time zone and none could be established, so UTC was applied. The true time may differ by the host\'s offset.',
};

// ---- state ----
const PAGE = 500, ROW = 26;
const S = {
  view: 'timeline',
  pending: new Set(), currentId: 0, // items waiting for or in a parse run (from /api/status)
  excluding: null, // the item whose exclusion form is open
  help: '', // the guide's topic on show
  q: '', from: null, to: null, desc: false, group: '',
  groups: [], checked: new Set(),
  rows: [], done: false, loading: false, gen: 0,
  summary: null, buckets: 120, zoom: [],
  selected: null,
  evidence: [], evMap: new Map(), evOpen: null, evFilter: '', evSort: 'tree', evOnly: false,
  img: null, imgPath: '/', imgEntries: [], imgChecked: new Set(), lastExtract: '',
  busy: false,
};

// ---- timeline ----
function params(extra) {
  const p = new URLSearchParams();
  if (S.q) p.set('q', S.q);
  if (S.group) p.set('group', S.group);
  if (S.from != null) p.set('from', String(S.from));
  if (S.to != null) p.set('to', String(S.to));
  for (const [k, v] of Object.entries(extra || {})) p.set(k, String(v));
  return p.toString();
}

// The address bar carries the view, search, zoom and selected event, so a
// position in a case can be bookmarked or pasted into notes.
function writeHash() {
  const p = new URLSearchParams();
  if (S.view !== 'timeline') p.set('view', S.view);
  if (S.q) p.set('q', S.q);
  if (S.group) p.set('group', S.group);
  if (S.from != null) p.set('from', String(S.from));
  if (S.to != null) p.set('to', String(S.to));
  if (S.desc) p.set('order', 'desc');
  if (S.view === 'help' && S.help) p.set('topic', S.help);
  if (S.selected != null) p.set('e', String(S.selected));
  const str = p.toString();
  history.replaceState(null, '', str ? '#' + str : location.pathname);
}
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const big = (k) => { try { return p.get(k) ? BigInt(p.get(k)) : null; } catch { return null; } };
  S.q = p.get('q') || '';
  S.group = p.get('group') || '';
  S.from = big('from'); S.to = big('to');
  S.desc = p.get('order') === 'desc';
  S.help = p.get('topic') || '';
  S.view = ['timeline', 'evidence', 'files', 'analysis', 'connections', 'details', 'audit', 'help'].includes(p.get('view')) ? p.get('view') : 'timeline';
  const e = Number(p.get('e'));
  return Number.isInteger(e) && e > 0 ? e : null;
}

async function reload() {
  const gen = ++S.gen;
  writeHash();
  S.rows = []; S.done = false; S.loading = false;
  S.checked.clear();
  renderSelection();
  $('rows').scrollTop = 0;
  S.buckets = Math.max(40, Math.min(240, Math.floor($('histo').clientWidth / 5)));
  renderZoomButtons();
  try {
    const [sum] = await Promise.all([api('/api/summary?' + params({ buckets: S.buckets })), loadMore()]);
    if (gen !== S.gen) return;
    S.summary = sum;
    renderSummary();
    renderSelection();
    renderHisto();
  } catch (e) { if (gen === S.gen) fail(e); }
  textHits(gen);
}

async function loadMore() {
  if (S.loading || S.done) return;
  const gen = S.gen;
  S.loading = true;
  const extra = { limit: PAGE, order: S.desc ? 'desc' : 'asc' };
  const last = S.rows[S.rows.length - 1];
  if (last) { extra.after_ts = last.ts_utc; extra.after_id = last.id; }
  try {
    const { events } = await api('/api/events?' + params(extra));
    if (gen !== S.gen) return;
    S.rows.push(...events);
    S.done = events.length < PAGE;
  } catch (e) {
    if (gen === S.gen) { S.done = true; fail(e); }
  } finally {
    if (gen === S.gen) { S.loading = false; renderRows(); }
  }
}

const MACB_WORDS = { M: 'content Modified', A: 'Accessed', C: 'metadata Changed', B: 'Born (created)' };
function macbEl(m) {
  const letters = [...m].filter((c) => c !== '.');
  const title = letters.length ? 'This time is: ' + letters.map((c) => MACB_WORDS[c]).join(', ') : 'Not a file time';
  return h('span', { class: 'macb', title }, [...m].map((c) => (c === '.' ? '.' : h('b', {}, c))));
}

function rowEl(e) {
  const tags = (e.groups || []).map((t) => h('span', { class: 'gtag' }, t))
    .concat((e.tags || []).map((t) => h('span', { class: 'tag' }, t)));
  const box = h('input', { type: 'checkbox', title: 'Select, to add to a group', checked: S.checked.has(e.id) });
  box.addEventListener('click', (ev) => {
    ev.stopPropagation();
    // Shift-click selects everything between this row and the last one ticked.
    if (ev.shiftKey && S.lastChecked != null) {
      const a = S.rows.findIndex((r) => r.id === S.lastChecked), b = S.rows.findIndex((r) => r.id === e.id);
      if (a >= 0 && b >= 0) for (let i = Math.min(a, b); i <= Math.max(a, b); i++) S.checked.add(S.rows[i].id);
    } else if (box.checked) S.checked.add(e.id); else S.checked.delete(e.id);
    S.lastChecked = e.id;
    renderSelection();
    if (ev.shiftKey) renderRows();
  });
  return h('div', {
    class: 'row' + (e.tz_source === 'assumed' ? ' assumed' : '') + (e.id === S.selected ? ' sel' : ''),
    onclick: () => select(e.id),
  },
    h('span', {}, box),
    h('span', { class: 'time' }, fmtNs(e.ts_utc)),
    h('span', { title: e.tz_source + (e.tz_name ? ' (' + e.tz_name + ')' : '') }, h('i', { class: 'dot ' + e.tz_source })),
    macbEl(e.macb),
    h('span', { title: e.category }, h('i', { class: 'cat ' + e.category }, e.category)),
    h('span', { class: 'dimc', title: e.ts_type }, e.ts_type),
    h('span', { class: 'dimc', title: e.source }, e.source),
    h('span', { title: e.host }, e.host),
    h('span', { title: e.user }, e.user),
    h('span', { class: 'dimc', title: itemTitle(e.evidence_id) }, itemName(e.evidence_id)),
    h('span', { class: 'msg' }, tags, e.message));
}

// ---- where an event came from ----
// An item's name, and for the tooltip its path, which for a file copied out
// of an image or an archive includes the image or archive it was in.
function itemName(id) { const e = S.evMap.get(id); return e ? e.name : '#' + id; }
function itemTitle(id) { const e = S.evMap.get(id); return e ? `#${id}  ${e.origin}` : ''; }

// The outermost item something came out of: the image for a file copied out
// of it, the archive for one of its members, the item itself otherwise.
function rootOf(e) {
  let seen = 0;
  while (e && e.parent_id && S.evMap.has(e.parent_id) && seen++ < 64) e = S.evMap.get(e.parent_id);
  return e;
}

// Events of each item together with everything that came out of it.
function familyTotals() {
  const kids = new Map();
  for (const e of S.evidence) if (e.parent_id) (kids.get(e.parent_id) || kids.set(e.parent_id, []).get(e.parent_id)).push(e);
  const totals = new Map();
  const total = (e, depth) => {
    let n = e.event_count, items = 1;
    if (depth < 64) for (const k of kids.get(e.id) || []) { const t = total(k, depth + 1); n += t.events; items += t.items; }
    totals.set(e.id, { events: n, items });
    return { events: n, items };
  };
  for (const e of S.evidence) if (!e.parent_id) total(e, 0);
  return { kids, totals };
}

const ORIGIN_KEYS = ['from', 'submission', 'kind', 'item'];
// The search's terms, split on spaces outside quotes, as the server splits
// them: item:"my file.txt" is one term.
function terms(s) {
  const out = [];
  let cur = '', inQ = false;
  for (const ch of s) {
    if (ch === '"') { inQ = !inQ; cur += ch; } else if (/\s/.test(ch) && !inQ) { if (cur) out.push(cur); cur = ''; } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
const isOriginToken = (t) => ORIGIN_KEYS.some((k) => t.toLowerCase().startsWith(k + ':'));

// The "From" list on the timeline: every image, every archive that things
// were taken out of, every item name in the Item column, and every
// submission. Choosing one narrows the timeline to it.
function renderOrigin() {
  const sel = $('origin');
  const { kids, totals } = familyTotals();
  const current = terms(S.q).find(isOriginToken) || '';
  const opts = [h('option', { value: '' }, 'From: all evidence')];
  // Every image, whether or not anything has been taken out of it yet, and
  // every top-level archive or folder that holds other items.
  const holders = S.evidence.filter((e) => !e.duplicate_of && !e.excluded && (isImage(e) || (kids.has(e.id) && !e.parent_id)));
  if (holders.length) {
    opts.push(h('optgroup', { label: 'Images and archives, with everything taken out of them' },
      holders.map((e) => {
        const t = totals.get(e.id) || { events: e.event_count, items: 1 };
        return h('option', { value: 'from:' + e.id }, `#${e.id} ${e.name}  ·  ${fmtInt(t.events)} events in ${fmtInt(t.items)} item${t.items === 1 ? '' : 's'}`);
      })));
  }
  // Every name in the Item column, from the evidence parsed so far: items
  // of the same name (one NTUSER.DAT per user) are one entry.
  const names = new Map();
  for (const e of S.evidence) {
    if (e.duplicate_of || e.excluded || !e.event_count) continue;
    const key = e.name.toLowerCase();
    const n = names.get(key) || names.set(key, { name: e.name, items: 0, events: 0 }).get(key);
    n.items++; n.events += e.event_count;
  }
  if (names.size) {
    opts.push(h('optgroup', { label: 'Items (as in the Item column)' },
      [...names.values()].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' })).map((n) =>
        h('option', { value: itemToken(n.name) },
          `${n.name}  ·  ${n.items > 1 ? fmtInt(n.items) + ' items  ·  ' : ''}${fmtInt(n.events)} events`))));
  }
  const batches = new Map();
  for (const e of S.evidence) {
    const b = batches.get(e.batch_id) || batches.set(e.batch_id, { items: 0, events: 0, first: e.name }).get(e.batch_id);
    b.items++; b.events += e.event_count;
  }
  if (batches.size > 1) {
    opts.push(h('optgroup', { label: 'Submissions (what was added together)' },
      [...batches].map(([id, b]) => h('option', { value: 'submission:' + id },
        `Submission ${id}  ·  ${b.items === 1 ? b.first : b.first + ' and ' + fmtInt(b.items - 1) + ' more'}  ·  ${fmtInt(b.events)} events`))));
  }
  // A filter typed by hand, or one whose item is not in the list, is shown as it is.
  if (current && !opts.some((o) => [...(o.children.length ? o.children : [o])].some((c) => c.value === current))) {
    opts.push(h('option', { value: current }, current));
  }
  sel.replaceChildren(...opts);
  sel.value = current;
  sel.classList.toggle('on', !!current);
}
// item:NAME, quoted when the name has a space; a quote in a name cannot be
// written in the search, so it is left out (the name is then not found).
function itemToken(name) {
  const v = name.replace(/"/g, '');
  return /\s/.test(v) ? `item:"${v}"` : 'item:' + v;
}
function setOrigin(token) {
  const parts = terms(S.q).filter((t) => t && !isOriginToken(t));
  if (token) parts.push(token);
  setQuery(parts.join(' '));
}

// Only the rows in view are in the document, so a long result scrolls smoothly.
function renderRows() {
  const box = $('rows');
  const n = S.rows.length;
  $('spacer').style.height = (n + (S.done ? 0 : 1)) * ROW + 'px';
  const first = Math.max(0, Math.floor(box.scrollTop / ROW) - 10);
  const last = Math.min(n, Math.ceil((box.scrollTop + box.clientHeight) / ROW) + 10);
  const win = $('win');
  win.style.transform = `translateY(${first * ROW}px)`;
  win.replaceChildren(...S.rows.slice(first, last).map(rowEl));
  if (!S.done && last > n - 100) loadMore();

  const empty = $('empty');
  if (n === 0 && S.done) {
    const filtered = S.q || S.from != null;
    if (S.group && !filtered) {
      empty.replaceChildren(h('b', {}, `"${S.group}" has no events yet`),
        h('span', {}, 'Go back to the whole timeline, tick the events that belong here, and choose "Add selected to group".'));
    } else {
      empty.replaceChildren(
        h('b', {}, filtered ? 'No events match this search' : 'The timeline is empty'),
        h('span', {}, filtered ? 'Try fewer terms, or return to the whole timeline.' : 'Drop files or folders anywhere on this page, or use "Add evidence".'));
    }
    empty.hidden = false;
  } else empty.hidden = true;
}

function renderSummary() {
  const s = S.summary, el = $('summary');
  if (!s || !Number(s.count)) { el.replaceChildren(h('b', {}, '0'), ' events'); return; }
  el.replaceChildren(h('b', {}, fmtInt(s.count)), s.count === 1 ? ' event' : ' events', '  ·  ',
    fmtNs(s.min_ts, 0), '  →  ', fmtNs(s.max_ts, 0), '  ·  ', fmtSpan(BigInt(s.max_ts) - BigInt(s.min_ts)));
}

function renderZoomButtons() {
  $('zoomout').hidden = S.zoom.length === 0;
  $('zoomreset').hidden = S.from == null && S.to == null;
}

// The number of bars the server drew the span in: at most the number asked
// for, fewer when it widened them to whole hours.
const nBars = () => (S.summary && Number(S.summary.buckets)) || S.buckets;
function renderHisto() {
  const s = S.summary, bars = $('bars');
  if (!s || !s.bars.length) { bars.replaceChildren(); return; }
  const max = Math.max(...s.bars.map((b) => b.n));
  const w = 100 / nBars();
  bars.replaceChildren(...s.bars.map((b) => {
    const d = document.createElement('div');
    d.style.left = b.i * w + '%';
    d.style.width = `calc(${w}% - 1px)`;
    // Square-root scale: a single event stays visible beside a burst of thousands.
    d.style.height = Math.max(3, Math.sqrt(b.n / max) * 100) + '%';
    return d;
  }));
}

function bucketAt(x) {
  const w = $('histo').clientWidth;
  return Math.max(0, Math.min(nBars() - 1, Math.floor(x / w * nBars())));
}
function bucketRange(i0, i1) {
  const start = BigInt(S.summary.start_ts), size = BigInt(S.summary.bucket_ns);
  return [start + size * BigInt(i0), start + size * BigInt(i1 + 1) - 1n];
}

function setupHisto() {
  const box = $('histo'), sel = $('sel'), tip = $('tip');
  let down = null;
  const x = (ev) => ev.clientX - box.getBoundingClientRect().left;
  box.addEventListener('mousedown', (ev) => {
    if (!S.summary || !Number(S.summary.count)) return;
    down = x(ev);
    ev.preventDefault();
  });
  box.addEventListener('mousemove', (ev) => {
    if (!S.summary || !Number(S.summary.count)) return;
    const i = bucketAt(x(ev));
    const [a, b] = bucketRange(i, i);
    const bar = S.summary.bars.find((r) => r.i === i);
    tip.textContent = `${fmtNs(a, 0)} → ${fmtNs(b, 0)}   ${fmtInt(bar ? bar.n : 0)} events`;
    tip.hidden = false;
    const tx = Math.min(box.clientWidth - tip.offsetWidth - 4, Math.max(4, x(ev) + 10));
    tip.style.left = tx + 'px';
    if (down != null) {
      const l = Math.min(down, x(ev)), r = Math.max(down, x(ev));
      sel.style.left = l + 'px'; sel.style.width = (r - l) + 'px'; sel.hidden = false;
    }
  });
  box.addEventListener('mouseleave', () => { tip.hidden = true; });
  window.addEventListener('mouseup', (ev) => {
    if (down == null) return;
    const up = x(ev), start = down;
    down = null; sel.hidden = true;
    const i0 = bucketAt(Math.min(start, up)), i1 = bucketAt(Math.max(start, up));
    // A click on one bucket that already spans the whole view would zoom nowhere.
    if (i0 === 0 && i1 === nBars() - 1) return;
    if (BigInt(S.summary.bucket_ns) <= 1n && i0 === i1) return;
    const [from, to] = bucketRange(i0, i1);
    S.zoom.push([S.from, S.to]);
    S.from = from; S.to = to;
    reload();
  });
  $('zoomout').onclick = () => { [S.from, S.to] = S.zoom.pop() || [null, null]; reload(); };
  $('zoomreset').onclick = () => { S.zoom = []; S.from = S.to = null; reload(); };
}

// Files with no dedicated parser are still text-indexed. A search that names
// something inside one of them says so, rather than looking like no result.
async function textHits(gen) {
  const box = $('texthits');
  const free = terms(S.q).some((t) => t && !t.startsWith('-') && !/^[a-z]+:/i.test(t));
  if (!free) { box.hidden = true; return; }
  try {
    const { hits } = await api('/api/textsearch?q=' + encodeURIComponent(S.q));
    if (gen !== S.gen) return;
    if (!hits.length) { box.hidden = true; return; }
    box.replaceChildren(
      h('div', { class: 't' }, `Also found in the text of ${hits.length} file${hits.length === 1 ? '' : 's'} that ${hits.length === 1 ? 'has' : 'have'} no dedicated parser:`),
      ...hits.map((x) => h('div', { class: 'hit' },
        h('button', { class: 'link', onclick: () => showEvidence(x.evidence_id) }, `#${x.evidence_id} ${x.name}`),
        h('span', { class: 'snip' }, x.snippet))));
    box.hidden = false;
  } catch { box.hidden = true; }
}

// ---- groups: timelines built from the timeline ----
async function loadGroups() {
  try {
    S.groups = (await api('/api/groups')).groups;
    if (S.group && !S.groups.some((g) => g.name === S.group)) S.group = '';
    renderGroups();
    renderSelection();
  } catch (e) { fail(e); }
}

function renderGroups() {
  const out = [h('span', { class: 'label' }, 'Timelines'),
    h('button', { class: 'chip' + (S.group ? '' : ' on'), onclick: () => setGroup('') }, 'Everything')];
  for (const g of S.groups) {
    out.push(h('button', { class: 'chip' + (S.group === g.name ? ' on' : ''), title: g.note || 'A timeline built from picked events', onclick: () => setGroup(g.name) },
      g.name, h('i', {}, fmtInt(g.count))));
  }
  out.push(h('button', { class: 'chip new', title: 'Name a group, then tick events and add them to it', onclick: () => newGroupDialog() }, '+ New group'));
  const cur = S.groups.find((g) => g.name === S.group);
  if (cur) {
    if (cur.note) out.push(h('span', { class: 'groupnote' }, cur.note));
    out.push(h('button', { class: 'link groupnote', title: 'Hides the group. Nothing is deleted, and the action is audited.', onclick: () => archiveGroup(cur) }, 'archive this group'));
  }
  $('groups').replaceChildren(...out);
}

function setGroup(name) {
  S.group = name; S.zoom = []; S.from = S.to = null;
  renderGroups();
  loadFacets();
  reload();
}

// The one control for filling a group: it acts on the ticked events when
// there are any, and otherwise on everything the current search shows.
function renderSelection() {
  const n = S.checked.size;
  const total = S.summary ? Number(S.summary.count) : 0;
  const sel = $('groupadd');
  const label = n ? `Add ${fmtInt(n)} selected to group…` : `Add all ${fmtInt(total)} shown to group…`;
  sel.replaceChildren(h('option', { value: '' }, label),
    ...S.groups.filter((g) => g.name !== S.group).map((g) => h('option', { value: String(g.id) }, g.name)),
    h('option', { value: 'new' }, '+ New group…'));
  sel.disabled = !n && !total;
  $('clearsel').hidden = !n;
  const rm = $('groupremove');
  rm.hidden = !(n && S.group);
  rm.textContent = `Remove ${fmtInt(n)} from "${S.group}"`;
  const all = $('checkall');
  all.checked = n > 0 && n >= S.rows.length;
  all.indeterminate = n > 0 && n < S.rows.length;
}

async function changeGroup(group, action, useSelection) {
  const body = { action };
  if (useSelection) body.event_ids = [...S.checked];
  else body.query = { q: S.q, from: S.from == null ? '' : String(S.from), to: S.to == null ? '' : String(S.to), group: S.group };
  try {
    const r = await api(`/api/groups/${group.id}/events`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const skipped = r.requested - r.changed;
    toast(action === 'add'
      ? `${fmtInt(r.changed)} event${r.changed === 1 ? '' : 's'} added to "${group.name}"` + (skipped ? ` (${fmtInt(skipped)} already there)` : '')
      : `${fmtInt(r.changed)} event${r.changed === 1 ? '' : 's'} removed from "${group.name}"`);
    S.checked.clear();
    await loadGroups();
    reload();
  } catch (e) { fail(e); }
}

function newGroupDialog(then) {
  const dlg = $('dlg');
  const name = h('input', { type: 'text', maxlength: '60', placeholder: 'Malware, Lateral movement, Exfiltration…' });
  const note = h('input', { type: 'text', maxlength: '500', placeholder: 'Optional: what this timeline is for' });
  const create = async () => {
    try {
      const g = await api('/api/groups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name.value, note: note.value }) });
      dlg.close();
      await loadGroups();
      if (then) then(g); else toast(`Group "${g.name}" created. Tick events and add them to it.`);
    } catch (e) { fail(e); }
  };
  name.addEventListener('keydown', (k) => { if (k.key === 'Enter') create(); });
  dlg.replaceChildren(
    h('h2', {}, 'New group'),
    h('p', {}, 'A group is a separate timeline made of events you pick from the main one: tick events, or search for them, and add them to the group. Picking an event never changes it, and every addition and removal is audited.'),
    h('label', {}, 'Name'), name, h('label', {}, 'Note'), note,
    h('div', { class: 'actions' }, h('button', { onclick: () => dlg.close() }, 'Cancel'), h('button', { class: 'primary', onclick: create }, 'Create group')));
  dlg.showModal();
  name.focus();
}

function archiveGroup(g) {
  const dlg = $('dlg');
  dlg.replaceChildren(
    h('h2', {}, `Archive "${g.name}"?`),
    h('p', {}, `The group and its ${fmtInt(g.count)} event${g.count === 1 ? '' : 's'} will no longer be listed. Nothing is deleted: the group, its membership and this action stay in the case and its audit log, and creating a group with the same name brings the events back.`),
    h('div', { class: 'actions' }, h('button', { onclick: () => dlg.close() }, 'Cancel'),
      h('button', { class: 'primary', onclick: async () => {
        dlg.close();
        try { await api(`/api/groups/${g.id}/archive`, { method: 'POST' }); S.group = ''; await loadGroups(); reload(); } catch (e) { fail(e); }
      } }, 'Archive')));
  dlg.showModal();
}

// ---- facets and query editing ----
function hasToken(tok) { return terms(S.q).includes(tok); }
function toggleToken(tok) {
  const parts = terms(S.q).filter(Boolean);
  const i = parts.indexOf(tok);
  if (i >= 0) parts.splice(i, 1); else parts.push(tok);
  setQuery(parts.join(' '));
}
function setQuery(q) {
  S.q = q.trim();
  $('q').value = S.q;
  renderOrigin();
  loadFacets();
  reload();
}

let caseData = null;
async function loadCase() {
  try {
    caseData = await api('/api/case');
    const m = caseData.meta || {};
    $('caseinfo').textContent = `Examiner ${caseData.examiner}  ·  Atropos ${caseData.tool_version}` +
      (caseData.local_zone ? `  ·  local zone ${caseData.local_zone}` : '');
    $('caseinfo').title = `Case created ${m.created_utc || '?'} by ${m.created_by || '?'}`;
    facetKey = null;
    loadFacets();
  } catch (e) { fail(e); }
}
// The chip counts follow the "From" choice and the group being viewed:
// they say how many of the events being looked at are of each kind.
let facetKey = null;
// The chips' counts follow the whole search: each group is counted with its
// own chips left out, so the others in that group stay to choose from.
async function loadFacets() {
  const q = S.q.trim();
  const key = q + '|' + S.group;
  if (key === facetKey) { renderFacets(); return; }
  facetKey = key;
  if (!q && !S.group) { S.facets = null; renderFacets(); return; }
  try {
    const r = await api('/api/facets?' + new URLSearchParams({ q, group: S.group }).toString());
    if (key === facetKey) { S.facets = r.facets; renderFacets(); }
  } catch (e) { fail(e); }
}

function renderFacets() {
  if (!caseData) return;
  const facets = S.facets || caseData.facets;
  // One row per group: Evidence of, then Source, above the chart; the time
  // zone chips sit under the chart.
  const group = (label, key, counts) => {
    const out = [];
    // A chip that is switched on stays, even at zero, so it can be switched off.
    const on = terms(S.q).filter((t) => t.startsWith(key + ':')).map((t) => t.slice(key.length + 1));
    const names = [...new Set([...Object.keys(counts), ...on])].sort();
    if (!names.length) return null;
    out.push(h('span', { class: 'label' }, label));
    for (const n of names) {
      const tok = key + ':' + n;
      out.push(h('button', {
        class: 'chip' + (hasToken(tok) ? ' on' : '') + (n === 'assumed' ? ' assumed' : '') + (key === 'category' ? ' cat ' + n : ''),
        title: key === 'tz' ? ZONES[n] : `Show only ${n} events`,
        onclick: () => toggleToken(tok),
      }, n, h('i', {}, fmtInt(counts[n] || 0))));
    }
    return h('div', { class: 'facetrow' }, ...out);
  };
  const rows = (...r) => r.filter(Boolean);
  $('facets').replaceChildren(...rows(group('Evidence of', 'category', facets.category || {}), group('Source', 'source', facets.source || {}), group('Host', 'host', facets.host || {})));
  $('tzfacets').replaceChildren(...rows(group('Time zone from', 'tz', facets.tz_source || {})));
}

// ---- event detail ----
async function select(id) {
  S.selected = id;
  writeHash();
  renderRows();
  const panel = $('detail');
  if (id == null) { panel.hidden = true; return; }
  try {
    const d = await api('/api/event/' + id);
    if (S.selected !== id) return;
    renderDetail(d);
  } catch (e) { fail(e); }
}

function kv(pairs) {
  return h('dl', {}, pairs.filter((p) => p && p[1] !== '' && p[1] != null).flatMap(([k, v, plain]) =>
    [h('dt', {}, k), h('dd', { class: plain ? 'plain' : null }, v)]));
}

// A browser visit or download, read out: where it went, how it was reached,
// where it came from (with a way to open that visit), and whether this
// machine or another device recorded it. Addresses are shown as text and
// never made into links: evidence does not get opened from the case.
function browsingSection(e, ev, f) {
  const isVisit = /^url-(last-)?visited/.test(e.ts_type), isDownload = e.ts_type.startsWith('download-');
  if (!(e.source || '').startsWith('browser') || !(isVisit || isDownload)) return null;
  const secs = (s) => s == null ? '' : s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
  const site = f.domain ? h('span', {}, f.domain, '  ', h('button', { class: 'link', onclick: () => setQuery('domain:' + f.domain) }, 'everything from this site')) : '';
  const user = e.user ? e.user + (f.user_from ? '  (inferred from the folder the file came from)' : '') : '';
  if (isVisit) {
    const how = (e.ts_type.match(/\((.*)\)$/) || [])[1] || f.transition_name || f.visit_type_name || '';
    const quals = (f.transition_qualifiers || []).filter((q) => !/^chain_/.test(q)).map((q) => q.replace(/_/g, ' '));
    const jump = (label, id) => id ? h('div', {}, h('button', { class: 'link', onclick: () => openVisit(ev.id, id) }, label)) : null;
    return [h('h3', {}, 'Browsing'), kv([
      ['Page', f.url], ['Title', f.title], ['Site', site],
      ['How it was reached', how + (quals.length ? `  (${quals.join(', ')})` : '') + (f.navigation === 'automatic' ? `. Loaded by the browser, not chosen: ${f.navigation_reason}` : '')],
      ['Came from', f.from_url ? h('span', {}, f.from_url, jump('open the visit it came from', f.from_visit_id)) : ''],
      ['Opened from', f.opener_url ? h('span', {}, f.opener_url, jump('open that visit', f.opener_visit_id)) : ''],
      ['Referred from outside', f.external_referrer_url],
      ['Searched for', f.search_term],
      ['Time on the page', [secs(f.visit_duration_seconds), f.foreground_seconds != null ? `${secs(f.foreground_seconds)} in front` : ''].filter(Boolean).join(', ')],
      ['Server answered', f.response_code != null ? String(f.response_code) : ''],
      ['Visits to this address', f.url_visit_count != null ? String(f.url_visit_count) + (f.url_typed_count ? `, typed ${f.url_typed_count} time${f.url_typed_count === 1 ? '' : 's'}` : '') : ''],
      ['Recorded on', f.synced_from_another_device ? 'another device signed in to the same account (synced). Not evidence that this machine was used' : (f.visit_records ? '' : 'this browser')],
      ['Profile of', user],
    ])];
  }
  const verdict = f.danger ? (f.danger_code > 0 ? h('b', { class: 'bad' }, f.danger) : f.danger) : '';
  return [h('h3', {}, 'Download'), kv([
    ['Saved to', f.target_path], ['Site', site], ['From', f.url],
    ['Redirect chain', (f.url_chain || []).length > 1 ? h('ol', { class: 'chain' }, ...f.url_chain.map((u) => h('li', {}, u))) : ''],
    ['Page it was started from', f.tab_url], ['That page came from', f.tab_referrer_url], ['Referrer', f.referrer],
    ['State', f.state + (f.interrupt_reason ? `, interrupted: ${f.interrupt_reason}` : '')],
    ['Browser\'s verdict', verdict],
    ['Size', f.total_bytes != null ? `${fmtInt(f.received_bytes || 0)} of ${fmtInt(f.total_bytes)} bytes` : ''],
    ['Type', f.mime_type + (f.original_mime_type && f.original_mime_type !== f.mime_type ? ` (server said ${f.original_mime_type})` : '')],
    ['Opened from the browser', f.opened_from_browser == null ? '' : f.opened_from_browser ? 'yes' : 'no'],
    ['Server\'s last-modified date', f.server_last_modified],
    ['Profile of', user],
  ])];
}

// Opens the visit with the browser's own number in the same history file.
async function openVisit(evidenceId, visitId) {
  try {
    // Not params(): the visit may lie outside the current zoom or group.
    const r = await api('/api/events?' + new URLSearchParams({ q: `evidence:${evidenceId} visit:${visitId}`, limit: '1' }));
    if (r.events.length) select(r.events[0].id);
    else toast('That visit is not in the history file any more: browsers delete old visit records');
  } catch (err) { fail(err); }
}

function renderDetail({ event: e, evidence: ev, annotations, journal_folder: jf, connection_record: conn }) {
  const panel = $('detail');
  const fields = e.fields || {};
  const caveat = fields._time_caveat;
  const kids = [
    h('h2', {}, `Event ${e.id}`, h('span', { class: 'spacer' }), h('button', { onclick: () => select(null), title: 'Close (Esc)' }, 'Close')),
    h('div', { class: 'bigtime' }, fmtNs(e.ts_utc, 9), ' UTC'),
    h('div', { class: 'summary' }, e.ts_type),
  ];
  if (e.tz_source === 'assumed') kids.push(h('div', { class: 'note warn' }, ZONES.assumed));
  if (caveat) kids.push(h('div', { class: 'note warn' }, 'Time caveat: ' + caveat));
  // For a browser visit or download, what it is comes first.
  const browsing = browsingSection(e, ev, fields);
  if (browsing) kids.push(...browsing);

  const letters = [...e.macb].filter((c) => c !== '.');
  kids.push(h('h3', {}, 'Time'), kv([
    ['MACB', e.macb + (letters.length ? '  (' + letters.map((c) => MACB_WORDS[c]).join(', ') + ')' : '  (not a file time)')],
    ['As found', e.ts_raw],
    ['Zone from', e.tz_source],
    ['Zone applied', e.tz_name],
    ['Meaning', ZONES[e.tz_source] || '', true],
  ]));
  kids.push(h('h3', {}, 'Event'), kv([
    ['Evidence of', e.category],
    ['Source', e.source], ['Host', e.host], ['User', e.user], ['Path', e.path],
    jf ? ['Folder (file table)', jf.path] : null,
  ]));
  if (jf) {
    kids.push(h('div', { class: 'note info' }, `The journal names the folder only by its file-table entry. This is that folder in the file table of #${jf.evidence_id}: ${jf.note}.`));
  }
  kids.push(h('h3', {}, 'Message'), h('pre', { class: 'msg' }, e.message));
  if (conn) {
    kids.push(h('div', { class: 'note info cnfrom' }, 'Read for the Connections tab: ', conn, '. ',
      h('button', { class: 'link', onclick: () => showEventConnections(e.id, conn) }, 'Show its connections')));
  }

  if (ev.kind === 'picture') kids.push(h('h3', {}, 'Picture'), pictureOf(ev));
  kids.push(h('h3', {}, 'Where this came from'), kv([
    ['Location', e.record_ref],
    ['Evidence', h('button', { class: 'link', onclick: () => showEvidence(ev.id) }, `#${ev.id} ${ev.name}`)],
    ['Origin', ev.origin],
    ['SHA-256', ev.sha256],
    ['Parser', ev.parser],
    ['Parse run', String(e.run_id)],
  ]), h('div', { class: 'note info' },
    h('button', { class: 'link', onclick: () => setQuery('evidence:' + ev.id) }, 'Show every event from this evidence item'),
    (() => {
      const root = rootOf(S.evMap.get(ev.id));
      return root && root.id !== ev.id
        ? h('div', {}, h('button', { class: 'link', onclick: () => setQuery('from:' + root.id) }, `Show everything that came out of ${root.name}`))
        : null;
    })()));

  const active = annotations.filter((a) => a.kind !== 'retract');
  kids.push(h('h3', {}, 'Examiner notes'));
  if (!active.length) kids.push(h('div', { class: 'hint' }, 'None. Notes are kept in their own layer and never alter the event.'));
  for (const a of active) {
    kids.push(h('div', { class: 'ann' + (a.retracted ? ' retracted' : '') },
      a.kind === 'tag' ? h('span', { class: 'tag' }, a.body) : null,
      a.kind === 'group' ? h('span', {}, 'in group ', h('span', { class: 'gtag' }, a.body)) : null,
      a.kind === 'comment' ? h('span', { class: 'body' }, a.body) : null,
      h('span', { class: 'who' }, `${a.actor}, ${fmtNs(a.made_utc, 0)}${a.retracted ? ', withdrawn' : ''}`),
      a.retracted ? null : h('button', { class: 'link', onclick: () => annotate(e.id, 'retract', '', a.id) }, 'withdraw')));
  }
  const input = h('input', { type: 'text', placeholder: 'Tag or comment', maxlength: '2000' });
  const submit = (kind) => { if (input.value.trim()) annotate(e.id, kind, input.value.trim(), null); };
  input.addEventListener('keydown', (k) => { if (k.key === 'Enter') submit(/\s/.test(input.value.trim()) ? 'comment' : 'tag'); });
  kids.push(h('div', { class: 'annform' }, input,
    h('button', { onclick: () => submit('tag') }, 'Add tag'),
    h('button', { onclick: () => submit('comment') }, 'Add comment')));

  kids.push(h('h3', {}, 'Parsed fields'), h('pre', {}, JSON.stringify(fields, null, 2)));
  panel.replaceChildren(...kids);
  panel.hidden = false;
  panel.scrollTop = 0;
}

async function annotate(eventId, kind, body, refersTo) {
  try {
    await api('/api/annotate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_id: eventId, kind, body, refers_to: refersTo }),
    });
    const d = await api('/api/event/' + eventId);
    const row = S.rows.find((r) => r.id === eventId);
    if (row) {
      row.tags = d.annotations.filter((a) => a.kind === 'tag' && !a.retracted).map((a) => a.body);
      row.groups = d.annotations.filter((a) => a.kind === 'group' && !a.retracted).map((a) => a.body);
    }
    if (kind === 'retract') loadGroups();
    if (S.selected === eventId) renderDetail(d);
    renderRows();
  } catch (e) { fail(e); }
}

// ---- evidence ----
async function loadEvidence() {
  try {
    const { evidence, ingest } = await api('/api/evidence');
    const first = S.evMap.size !== evidence.length;
    S.evidence = evidence;
    S.evMap = new Map(evidence.map((e) => [e.id, e]));
    renderOrigin();
    if (first && S.view === 'timeline') renderRows(true);
    $('evcount').textContent = evidence.length ? String(evidence.length) : '';
    const n = evidence.filter(isImage).length;
    $('imgcount').textContent = n ? String(n) : '';
    if (S.view === 'files') renderImagePicker();
    setIngest(ingest);
    if (S.view === 'evidence') renderEvidence();
  } catch (e) { fail(e); }
}

function renderEvidence() {
  const f = S.evFilter.toLowerCase();
  const { kids, totals } = familyTotals();
  let list = S.evidence.filter((e) => (!f ||
    [e.name, e.kind, e.status, e.sha256, e.origin, '#' + e.id].some((v) => String(v).toLowerCase().includes(f))) &&
    (!S.evOnly || e.event_count > 0));
  // In the order added, each file sits under what it came out of. Any other
  // order is a flat list, so the indentation is dropped.
  const flat = S.evSort !== 'tree';
  const sorts = {
    events: (a, b) => b.event_count - a.event_count,
    name: (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }),
    kind: (a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name),
    size: (a, b) => b.size - a.size,
    status: (a, b) => a.status.localeCompare(b.status) || a.id - b.id,
    newest: (a, b) => b.id - a.id,
  };
  if (flat) list = [...list].sort((a, b) => sorts[S.evSort](a, b) || a.id - b.id);
  const stale = S.evidence.filter((e) => e.stale).length;
  $('evstale').hidden = !stale;
  $('evstale').textContent = `Bring ${fmtInt(stale)} item${stale === 1 ? '' : 's'} up to date`;
  const by = {};
  let events = 0;
  for (const e of S.evidence) {
    const st = e.excluded ? 'excluded' : e.status;
    by[st] = (by[st] || 0) + 1;
    if (!e.excluded) events += e.event_count;
  }
  $('evsummary').replaceChildren(h('b', {}, fmtInt(S.evidence.length)), ' items  ·  ', h('b', {}, fmtInt(events)), ' events  ·  ',
    Object.keys(by).sort().map((k) => `${by[k]} ${k}`).join(', '));
  const out = [];
  for (const e of list) {
    out.push(h('div', { class: 'erow' + (S.evOpen === e.id ? ' sel' : '') + (e.excluded ? ' excluded' : ''), id: 'ev-' + e.id, onclick: () => { S.evOpen = S.evOpen === e.id ? null : e.id; renderEvidence(); } },
      h('span', { class: 'dimc' }, e.id),
      h('span', { class: 'name', title: e.origin }, flat ? '' : '  '.repeat(e.depth) + (e.depth ? '└ ' : ''), e.name),
      h('span', { title: e.detect_reason }, e.kind),
      h('span', {}, statusPill(e), e.stale ? h('i', { class: 'pill stale', title: 'This version of Atropos would read it differently: ' + e.stale }, 'older') : null),
      h('span', { class: 'num' }, e.event_count ? fmtInt(e.event_count) : ''),
      h('span', { class: 'num' }, fmtSize(e.size)),
      h('span', { class: 'mono', title: e.sha256 }, e.sha256.slice(0, 12) + '…'),
      h('span', { class: 'notes', title: e.notes }, e.notes)));
    if (S.evOpen === e.id) {
      out.push(h('div', { class: 'evdetail' }, e.kind === 'picture' ? pictureOf(e) : null, kv([
        ['Submitted as', e.origin],
        ['Identified as', `${e.kind}: ${e.detect_reason}`, true],
        ['SHA-256', e.sha256], ['SHA-1', e.sha1], ['MD5', e.md5],
        ['Size', `${fmtInt(e.size)} bytes`],
        ['Received', `${fmtNs(e.received_utc, 3)} UTC by ${e.received_by}`],
        ['Submission', `batch ${e.batch_id}` + (e.parent_id ? `, unpacked from #${e.parent_id}` : '')],
        ['From', e.assigned ? (e.assigned.host ? `host ${e.assigned.host}` : `not from a host: ${e.assigned.source}`) : 'not assigned to a host', true],
        e.duplicate_of ? ['Duplicate of', `#${e.duplicate_of}: identical content, stored once and not parsed again`, true] : null,
        ['Parser', e.parser + (e.parser_version ? ', version ' + e.parser_version : '')],
        e.stale ? ['Out of date', `${e.stale}. "Parse again" reads it with this version; the earlier run is kept.`, true] : null,
        ['Zone context', e.zone_context],
        ['Notes', e.notes, true],
        e.excluded ? ['Excluded', (e.excluded_by === e.id ? '' : `with #${e.excluded_by}, which it came out of. `) + `Reason: ${e.exclude_reason}. Its events are off the timeline, the counts, exports, the report's timeline and the checks; it stays stored and verifiable.`, true] : null,
      ]), S.excluding === e.id ? excludeForm(e) : null, h('div', { class: 'actions' },
        e.event_count ? h('button', { onclick: (c) => { c.stopPropagation(); setView('timeline'); setQuery('evidence:' + e.id); } }, `Show its ${fmtInt(e.event_count)} event${e.event_count === 1 ? '' : 's'}`) : null,
        kids.has(e.id) && totals.get(e.id) && totals.get(e.id).events > e.event_count
          ? h('button', { onclick: (c) => { c.stopPropagation(); setView('timeline'); setQuery('from:' + e.id); } },
            `Show all ${fmtInt(totals.get(e.id).events)} events from it and what came out of it`) : null,
        isImage(e) ? h('button', { class: 'primary', onclick: (c) => { c.stopPropagation(); S.img = e.id; S.imgPath = '/'; setView('files'); } }, 'Browse its contents') : null,
        e.event_count ? evidenceGroupSelect(e) : null,
        e.duplicate_of ? null : h('button', { title: 'Runs the parser again as a new run. The earlier run and its events are kept, but tags, comments and group membership stay with the earlier events and will not appear on the new ones.', onclick: (c) => { c.stopPropagation(); reparse(e.id); } }, 'Parse again'),
        h('button', { title: 'Say which host this submission came from. Its items are parsed again, as new runs, so their events carry the host and its time zone.', onclick: (c) => { c.stopPropagation(); reassignDialog(e); } }, 'Change host…'),
        !e.excluded && S.excluding !== e.id ? h('button', { title: 'Takes this item, and everything that came out of it, out of the timeline and everything built on it. Nothing is deleted, and it can be included again.', onclick: (c) => { c.stopPropagation(); S.excluding = e.id; renderEvidence(); } }, 'Exclude from case…') : null,
        e.excluded && e.excluded_by === e.id ? h('button', { onclick: (c) => { c.stopPropagation(); setExcluded(e.id, false, ''); } }, 'Include again') : null)));
    }
  }
  if (!out.length) out.push(h('div', { class: 'evdetail hint' }, S.evidence.length ? 'Nothing matches this filter.' : 'No evidence yet. Drop files or folders anywhere on this page.'));
  $('evrows').replaceChildren(...out);
}

// Adds every event of one evidence item to a group in a single step.
function evidenceGroupSelect(e) {
  const sel = h('select', { title: 'Put every event from this item into a group' },
    h('option', { value: '' }, `Add its ${fmtInt(e.event_count)} event${e.event_count === 1 ? '' : 's'} to group…`),
    ...S.groups.map((g) => h('option', { value: String(g.id) }, g.name)),
    h('option', { value: 'new' }, '+ New group…'));
  sel.addEventListener('click', (c) => c.stopPropagation());
  sel.addEventListener('change', () => {
    const v = sel.value;
    sel.value = '';
    const add = async (g) => {
      try {
        const r = await api(`/api/groups/${g.id}/events`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'add', query: { q: 'evidence:' + e.id } }) });
        toast(`${fmtInt(r.changed)} event${r.changed === 1 ? '' : 's'} from #${e.id} added to "${g.name}"`);
        loadGroups();
      } catch (err) { fail(err); }
    };
    if (v === 'new') newGroupDialog(add);
    else if (v) add(S.groups.find((g) => String(g.id) === v));
  });
  return sel;
}

// pictureOf shows an evidence item that is a picture. The server sends it
// only if its bytes are a JPEG, PNG, GIF, WebP or BMP; if it refuses, the
// space says why rather than showing a broken image.
function pictureOf(ev) {
  const img = h('img', { class: 'evpic', alt: `Evidence #${ev.id}, ${ev.name}`, src: `/api/evidence/${ev.id}/picture` });
  const box = h('div', { class: 'picbox' }, img);
  img.addEventListener('error', () => box.replaceChildren(h('div', { class: 'hint' }, 'This picture could not be shown.')));
  img.addEventListener('click', (c) => { c.stopPropagation(); box.classList.toggle('big'); });
  return box;
}

function showEvidence(id) {
  S.evOpen = id; S.evFilter = ''; $('evq').value = '';
  setView('evidence');
  loadEvidence().then(() => { const el = $('ev-' + id); if (el) el.scrollIntoView({ block: 'center' }); });
}

// One step after an upgrade: every item this version would read differently
// is parsed again. Earlier runs are kept.
async function reparseStale() {
  try {
    const r = await api('/api/evidence/reparse-stale', { method: 'POST' });
    toast(r.queued ? `${fmtInt(r.queued)} item${r.queued === 1 ? '' : 's'} queued for a new parse run` : 'Everything is already up to date');
    pollSoon();
  } catch (e) { fail(e); }
}

// An item's stored status is that of its last finished run; while a new run
// is waiting or under way the row says so instead.
function statusPill(e) {
  if (e.excluded) return h('i', { class: 'pill excluded', title: `Excluded from the case${e.excluded_by === e.id ? '' : ' with #' + e.excluded_by}: ${e.exclude_reason}. Last run: ${e.status}` }, 'excluded');
  if (S.pending.has(e.id)) {
    const now = S.currentId === e.id;
    return h('i', { class: 'pill ' + (now ? 'processing' : 'queued'), title: `A new parse run is ${now ? 'under way' : 'waiting'}. The last finished run: ${e.status}` }, now ? 'processing' : 'queued');
  }
  return h('i', { class: 'pill ' + e.status }, e.status);
}

// Excluding needs a reason, which is kept in the case and the audit log.
function excludeForm(e) {
  const reason = h('input', { type: 'text', class: 'excludereason', placeholder: 'Why is it being excluded? (kept in the case and the audit log)', maxlength: '500', onclick: (c) => c.stopPropagation() });
  const go = h('button', { class: 'primary', onclick: (c) => { c.stopPropagation(); setExcluded(e.id, true, reason.value); } }, 'Exclude');
  reason.addEventListener('keydown', (k) => { if (k.key === 'Enter') go.click(); if (k.key === 'Escape') { S.excluding = null; renderEvidence(); } });
  setTimeout(() => reason.focus(), 0);
  return h('div', { class: 'excludeform', onclick: (c) => c.stopPropagation() },
    h('p', { class: 'hint' }, `Take #${e.id} ${e.name}` + (S.evidence.some((x) => x.parent_id === e.id) ? ', and everything that came out of it,' : '') +
      ' out of the timeline, its counts, exports, the report\'s timeline and the checks. Nothing is deleted: the file stays in the vault and its runs stay verifiable, and you can include it again.'),
    reason, go,
    h('button', { onclick: (c) => { c.stopPropagation(); S.excluding = null; renderEvidence(); } }, 'Cancel'));
}

async function setExcluded(id, exclude, reason) {
  if (exclude && !reason.trim()) { toast('Say why it is being excluded: the reason is kept in the case'); return; }
  try {
    await api(`/api/evidence/${id}/exclude`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ exclude, reason }) });
    S.excluding = null;
    toast(exclude ? `Evidence #${id} excluded from the case` : `Evidence #${id} included again`);
    refreshAll();
  } catch (e) { fail(e); }
}

async function reassignDialog(e) {
  let hosts = [];
  try { hosts = (await api('/api/hosts')).hosts; } catch (err) { fail(err); return; }
  const dlg = $('dlg');
  const pick = h('select', { 'aria-label': 'Host' }, hosts.map((x) => h('option', { value: 'h' + x.id }, x.name)), h('option', { value: 'none' }, 'Not from a host…'));
  const where = h('textarea', { rows: 3, placeholder: 'Where it came from', 'aria-label': 'Where the evidence came from', maxlength: '4000' });
  const whereRow = h('label', { class: 'dlgrow' }, h('span', {}, 'Where it came from'), where);
  if (e.assigned && e.assigned.host_id) pick.value = 'h' + e.assigned.host_id; else if (e.assigned) { pick.value = 'none'; where.value = e.assigned.source || ''; } else if (!hosts.length) pick.value = 'none';
  const sync = () => { whereRow.hidden = pick.value !== 'none'; };
  pick.addEventListener('change', sync); sync();
  const save = async () => {
    const body = pick.value === 'none' ? { not_from_host: where.value.trim() } : { host_id: Number(pick.value.slice(1)) };
    if (pick.value === 'none' && !body.not_from_host) { toast('Say where the evidence came from', true); return; }
    try {
      const r = await api(`/api/submissions/${e.batch_id}/host`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      dlg.close();
      toast(`Submission ${e.batch_id} reassigned; ${fmtInt(r.reparsing)} item${r.reparsing === 1 ? '' : 's'} being parsed again`);
      pollSoon();
    } catch (err) { fail(err); }
  };
  dlg.replaceChildren(h('h2', {}, `Which host is submission ${e.batch_id} from?`),
    h('p', { class: 'hint' }, 'Everything added together with this item moves with it. Its items are parsed again as new runs (earlier runs are kept), so their events carry the host and its time zone. Tags and comments stay with the earlier events.'),
    h('label', { class: 'dlgrow' }, h('span', {}, 'From'), pick), whereRow,
    h('div', { class: 'actions' }, h('button', { onclick: () => dlg.close() }, 'Cancel'), h('button', { class: 'primary', onclick: save }, 'Save')));
  dlg.showModal();
}

async function reparse(id) {
  try {
    await api(`/api/evidence/${id}/reparse`, { method: 'POST' });
    S.pending.add(id);
    renderEvidence();
    toast(`Evidence #${id} queued for a new parse run`);
    pollSoon();
  } catch (e) { fail(e); }
}

// ---- files: looking inside disk and disc images ----
const IMAGE_KINDS = ['iso-image', 'disk-image', 'ntfs-volume-image', 'fat-volume-image', 'ext-volume-image', 'thumbnail-cache', 'ewf-image', 'vhd-image', 'vhdx-image', 'vmdk-image'];
const isImage = (e) => IMAGE_KINDS.includes(e.kind) && !e.duplicate_of;

function renderImagePicker() {
  const images = S.evidence.filter(isImage);
  const pick = $('imgpick');
  pick.replaceChildren(...(images.length
    ? images.map((e) => h('option', { value: String(e.id), selected: e.id === S.img }, `#${e.id} ${e.name} (${fmtSize(e.size)})`))
    : [h('option', { value: '' }, 'No disk or disc images in this case')]));
  pick.disabled = !images.length;
  $('imgstd').disabled = !images.length;
  if (!images.length) {
    S.img = null;
    $('imgdesc').textContent = '';
    $('crumbs').replaceChildren();
    $('imgrows').replaceChildren(h('div', { class: 'evdetail hint' },
      'Add a disk image (raw or dd, with NTFS volumes) or an ISO as evidence. It is stored and hashed like anything else, and then appears here so you can look inside it and choose what goes on the timeline.'));
    return;
  }
  if (!images.some((e) => e.id === S.img)) { S.img = images[0].id; S.imgPath = '/'; }
  browse(S.imgPath);
}

async function browse(path) {
  if (S.img == null) return;
  S.imgPath = path;
  S.imgChecked.clear();
  try {
    const r = await api(`/api/evidence/${S.img}/browse?path=` + encodeURIComponent(path));
    $('imgdesc').textContent = r.describe;
    S.imgEntries = r.entries;
  } catch (e) {
    S.imgEntries = [];
    $('imgdesc').textContent = '';
    $('imgrows').replaceChildren(h('div', { class: 'evdetail' }, h('div', { class: 'note warn' }, 'This image could not be read: ' + e.message)));
    renderCrumbs();
    return;
  }
  renderCrumbs();
  renderImageRows();
}

function renderCrumbs() {
  const parts = S.imgPath.split('/').filter(Boolean);
  const out = [h('button', { class: 'link', onclick: () => browse('/') }, 'image root')];
  parts.forEach((p, i) => {
    out.push(h('span', {}, '/'));
    const to = '/' + parts.slice(0, i + 1).join('/');
    out.push(i === parts.length - 1 ? document.createTextNode(p) : h('button', { class: 'link', onclick: () => browse(to) }, p));
  });
  $('crumbs').replaceChildren(...out);
}

function renderImageRows() {
  const rows = S.imgEntries.map((e) => {
    const box = h('input', { type: 'checkbox', checked: S.imgChecked.has(e.path), title: e.is_dir ? 'Select this folder and everything in it' : 'Select this file' });
    box.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (box.checked) S.imgChecked.add(e.path); else S.imgChecked.delete(e.path);
      renderImageButtons();
    });
    // A partition Atropos cannot read is listed but cannot be opened or chosen.
    const openable = e.is_dir;
    const dead = !e.is_dir && e.note && /not readable/.test(e.note);
    return h('div', { class: 'frow' + (openable ? ' dir' : ''), onclick: openable ? () => browse(e.path) : null },
      h('span', {}, dead ? null : box),
      h('span', { class: 'fname', title: e.path }, e.name + (e.is_dir ? '/' : '')),
      h('span', { class: 'num' }, e.is_dir && !e.size ? '' : fmtSize(e.size)),
      h('span', { class: 'time' }, e.modified !== '0' ? fmtNs(e.modified, 0) : ''),
      h('span', { class: 'time' }, e.born !== '0' ? fmtNs(e.born, 0) : ''),
      h('span', { class: 'notes', title: e.note || '' }, e.note || ''));
  });
  $('imgrows').replaceChildren(...(rows.length ? rows : [h('div', { class: 'evdetail hint' }, 'This folder is empty.')]));
  renderImageButtons();
}

function showImageEvents() {
  if (S.img == null) return;
  setView('timeline');
  setQuery('from:' + S.img);
}

function renderImageButtons() {
  const n = S.imgChecked.size;
  $('imgadd').disabled = !n;
  $('imgadd').textContent = n ? `Add ${fmtInt(n)} selected to timeline` : 'Add selected to timeline';
  const all = $('imgall');
  all.checked = n > 0 && n >= S.imgEntries.length;
  all.indeterminate = n > 0 && n < S.imgEntries.length;
}

async function extractFromImage(body, what) {
  try {
    await api(`/api/evidence/${S.img}/extract`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    toast(`Copying ${what} out of the image. Each file is hashed, added as evidence and parsed.`);
    S.imgChecked.clear();
    renderImageRows();
    pollSoon();
  } catch (e) { fail(e); }
}

// ---- analysis ----
const KIND_TITLES = {
  'modified-earlier-than-shimcache': 'Modified earlier than ShimCache recorded',
  'built-after-file-times': 'Built after its own creation and modification times',
  'created-earlier-than-older-record': 'Created earlier than an older copy of its own times',
  'created-earlier-than-journal': 'Created earlier than the change journal recorded',
};
let analysisLoaded = false;
function fmtGap(s) {
  if (s >= 2 * 86400) return fmtInt(Math.floor(s / 86400)) + ' days';
  if (s >= 2 * 3600) return Math.floor(s / 3600) + ' hours';
  if (s >= 120) return Math.floor(s / 60) + ' minutes';
  return s + ' seconds';
}
function showEvents(ids) {
  S.group = ''; S.zoom = []; S.from = S.to = null; S.selected = null;
  S.q = 'id:' + ids.join(',');
  $('q').value = S.q;
  setView('timeline');
  loadFacets();
  reload();
}
let anMode = 'anomalies';
function setAnMode(m) {
  anMode = m;
  for (const b of $('anmode').children) b.classList.toggle('on', b.dataset.mode === m);
  $('anintro-anomalies').hidden = m !== 'anomalies';
  $('anintro-timestamps').hidden = m !== 'timestamps';
  $('antag').hidden = m !== 'anomalies';
  loadAnalysis();
}
async function loadAnomalies() {
  $('ansummary').replaceChildren('Looking…');
  $('anrows').replaceChildren();
  $('ancompared').replaceChildren();
  $('antag').disabled = true;
  try {
    const r = await api('/api/analysis/anomalies');
    if (anMode !== 'anomalies') return;
    const kinds = Object.fromEntries(r.kinds.map((k) => [k.kind, k]));
    $('ansummary').replaceChildren(h('b', {}, fmtInt(r.findings.length)), r.findings.length === 1 ? ' thing out of place in ' : ' things out of place in ',
      h('b', {}, fmtInt(r.scanned)), ' events', r.texts ? ` and the text of ${fmtInt(r.texts)} file${r.texts === 1 ? '' : 's'}` : '');
    $('antag').disabled = !r.findings.some((f) => f.events);
    $('ancompared').replaceChildren(...r.kinds.filter((k) => r.counts[k.kind]).map((k) =>
      h('span', { class: 'chip static' }, k.title, h('i', {}, fmtInt(r.counts[k.kind])))));
    const out = [];
    let last = '';
    for (const f of r.findings) {
      if (f.kind !== last) {
        last = f.kind;
        const k = kinds[f.kind] || { title: f.kind, why: '', caveat: '' };
        out.push(h('div', { class: 'anhead' },
          h('h3', {}, k.title, h('span', { class: 'count' }, ' ' + fmtInt(r.counts[f.kind]))),
          h('p', {}, k.why), h('p', { class: 'hint' }, 'Caution: ' + k.caveat)));
      }
      // A finding in a file's text has no event: it opens the file instead.
      if (f.evidence_id) {
        out.push(h('div', { class: 'anrow' },
          h('div', { class: 'anpath' }, h('span', { class: 'mono' }, f.subject)),
          f.detail ? h('div', { class: 'antext' }, f.detail) : '',
          h('div', {}, h('button', { class: 'link', onclick: () => showEvidence(f.evidence_id) }, `Open #${f.evidence_id} ${f.evidence} under Evidence`))));
        continue;
      }
      out.push(h('div', { class: 'anrow' },
        h('div', { class: 'anpath' }, h('span', { class: 'mono' }, f.subject), f.host ? h('span', { class: 'dimc' }, f.host) : ''),
        f.detail ? h('div', { class: 'antext' }, f.detail) : '',
        h('div', { class: 'antimes' },
          h('span', {}, 'Seen in ', h('b', {}, f.sources.join(', '))),
          h('span', {}, 'First ', h('b', { class: 'mono' }, f.first)),
          f.last !== f.first ? h('span', {}, 'Last ', h('b', { class: 'mono' }, f.last)) : ''),
        h('div', {}, h('button', { class: 'link', onclick: () => showEvents(f.event_ids) },
          f.events > f.event_ids.length ? `Show the first ${f.event_ids.length} of ${fmtInt(f.events)} events on the timeline`
            : (f.events === 1 ? 'Show the event on the timeline' : `Show the ${f.events} events on the timeline`)))));
    }
    if (!r.findings.length) out.push(h('p', { class: 'anempty' }, 'Nothing matched. That is not the same as nothing being wrong.'));
    out.push(h('div', { class: 'anhead' }, h('h3', {}, 'Notes'), h('ul', { class: 'annotes' }, ...r.notes.map((n) => h('li', {}, n)))));
    $('anrows').replaceChildren(...out);
  } catch (e) { $('ansummary').replaceChildren('The checks failed'); fail(e); }
}
async function tagAnomalies() {
  $('antag').disabled = true;
  try {
    const r = await api('/api/analysis/anomalies/tag', { method: 'POST' });
    $('ansummary').replaceChildren(r.tags_added ? `${fmtInt(r.tags_added)} tags added. Search the timeline for tag:anomaly` : 'Every event listed already carries its tags');
    reload();
  } catch (e) { fail(e); }
  $('antag').disabled = false;
}
async function loadAnalysis() {
  analysisLoaded = true;
  if (anMode === 'anomalies') return loadAnomalies();
  $('ansummary').replaceChildren('Comparing…');
  $('anrows').replaceChildren();
  try {
    const r = await api('/api/analysis/timestamps');
    if (anMode !== 'timestamps') return;
    const total = Object.values(r.counts).reduce((a, b) => a + b, 0);
    $('ansummary').replaceChildren(h('b', {}, fmtInt(total)), total === 1 ? ' finding' : ' findings');
    $('ancompared').replaceChildren(h('span', { class: 'label' }, 'Compared'),
      ...Object.keys(r.compared).sort().map((k) => h('span', { class: 'chip static' }, k, h('i', {}, fmtInt(r.compared[k])))),
      ...(Object.keys(r.compared).length ? [] : [h('span', { class: 'hint' }, 'nothing')]));
    const out = [];
    let last = '';
    for (const f of r.findings) {
      if (f.kind !== last) {
        last = f.kind;
        out.push(h('div', { class: 'anhead' },
          h('h3', {}, KIND_TITLES[f.kind] || f.kind, h('span', { class: 'count' }, ' ' + fmtInt(r.counts[f.kind]))),
          h('p', { class: 'hint' }, 'Caution: ' + f.caveat)));
      }
      out.push(h('div', { class: 'anrow' },
        h('div', { class: 'anpath' }, h('span', { class: 'mono' }, f.path),
          f.also_flagged_in_file_table ? h('span', { class: 'chip static assumed', title: 'The file table itself also shows $SI earlier than $FN, or zeroed sub-seconds, for this file' }, 'also flagged in the file table') : '',
          f.host ? h('span', { class: 'dimc' }, f.host) : ''),
        h('div', { class: 'antimes' },
          h('span', {}, 'File table ', h('b', { class: 'mono' }, f.file_time)),
          h('span', {}, 'Other record ', h('b', { class: 'mono' }, f.other_time)),
          h('span', {}, 'Apart by ', h('b', {}, fmtGap(f.gap_seconds)))),
        h('div', { class: 'antext' }, f.summary),
        h('div', {}, h('button', { class: 'link', onclick: () => showEvents(f.event_ids) }, `Show the ${f.event_ids.length} events compared on the timeline`))));
    }
    if (!r.findings.length) out.push(h('p', { class: 'anempty' }, 'No contradictions found in what could be compared.'));
    out.push(h('div', { class: 'anhead' }, h('h3', {}, 'Notes'), h('ul', { class: 'annotes' }, ...r.notes.map((n) => h('li', {}, n)))));
    $('anrows').replaceChildren(...out);
  } catch (e) { $('ansummary').replaceChildren('The comparison failed'); fail(e); }
}

// ---- case and host details ----
// newHosts are hosts added in this session that have nothing saved yet.
const newHosts = [];
// host === null is a host no one has named yet: the form then starts with
// the computer's name, which is how the host is known in the case and report.
function detailForm(title, host, fields, values, found, opened) {
  const inputs = {};
  const groups = [];
  let group = null;
  let nameInput = null;
  if (host === null) {
    nameInput = h('input', { type: 'text', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Computer name', placeholder: 'e.g. DESKTOP-4F2K1' });
    group = { name: fields.length ? fields[0].group : 'Identification', rows: [h('label', { class: 'dtrow' },
      h('span', { class: 'dtlabel' }, 'Computer name'),
      h('span', { class: 'dtfield' }, nameInput, h('span', { class: 'hint' }, 'Required. The name the host is known by in the case and the report; usually the Windows computer name'))) ] };
    groups.push(group);
  }
  for (const f of fields) {
    if (!group || group.name !== f.group) { group = { name: f.group, rows: [] }; groups.push(group); }
    const cur = values[f.key];
    const input = f.long ? h('textarea', { rows: 3, spellcheck: 'false' }) : h('input', { type: 'text', spellcheck: 'false', autocomplete: 'off', list: f.key === 'time_zone' ? 'tzlist' : null });
    input.value = cur ? cur.value : '';
    input.setAttribute('aria-label', (host ? host + ': ' : '') + f.label);
    inputs[f.key] = input;
    group.rows.push(h('label', { class: 'dtrow' },
      h('span', { class: 'dtlabel' }, f.label),
      h('span', { class: 'dtfield' }, input,
        f.hint ? h('span', { class: 'hint' }, f.hint) : '',
        found && found[f.key] ? h('span', { class: 'dtfound' }, 'Read from the evidence: ', h('b', {}, found[f.key])) : '',
        cur ? h('span', { class: 'hint' }, `Stated by ${cur.actor}, ${fmtNs(BigInt(cur.made_utc), 0)} UTC`) : '')));
  }
  const status = h('span', { class: 'hint' });
  const save = h('button', { class: 'primary' }, 'Save');
  const stated = Object.keys(values).length;
  const form = h('details', { class: 'dtform', open: opened },
    h('summary', {}, h('b', {}, title), h('span', { class: 'count' }, ` ${stated} of ${fields.length} stated`)),
    ...groups.map((g) => h('fieldset', {}, h('legend', {}, g.name), ...g.rows)),
    h('div', { class: 'dtsave' }, save, status));
  save.onclick = async () => {
    const out = {};
    for (const [k, el] of Object.entries(inputs)) out[k] = el.value;
    const name = nameInput ? nameInput.value.trim() : host;
    if (nameInput && !name) { toast("Give the computer's name: it is how this host is known in the case and the report", true); nameInput.focus(); return; }
    if (nameInput && !Object.values(out).some((v) => v.trim())) { addDetailHost(name); return; }
    save.disabled = true;
    try {
      const r = await api('/api/details', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host: name, values: out }) });
      toast(r.changed ? `${r.changed} ${r.changed === 1 ? 'detail' : 'details'} saved` : 'Nothing had changed');
      const i = newHosts.indexOf(name);
      if (i >= 0 && r.changed) newHosts.splice(i, 1);
      await loadDetails(name);
    } catch (e) { fail(e); save.disabled = false; }
  };
  return form;
}
async function loadDetails(openHost) {
  try {
    const d = await api('/api/details');
    const names = d.hosts.map((x) => x.name.toLowerCase());
    const pending = newHosts.filter((n) => !names.includes(n.toLowerCase()));
    $('dtsummary').replaceChildren(h('b', {}, fmtInt(d.hosts.length)), d.hosts.length === 1 ? ' host with details' : ' hosts with details');
    $('dtknown').replaceChildren(...d.known_hosts.map((n) => h('option', { value: n })));
    const out = [detailForm('Case', '', d.case_fields, d.case, null, openHost === '' || (!d.hosts.length && !pending.length))];
    for (const x of d.hosts) out.push(detailForm('Host ' + x.name, x.name, d.host_fields, x.values, x.found, openHost === x.name));
    for (const n of pending) out.push(detailForm('Host ' + n + ' (nothing saved yet)', n, d.host_fields, {}, null, true));
    // Hosts the evidence names but no one has described yet: their forms, ready.
    for (const n of d.known_hosts.filter((n) => !pending.some((p) => p.toLowerCase() === n.toLowerCase()))) {
      out.push(detailForm('Host ' + n + ' (named by the evidence)', n, d.host_fields, {}, null, false));
    }
    if (!d.hosts.length && !pending.length && !d.known_hosts.length) {
      out.push(h('p', { class: 'hint dtnohost' }, "The evidence names no host: Atropos reads a computer's name and time zone from its SYSTEM registry hive, and there is none in this case. Describe the host here, giving its name, or add the SYSTEM hive."));
      out.push(detailForm('Host', null, d.host_fields, {}, null, true));
    }
    $('dtbody').replaceChildren(...out);
  } catch (e) { fail(e); }
}
async function addDetailHost(name) {
  name = (name || '').trim();
  if (!name) { toast('Give the host a name first', true); return; }
  try {
    const hst = await api('/api/hosts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    $('dthost').value = '';
    toast(`Host ${hst.name} added`);
    loadDetails(hst.name);
  } catch (e) { fail(e); }
}

// ---- audit ----
async function loadAudit() {
  try {
    const { audit } = await api('/api/audit?limit=2000');
    $('auditsummary').replaceChildren('Newest first. Showing ', h('b', {}, fmtInt(audit.length)),
      audit.length && audit[audit.length - 1].id > 1 ? ` of ${fmtInt(audit[0].id)} entries` : ' entries');
    $('auditrows').replaceChildren(...audit.map((a) => h('div', { class: 'arow' },
      h('span', { class: 'dimc' }, a.id),
      h('span', { class: 'time' }, fmtNs(a.ts_utc, 3)),
      h('span', {}, a.actor),
      h('span', {}, a.action),
      h('span', { class: 'dimc' }, a.target),
      h('span', { class: 'details', title: JSON.stringify(a.details, null, 1) }, JSON.stringify(a.details)),
      h('span', { class: 'mono dimc', title: a.hash }, a.hash.slice(0, 12) + '…'))));
  } catch (e) { fail(e); }
}

// ---- verify ----
async function verify() {
  const dlg = $('dlg');
  dlg.replaceChildren(h('h2', {}, 'Verifying integrity…'),
    h('p', { class: 'hint' }, 'Re-hashing every stored file, recomputing every run\'s event digest and walking the audit chain.'));
  dlg.showModal();
  try {
    const r = await api('/api/verify', { method: 'POST' });
    const check = (ok, title, detail) => h('div', { class: 'check' },
      h('span', { class: 'mark ' + (ok ? 'ok' : 'bad') }, ok ? '✓' : '✗'), h('span', {}, title), detail ? h('small', {}, detail) : null);
    dlg.replaceChildren(
      h('h2', {}, 'Integrity check'),
      h('div', { class: 'verdict ' + (r.ok ? 'ok' : 'bad') }, r.ok ? 'Everything verifies' : 'VERIFICATION FAILED'),
      check(!r.evidence_bad.length, `${fmtInt(r.evidence_checked)} stored files re-hashed against their recorded SHA-256`, r.evidence_bad.join('\n')),
      check(!r.runs_bad.length, `${fmtInt(r.runs_checked)} parse runs: event digests recomputed from stored events`,
        r.runs_bad.length ? 'Events no longer match their run: runs ' + r.runs_bad.join(', ') : ''),
      check(!r.runs_unaudited.length && !r.runs_missing.length, 'Parse runs compared with what the audit log recorded when each was sealed',
        [r.runs_unaudited.length ? 'Not vouched for by the audit log: runs ' + r.runs_unaudited.join(', ') : '',
          r.runs_missing.length ? 'Sealed in the audit log but now missing: runs ' + r.runs_missing.join(', ') : ''].filter(Boolean).join('. ')),
      check(!r.audit_broken_at, `${fmtInt(r.audit_entries)} audit entries: hash chain walked`,
        r.audit_broken_at ? `The chain is broken at entry ${r.audit_broken_at}` : ''),
      h('h3', {}, 'Audit chain head'),
      h('pre', {}, r.audit_head),
      h('p', { class: 'hint' }, `Checked ${r.checked_utc}. Record the head hash somewhere outside the case: it is what proves later that no entries were removed from the end of the log.`),
      h('div', { class: 'actions' }, h('button', { onclick: () => dlg.close() }, 'Close')));
    if (S.view === 'audit') loadAudit();
  } catch (e) { dlg.close(); fail(e); }
}

// ---- adding evidence ----
// Where evidence comes from is stated before it is sent: a host described in
// the case, or no host and a description of where it came from. The last
// choice is offered again. A drop opens the same dialog with its files.
let lastSource = null; // { host: id } or { notFromHost: text }
async function addDialog(dropped) {
  let hosts = [];
  try { hosts = (await api('/api/hosts')).hosts; } catch (e) { fail(e); return; }
  const dlg = $('dlg');
  const pick = h('select', { 'aria-label': 'Where the evidence comes from' },
    hosts.map((x) => h('option', { value: 'h' + x.id }, x.name)),
    h('option', { value: 'none' }, 'Not from a host…'));
  const where = h('textarea', { rows: 3, placeholder: 'Where it came from, e.g. firewall logs exported from the perimeter firewall by IT on 23 Nov', 'aria-label': 'Where the evidence came from', maxlength: '4000' });
  const whereRow = h('label', { class: 'dlgrow' }, h('span', {}, 'Where it came from'), where);
  if (lastSource && lastSource.host && hosts.some((x) => x.id === lastSource.host)) pick.value = 'h' + lastSource.host;
  else if (!hosts.length || (lastSource && lastSource.notFromHost != null)) pick.value = 'none';
  if (lastSource && lastSource.notFromHost) where.value = lastSource.notFromHost;
  const sync = () => { whereRow.hidden = pick.value !== 'none'; };
  pick.addEventListener('change', sync);
  sync();
  // The choice, checked: null when something is missing (and the reason shown).
  const chosen = () => {
    if (pick.value === 'none') {
      if (!where.value.trim()) { toast('Say where the evidence came from: it is kept with it and shown in the report', true); where.focus(); return null; }
      return { notFromHost: where.value.trim() };
    }
    return { host: Number(pick.value.slice(1)) };
  };
  const go = (fn) => () => { const c = chosen(); if (!c) return; lastSource = c; dlg.close(); fn(c); };
  const size = dropped ? dropped.reduce((n, x) => n + x.file.size, 0) : 0;
  dlg.replaceChildren(
    h('h2', {}, dropped ? `Add ${fmtInt(dropped.length)} file${dropped.length === 1 ? '' : 's'} (${fmtSize(size)})` : 'Add evidence'),
    hosts.length ? null : h('p', { class: 'note warn' }, 'No host is described in this case yet. Describe the computer the evidence comes from on the ',
      h('button', { class: 'link', onclick: () => { dlg.close(); setView('details'); } }, 'Details tab'), ' first, or add it as not from a host.'),
    h('label', { class: 'dlgrow' }, h('span', {}, 'From'), pick),
    whereRow,
    h('p', { class: 'hint' }, 'Each file is hashed, copied into the case vault and identified by its content; originals are opened read-only. Its events carry the host, and a time zone stated for the host on the Details tab is used for times the files record in local time. Add a host\'s artefacts together.'),
    dropped ? null : h('p', { class: 'hint' }, 'You can also drop files or folders anywhere on the page.'),
    h('div', { class: 'actions' },
      h('button', { onclick: () => dlg.close() }, 'Cancel'),
      dropped ? null : h('button', { onclick: go((c) => { S.pendingSource = c; $('pickdir').click(); }) }, 'Choose a folder'),
      dropped ? h('button', { class: 'primary', onclick: go((c) => upload(dropped, c)) }, 'Add')
        : h('button', { class: 'primary', onclick: go((c) => { S.pendingSource = c; $('pickfiles').click(); }) }, 'Choose files')));
  dlg.showModal();
}

// Walks dropped folders. Entries must be taken from the drop event before
// anything asynchronous happens, or the browser discards them.
async function filesFromDrop(dt) {
  const entries = [...dt.items].map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
  const loose = [...dt.files];
  const out = [];
  let shown = 0;
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      const file = await new Promise((ok, no) => entry.file(ok, no));
      out.push({ file, path: prefix + entry.name });
      if (out.length - shown >= 200) { shown = out.length; showIngest(`Reading the folder…  ${fmtInt(out.length)} files found`); }
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) { // readEntries returns results in batches until it returns none
        const batch = await new Promise((ok, no) => reader.readEntries(ok, no));
        if (!batch.length) break;
        for (const child of batch) await walk(child, prefix + entry.name + '/');
      }
    }
  };
  if (entries.some(Boolean)) {
    showIngest('Reading the folder…');
    try {
      for (const e of entries) if (e) await walk(e, '');
    } finally { showIngest(null); }
    return out;
  }
  return loose.map((file) => ({ file, path: file.name }));
}

// Files go to the server in chunks, all into one submission, so that a file
// the browser cannot read (locked, or changing while a program has it open)
// costs that file and not the whole upload. After a chunk breaks off the page
// asks what arrived and sends the rest one by one; a file that still cannot be
// sent is listed for the examiner and recorded in the audit log. The server
// parses the submission when the last request closes it.
const CHUNK_FILES = 100, CHUNK_BYTES = 200 * 1024 * 1024;
const normPath = (p) => p.replace(/\\/g, '/').replace(/^\/+/, '');

function postFiles(files, batch, final, onProgress, source) {
  return new Promise((resolve) => {
    const fd = new FormData();
    for (const { file, path } of files) fd.append('file', file, path);
    const xhr = new XMLHttpRequest();
    xhr.upload.onprogress = (p) => { if (p.lengthComputable && onProgress) onProgress(p.loaded); };
    xhr.onerror = () => resolve({ status: 0, body: null });
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      resolve({ status: xhr.status, body });
    };
    const q = batch ? { batch, final: final ? '1' : '0' } : { final: final ? '1' : '0' };
    if (!batch && source) { if (source.host) q.host = String(source.host); else q.not_from_host = source.notFromHost; }
    xhr.open('POST', '/api/upload?' + new URLSearchParams(q));
    xhr.send(fd);
  });
}

// "Uploading 120 of 2,000 files · 310 MB of 1.2 GB (26%) · 40 MB/s · about 25 s left"
function uploadProgress(total, count) {
  const started = Date.now();
  return (files, bytes) => {
    const secs = (Date.now() - started) / 1000;
    const pct = total ? Math.floor(bytes / total * 100) : 0;
    let tail = '';
    if (secs >= 2 && bytes > 0) {
      const rate = bytes / secs;
      const left = (total - bytes) / rate;
      tail = `  ·  ${fmtSize(Math.round(rate))}/s` + (left >= 1 ? `  ·  about ${left < 90 ? Math.ceil(left) + ' s' : Math.ceil(left / 60) + ' min'} left` : '');
    }
    showIngest(`Uploading ${fmtInt(files)} of ${fmtInt(count)} file${count === 1 ? '' : 's'}  ·  ${fmtSize(bytes)} of ${fmtSize(total)} (${pct}%)${tail}`, bytes, total || 1);
  };
}

// Leaving the page mid-upload would cut it short; ask first.
window.addEventListener('beforeunload', (ev) => { if (S.uploading) { ev.preventDefault(); ev.returnValue = ''; } });

async function upload(list, source) {
  if (!list.length) { toast('Nothing to add: no files were found'); return; }
  const total = list.reduce((n, x) => n + x.file.size, 0);
  const progress = uploadProgress(total, list.length);
  S.uploading = true;
  progress(0, 0);
  const finish = (msg, bad) => { S.uploading = false; showIngest(null); if (msg) toast(msg, bad); };

  // Open the submission.
  const opened = await postFiles([], null, false, null, source);
  if (opened.status !== 200) { finish(opened.body && opened.body.error ? opened.body.error : 'The upload failed: Atropos could not be reached', true); return; }
  const batch = opened.body.batch;

  const chunks = [];
  let cur = [], size = 0;
  for (const x of list) {
    if (cur.length && (cur.length >= CHUNK_FILES || size + x.file.size > CHUNK_BYTES)) { chunks.push(cur); cur = []; size = 0; }
    cur.push(x); size += x.file.size;
  }
  if (cur.length) chunks.push(cur);

  let sentBytes = 0, sentFiles = 0;
  const unreadable = [];
  for (const chunk of chunks) {
    const bytes = chunk.reduce((n, x) => n + x.file.size, 0);
    const r = await postFiles(chunk, batch, false, (loaded) => progress(sentFiles + Math.floor(chunk.length * loaded / Math.max(1, bytes)), sentBytes + Math.min(loaded, bytes)));
    if (r.status !== 200) {
      // Find out what of this chunk arrived, and send the rest one by one.
      let have = new Set();
      try { have = new Set((await api(`/api/upload/${batch}`)).paths); } catch { /* the submission is gone */ }
      for (const x of chunk) {
        if (have.has(normPath(x.path))) continue;
        showIngest(`Retrying files one by one after a file could not be read  ·  ${x.path}`, sentBytes, total || 1);
        const one = await postFiles([x], batch, false);
        if (one.status !== 200) unreadable.push(x.path);
      }
    }
    sentBytes += bytes; sentFiles += chunk.length;
    progress(sentFiles, sentBytes);
  }
  showIngest('Finishing the upload…', total || 1, total || 1);
  if (unreadable.length) {
    try { await api('/api/upload/unreadable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ batch, paths: unreadable, error: 'the browser could not read the file, or it changed while being sent' }) }); } catch { /* shown below all the same */ }
  }
  const closed = await postFiles([], batch, true);
  if (closed.status !== 200) {
    finish((closed.body && closed.body.error) || 'The upload could not be finished: Atropos could not be reached. What arrived is parsed within two minutes.', true);
    return;
  }
  const stored = list.length - unreadable.length;
  finish(`${fmtInt(stored)} file${stored === 1 ? '' : 's'} hashed and stored as submission ${batch}. Parsing…`);
  if (unreadable.length) unreadableDialog(batch, unreadable);
  pollSoon();
}

// Files the browser could not send: usually locked or in use by a running
// program (a browser's own profile while it is open). They are not in the case.
function unreadableDialog(batch, paths) {
  const dlg = $('dlg');
  dlg.replaceChildren(
    h('h2', {}, `${fmtInt(paths.length)} file${paths.length === 1 ? '' : 's'} could not be added`),
    h('p', {}, `Everything else is in submission ${batch}. The browser could not read ${paths.length === 1 ? 'this file' : 'these files'}, or ${paths.length === 1 ? 'it' : 'they'} changed while being sent: usually because a program has ${paths.length === 1 ? 'it' : 'them'} open, as a web browser does with its own profile. Close that program and add ${paths.length === 1 ? 'it' : 'them'} again. The list is recorded in the audit log.`),
    h('pre', { class: 'unreadable' }, paths.slice(0, 200).join('\n') + (paths.length > 200 ? `\n… and ${fmtInt(paths.length - 200)} more` : '')),
    h('div', { class: 'actions' }, h('button', { class: 'primary', onclick: () => dlg.close() }, 'OK')));
  dlg.showModal();
}

function setupDrop() {
  let depth = 0;
  const isFiles = (ev) => ev.dataTransfer && [...ev.dataTransfer.types].includes('Files');
  window.addEventListener('dragenter', (ev) => { if (isFiles(ev)) { depth++; $('drop').hidden = false; ev.preventDefault(); } });
  window.addEventListener('dragover', (ev) => { if (isFiles(ev)) ev.preventDefault(); });
  window.addEventListener('dragleave', (ev) => { if (isFiles(ev) && --depth <= 0) { depth = 0; $('drop').hidden = true; } });
  window.addEventListener('drop', (ev) => {
    if (!isFiles(ev)) return;
    ev.preventDefault();
    depth = 0; $('drop').hidden = true;
    filesFromDrop(ev.dataTransfer).then((list) => list.length ? addDialog(list) : toast('Nothing to add: no files were found'), fail);
  });
  for (const id of ['pickfiles', 'pickdir']) {
    $(id).addEventListener('change', (ev) => {
      upload([...ev.target.files].map((file) => ({ file, path: file.webkitRelativePath || file.name })), S.pendingSource);
      ev.target.value = '';
    });
  }
}

// ---- ingest status ----
function showIngest(text, done, total) {
  const el = $('ingest');
  if (!text) { el.hidden = true; return; }
  el.replaceChildren(h('progress', total ? { value: String(done), max: String(total) } : {}), h('span', {}, text));
  el.hidden = false;
}
function setIngest(st) {
  if (st && st.last && st.last !== S.lastExtract) {
    // The first status after loading the page describes work done earlier.
    if (S.lastExtract !== '' || S.busy) toast(st.last);
    S.lastExtract = st.last;
  } else if (st && !st.last && S.lastExtract === '') S.lastExtract = ' ';
  if (S.uploading) return;
  S.pending = new Set(st && st.pending ? st.pending.map(Number) : []);
  S.currentId = st && st.current_id ? Number(st.current_id) : 0;
  const was = S.busy;
  S.busy = !!(st && st.busy);
  if (S.busy) {
    showIngest(st.current ? `Processing ${st.current}` + (st.queued ? `  (${st.done} of ${st.queued})` : '') : 'Processing…', st.done, st.queued);
  } else showIngest(null);
  if (was && !S.busy) refreshAll(); // a submission just finished: everything on screen may be stale
}
// The timeline is reloaded now if it is in view, else when it next is.
let timelineStale = false;
function refreshAll() {
  loadCase(); loadEvidence(); loadGroups();
  if (S.view === 'timeline') reload(); else timelineStale = true;
  if (S.view === 'audit') loadAudit();
  analysisLoaded = false;
  if (S.view === 'analysis') loadAnalysis();
  connectionsLoaded = false;
  if (S.view === 'connections') loadConnections();
  if (S.view === 'files') renderImagePicker();
}
let pollTimer;
async function poll() {
  clearTimeout(pollTimer);
  try {
    setIngest(await api('/api/status'));
    if (S.busy && S.view === 'evidence') loadEvidence();
  } catch { /* the server may be restarting; keep trying quietly */ }
  pollTimer = setTimeout(poll, S.busy ? 1000 : 4000);
}
// Called after work is handed to the server. Small files can be parsed before
// the first poll, so the page treats itself as busy from this moment: the next
// idle status then counts as "just finished" and refreshes what is on screen.
function pollSoon() { S.busy = true; clearTimeout(pollTimer); pollTimer = setTimeout(poll, 150); }

// ---- views and wiring ----
// ---- the user guide, one topic at a time ----
// The guide is written in index.html as one article; here each h2 and what
// follows it becomes a topic, shown alone, with the contents list beside it,
// previous and next at the foot, and a search over all topics.
let helpTopics = [];
function setupHelp() {
  const body = document.querySelector('.helpbody');
  const kids = [...body.children];
  let cur = null;
  const intro = [];
  for (const el of kids) {
    if (el.tagName === 'H2') {
      cur = h('section', { class: 'helptopic', 'data-id': el.id });
      helpTopics.push(cur);
      body.appendChild(cur);
    }
    if (cur) cur.appendChild(el); else intro.push(el);
  }
  // The title and introduction open the first topic.
  if (helpTopics.length) helpTopics[0].prepend(...intro);
  helpTopics.forEach((sec, i) => {
    const prev = helpTopics[i - 1], next = helpTopics[i + 1];
    const title = (s) => s.querySelector('h2').textContent;
    sec.appendChild(h('div', { class: 'helpfoot' },
      prev ? h('button', { onclick: () => showHelp(prev.dataset.id) }, '← ' + title(prev)) : h('span'),
      next ? h('button', { class: 'primary', onclick: () => showHelp(next.dataset.id) }, title(next) + ' →') : h('span')));
  });
  $('helptoc').addEventListener('click', (ev) => {
    const b = ev.target.closest('button');
    if (b && b.dataset.to) showHelp(b.dataset.to);
  });
  $('helpq').addEventListener('input', () => searchHelp($('helpq').value));
  $('helpq').addEventListener('keydown', (k) => {
    if (k.key === 'Enter') { // the next topic that matches
      const hits = [...$('helptoc').querySelectorAll('button[data-to]:not([hidden])')];
      const i = hits.findIndex((b) => b.dataset.to === S.help);
      if (hits.length) showHelp(hits[(i + 1) % hits.length].dataset.to);
    }
    if (k.key === 'Escape') { $('helpq').value = ''; searchHelp(''); }
  });
  showHelp(S.help || helpTopics[0].dataset.id, true);
}
function showHelp(id, quiet) {
  if (!helpTopics.some((s) => s.dataset.id === id)) id = helpTopics[0].dataset.id;
  S.help = id;
  for (const s of helpTopics) s.hidden = s.dataset.id !== id;
  for (const b of $('helptoc').querySelectorAll('button[data-to]')) b.classList.toggle('on', b.dataset.to === id);
  document.querySelector('.helpbody').scrollTop = 0;
  if (!quiet) writeHash();
}
// Shows only the topics whose text holds every word typed, and opens the first.
function searchHelp(q) {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  let n = 0, first = null;
  for (const b of $('helptoc').querySelectorAll('button[data-to]')) {
    const sec = helpTopics.find((s) => s.dataset.id === b.dataset.to);
    const text = sec ? sec.textContent.toLowerCase() : '';
    const hit = words.every((w) => text.includes(w));
    b.hidden = !hit;
    if (hit) { n++; first = first || b.dataset.to; }
  }
  for (const g of $('helptoc').querySelectorAll('.tocgroup')) g.hidden = words.length > 0;
  $('helphits').hidden = !words.length;
  $('helphits').textContent = n ? `${n} topic${n === 1 ? '' : 's'} mention ${words.length === 1 ? 'it' : 'them'}. Enter shows the next.` : 'No topic mentions that.';
  if (first && words.length && !$('helptoc').querySelector(`button[data-to="${S.help}"]:not([hidden])`)) showHelp(first);
}

function setView(v) {
  S.view = v;
  writeHash();
  for (const b of $('nav').children) b.classList.toggle('on', b.dataset.view === v);
  for (const name of ['timeline', 'evidence', 'files', 'analysis', 'connections', 'details', 'audit', 'help']) $('view-' + name).hidden = name !== v;
  if (v === 'connections' && !connectionsLoaded) loadConnections();
  if (v === 'details') loadDetails();
  if (v === 'analysis' && !analysisLoaded) loadAnalysis();
  if (v === 'evidence' || v === 'files') loadEvidence();
  if (v === 'audit') loadAudit();
  if (v === 'timeline') {
    if (timelineStale) { timelineStale = false; reload(); } else renderRows();
  }
}

function moveSelection(delta) {
  if (!S.rows.length) return;
  let i = S.rows.findIndex((r) => r.id === S.selected);
  i = i < 0 ? 0 : Math.max(0, Math.min(S.rows.length - 1, i + delta));
  const box = $('rows'), top = i * ROW;
  if (top < box.scrollTop) box.scrollTop = top;
  else if (top + ROW > box.scrollTop + box.clientHeight) box.scrollTop = top + ROW - box.clientHeight;
  select(S.rows[i].id);
}

function init() {
  $('nav').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) setView(b.dataset.view); });
  $('add').onclick = () => addDialog();
  // Zone names for the Details tab's time zone field.
  try { $('tzlist').replaceChildren(...Intl.supportedValuesOf('timeZone').map((z) => h('option', { value: z }))); } catch { /* an older browser: typed by hand */ }
  $('verify').onclick = verify;
  $('anrun').onclick = loadAnalysis;
  setupConnections();
  $('antag').onclick = tagAnomalies;
  $('dtadd').onclick = () => addDetailHost($('dthost').value);
  $('dthost').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') addDetailHost($('dthost').value); });
  $('anmode').addEventListener('click', (ev) => { const b = ev.target.closest('button'); if (b) setAnMode(b.dataset.mode); });

  let typing;
  $('q').addEventListener('input', (ev) => {
    clearTimeout(typing);
    typing = setTimeout(() => { S.q = ev.target.value.trim(); renderOrigin(); loadFacets(); reload(); }, 250);
  });
  $('order').onclick = () => {
    S.desc = !S.desc;
    $('order').textContent = S.desc ? 'Newest first' : 'Oldest first';
    reload();
  };
  $('export').addEventListener('change', (ev) => {
    const format = ev.target.value;
    ev.target.value = '';
    if (!format) return;
    const a = h('a', { href: '/api/export?' + params({ format }), download: '' });
    document.body.append(a); a.click(); a.remove();
    toast('Export started. It is recorded in the audit log.');
  });
  $('report').addEventListener('change', (ev) => {
    const format = ev.target.value;
    ev.target.value = '';
    if (!format) return;
    const a = h('a', { href: '/api/report?format=' + format, download: '' });
    document.body.append(a); a.click(); a.remove();
    toast('Verifying the case and building the report. It will download when ready.');
  });
  $('groupadd').addEventListener('change', (ev) => {
    const v = ev.target.value;
    ev.target.value = '';
    if (!v) return;
    const useSelection = S.checked.size > 0;
    const go = (g) => changeGroup(g, 'add', useSelection);
    if (v === 'new') newGroupDialog(go);
    else go(S.groups.find((g) => String(g.id) === v));
  });
  $('groupremove').onclick = () => { const g = S.groups.find((x) => x.name === S.group); if (g) changeGroup(g, 'remove', true); };
  $('clearsel').onclick = () => { S.checked.clear(); renderSelection(); renderRows(); };
  $('checkall').addEventListener('change', (ev) => {
    if (ev.target.checked) for (const r of S.rows) S.checked.add(r.id); else S.checked.clear();
    renderSelection(); renderRows();
  });
  $('rows').addEventListener('scroll', renderRows, { passive: true });
  $('evq').addEventListener('input', (ev) => { S.evFilter = ev.target.value; renderEvidence(); });
  $('evsort').addEventListener('change', (ev) => { S.evSort = ev.target.value; renderEvidence(); });
  $('evonly').addEventListener('change', (ev) => { S.evOnly = ev.target.checked; renderEvidence(); });
  $('evstale').onclick = reparseStale;
  $('origin').addEventListener('change', (ev) => setOrigin(ev.target.value));
  $('imgshow').onclick = showImageEvents;
  setupHelp();
  $('imgpick').addEventListener('change', (ev) => { S.img = Number(ev.target.value); browse('/'); });
  $('imgall').addEventListener('change', (ev) => {
    S.imgChecked.clear();
    if (ev.target.checked) for (const e of S.imgEntries) if (!(e.note && /not readable/.test(e.note))) S.imgChecked.add(e.path);
    renderImageRows();
  });
  $('imgadd').onclick = () => extractFromImage({ paths: [...S.imgChecked] }, `${fmtInt(S.imgChecked.size)} selected item${S.imgChecked.size === 1 ? '' : 's'}`);
  $('imgstd').onclick = () => extractFromImage({ standard: true }, 'the standard Windows artefacts');
  window.addEventListener('resize', () => { renderRows(); });

  document.addEventListener('keydown', (ev) => {
    const typingNow = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (ev.key === 'Escape') {
      if (typingNow) document.activeElement.blur(); else if (S.selected != null) select(null);
      return;
    }
    if (typingNow || $('dlg').open) return;
    if (ev.key === '?') { ev.preventDefault(); setView('help'); return; }
    if (S.view !== 'timeline') return;
    if (ev.key === '/') { ev.preventDefault(); $('q').focus(); $('q').select(); }
    else if (ev.key === 'ArrowDown' || ev.key === 'j') { ev.preventDefault(); moveSelection(1); }
    else if (ev.key === 'ArrowUp' || ev.key === 'k') { ev.preventDefault(); moveSelection(-1); }
  });

  setupHisto();
  setupDrop();
  const selected = readHash();
  $('q').value = S.q;
  $('order').textContent = S.desc ? 'Newest first' : 'Oldest first';
  loadCase();
  loadEvidence();
  loadGroups();
  reload();
  if (S.view !== 'timeline') setView(S.view);
  if (selected != null) select(selected);
  poll();
}

init();
