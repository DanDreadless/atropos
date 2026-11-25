// Drives the Atropos page in a real browser and checks what a person would see.
// Run it through run.sh, which builds Atropos, serves a fresh empty case and
// sets ATROPOS_URL, BROWSER, TESTDATA (sample artefacts) and OUT (screenshots).
const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');

const URL = process.env.ATROPOS_URL;
const TOKEN = process.env.ATROPOS_TOKEN;
// Requests made from this script, outside the browser, sign in as a script would.
const apiFetch = (p) => fetch(URL + p, { headers: { Authorization: 'Bearer ' + TOKEN } });
const TD = process.env.TESTDATA;
const OUT = process.env.OUT;
const problems = [];
let step = 0;
const ok = (cond, what) => { step++; if (cond) console.log(`ok   ${what}`); else { console.log(`FAIL ${what}`); problems.push(what); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await puppeteer.launch({
    executablePath: process.env.BROWSER,
    headless: 'new', args: ['--window-size=1500,900'], defaultViewport: { width: 1500, height: 900 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') errors.push(`console ${m.type()}: ${m.text()}`); });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('requestfailed', (r) => errors.push('requestfailed: ' + r.url() + ' ' + (r.failure() || {}).errorText));
  page.on('response', (r) => { if (r.status() >= 400) errors.push(`http ${r.status()}: ${r.url()}`); });
  const text = (sel) => page.$eval(sel, (el) => el.textContent);
  const visible = (sel) => page.$eval(sel, (el) => !el.hidden && el.getClientRects().length > 0);
  const count = (sel) => page.$$eval(sel, (els) => els.length);
  const shot = (name) => page.screenshot({ path: path.join(OUT, name + '.png') });
  const settled = async () => { await page.waitForFunction(() => document.getElementById('ingest').hidden, { timeout: 60000 }); await sleep(500); };
  const summaryCount = async () => Number((await text('#summary b')).replace(/,/g, ''));

  // ---- signing in ----
  const refused = await page.goto(URL, { waitUntil: 'networkidle0' });
  ok(refused.status() === 401 && (await page.evaluate(() => document.body.innerText)).includes('not signed in'), 'without the token the page is refused, with an explanation');
  ok((await (await fetch(URL + 'api/events')).status) === 401, 'the API is refused without the token');
  errors.length = 0; // those refusals were the point
  await page.goto(URL + '?token=' + TOKEN, { waitUntil: 'networkidle0' });
  ok(!(await page.evaluate(() => location.href)).includes('token'), 'the token link signs in and leaves no token in the address bar');

  // ---- empty case ----
  ok(await visible('#empty'), 'empty case shows the empty-state message');
  ok((await text('#empty')).includes('Drop files or folders'), 'empty state tells the examiner how to add evidence');
  await shot('01-empty');

  // ---- add evidence through the file picker ----
  const evil = path.join(OUT, 'evil.log');
  fs.writeFileSync(evil, '2024-03-01T11:00:00Z <img src=x onerror="window.__xss=1"> <script>window.__xss=2</script> hostile\n');
  const local = path.join(OUT, 'local.log');
  fs.writeFileSync(local, '2024-07-15 12:00:00 a local time with no zone\n');
  await page.click('#add');
  // The dialog opens once the case's hosts are read.
  await page.waitForFunction(() => document.getElementById('dlg').open, { timeout: 5000 }).catch(() => {});
  ok(await page.$eval('#dlg', (d) => d.open), '"Add evidence" opens a dialog');
  await page.keyboard.press('Escape');
  const input = await page.$('#pickfiles');
  await input.uploadFile(path.join(TD, 'Security.evtx'), path.join(TD, 'NTUSER.DAT'), path.join(TD, 'test.ntfs.dd'),
    path.join(TD, 'prefetch/Win10/CALC.EXE-3FBEF7FD.pf'), evil, local);
  await page.waitForFunction(() => Number(document.querySelector('#summary b').textContent.replace(/,/g, '')) > 1000, { timeout: 60000 });
  await settled();
  const total = await summaryCount();
  // The sample volume gives 49 file table times (a named stream is not an event of its own) and 55 from its transaction log. The sample hive gives 1157, three of them its RecentDocs lists.
  ok(total === 739 + 1157 + 49 + 55 + 2 + 1 + 1, `timeline shows every event after upload (${total})`);
  ok((await text('#evcount')) === '6', 'evidence count in the navigation updates');
  ok(await count('#facets .chip') >= 6 && await count('#tzfacets .chip') >= 1, 'facet chips appear');
  ok(await page.evaluate(() => {
    const rows = [...document.querySelectorAll('#facets .facetrow')].map((r) => r.querySelector('.label').textContent);
    const tz = document.querySelector('#tzfacets .label');
    const histo = document.getElementById('histo');
    return rows.join(',').startsWith('Evidence of,Source') && tz && tz.textContent === 'Time zone from' &&
      document.querySelector('#facets .facetrow:nth-child(2)').getBoundingClientRect().top > document.querySelector('#facets .facetrow').getBoundingClientRect().bottom - 1 &&
      document.getElementById('tzfacets').getBoundingClientRect().top >= histo.getBoundingClientRect().bottom - 1;
  }), 'Source chips sit on a row under Evidence of, and the time zone chips under the chart');
  ok(await count('#bars div') > 3, 'histogram has bars');
  await shot('02-timeline');

  // ---- hostile content is text, never markup ----
  await page.type('#q', 'hostile');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '1');
  ok(await count('#win img, #win script') === 0, 'markup in evidence is not turned into elements');
  ok((await text('#win .msg')).includes('<img src=x onerror='), 'hostile message is shown verbatim as text');
  await page.click('#win .row');
  await page.waitForSelector('#detail:not([hidden]) pre');
  ok(await count('#detail img, #detail script') === 0, 'detail panel does not render markup from evidence');
  ok(await page.evaluate(() => window.__xss === undefined), 'no script from evidence executed');

  // ---- search syntax and facets ----
  const setQ = async (q, want) => {
    await page.focus('#q'); await page.keyboard.down('Control'); await page.keyboard.press('a'); await page.keyboard.up('Control'); await page.keyboard.press('Backspace');
    if (q) await page.type('#q', q);
    await page.waitForFunction((w) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(w), { timeout: 8000 }, want)
      .catch(async () => ok(false, `search "${q}" should give ${want}, summary says ${await text('#summary b')}`));
  };
  await setQ('', total);
  await setQ('source:evtx', 739);
  await setQ('source:evtx 4624', await (async () => { const r = await (await apiFetch('api/summary?q=' + encodeURIComponent('source:evtx 4624'))).json(); return r.count; })());
  await setQ('', total);
  await page.evaluate(() => [...document.querySelectorAll('#tzfacets .chip')].find((c) => c.textContent.startsWith('assumed')).click());
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '1');
  ok((await page.$eval('#q', (i) => i.value)) === 'tz:assumed', 'clicking a facet adds its filter to the search box');
  ok(await count('#win .row.assumed') === 1, 'assumed-zone event is visibly marked in the table');
  await page.click('#win .row');
  await page.waitForSelector('#detail .note.warn');
  ok((await text('#detail .note.warn')).startsWith('ASSUMED'), 'detail panel warns that the zone was assumed');
  await shot('03-assumed');
  await page.evaluate(() => document.querySelector('#tzfacets .chip.on').click());
  await page.waitForFunction((t) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(t), {}, total);
  ok(true, 'clicking the facet again removes the filter');
  // The chips count what the search finds, not the whole case.
  const chipNames = (label) => page.evaluate((l) => {
    const kids = [...document.querySelectorAll('#facets .facetrow > *')];
    const at = kids.findIndex((k) => k.classList.contains('label') && k.textContent === l);
    const out = [];
    for (let i = at + 1; i < kids.length && !kids[i].classList.contains('label'); i++) out.push(kids[i].firstChild.textContent);
    return out.sort().join(',');
  }, label);
  const word = '4624';
  await setQ(word, await (async () => (await (await apiFetch('api/summary?q=' + word)).json()).count)());
  const fc = (await (await apiFetch('api/facets?q=' + word)).json()).facets;
  const caseFacets = (await (await apiFetch('api/case')).json()).facets;
  await page.waitForFunction((want) => {
    const kids = [...document.querySelectorAll('#facets .facetrow > *')];
    const at = kids.findIndex((k) => k.classList.contains('label') && k.textContent === 'Source');
    const out = [];
    for (let i = at + 1; i < kids.length && !kids[i].classList.contains('label'); i++) out.push(kids[i].firstChild.textContent);
    return out.sort().join(',') === want;
  }, { timeout: 8000 }, Object.keys(fc.source).sort().join(',')).catch(() => {});
  ok(await chipNames('Source') === Object.keys(fc.source).sort().join(',') && await chipNames('Evidence of') === Object.keys(fc.category).sort().join(',') &&
    Object.keys(fc.source).length < Object.keys(caseFacets.source).length,
    'typing in the search box narrows the Evidence of and Source chips to what it finds: ' + await chipNames('Source'));
  await setQ('', total);

  // ---- MACB and what events are evidence of ----
  await setQ('source:mft', 49);
  const macb = await page.$$eval('#win .row .macb', (els) => els.map((e) => e.textContent));
  ok(macb.length > 0 && macb.every((m) => /^[M.][A.][C.][B.]$/.test(m) && m !== '....'), 'file-system events show their MACB letters: ' + macb.slice(0, 3).join(' '));
  await setQ('macb:b', await (async () => (await (await apiFetch('api/summary?q=macb:b')).json()).count)());
  ok((await page.$$eval('#win .row .macb', (els) => els.every((e) => e.textContent[3] === 'B'))), 'macb:b shows only birth times');
  await setQ('source:evtx', 739);
  ok((await text('#win .row .macb')) === '....', 'a log record is not given a MACB letter');
  await setQ('', total);
  await page.evaluate(() => [...document.querySelectorAll('#facets .chip')].find((c) => c.textContent.startsWith('execution')).click());
  await sleep(600);
  ok((await page.$eval('#q', (i) => i.value)) === 'category:execution' && (await page.$$eval('#win .row .cat', (els) => els.length > 0 && els.every((e) => e.textContent === 'execution'))),
    'the "Evidence of" chips filter by category across artefacts');
  const sources = await page.$$eval('#win .row', (rows) => [...new Set(rows.map((r) => r.children[6].textContent))]);
  ok(sources.includes('registry') && sources.includes('prefetch'), 'execution evidence comes from more than one artefact: ' + sources.join(', '));
  await setQ('', total);

  // ---- groups: a timeline built from the timeline ----
  const groupId = (name) => page.evaluate((n) => { const o = [...document.querySelectorAll('#groupadd option')].find((x) => x.textContent === n); return o && o.value; }, name);
  const chipCount = (name) => page.evaluate((n) => { const c = [...document.querySelectorAll('#groups .chip')].find((x) => x.firstChild.textContent === n); return c ? Number(c.querySelector('i').textContent.replace(/,/g, '')) : -1; }, name);
  await page.evaluate(() => [...document.querySelectorAll('#groups .chip')].find((c) => c.textContent === '+ New group').click());
  await page.waitForSelector('#dlg[open] input');
  await page.type('#dlg input', 'Malware');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => [...document.querySelectorAll('#groups .chip')].some((c) => c.firstChild.textContent === 'Malware'));
  ok(await chipCount('Malware') === 0, 'a new group appears, empty');
  ok((await text('#groupadd option')).startsWith('Add all'), 'with nothing ticked the control offers everything shown');
  const boxes = await page.$$('#win .row input[type=checkbox]');
  const selectedBefore = await page.evaluate(() => new URLSearchParams(location.hash.slice(1)).get('e'));
  await boxes[5].click(); await boxes[7].click();
  ok((await text('#groupadd option')) === 'Add 2 selected to group…' && await visible('#clearsel'), 'ticking events switches the control to the selection');
  ok((await page.evaluate(() => new URLSearchParams(location.hash.slice(1)).get('e'))) === selectedBefore, 'ticking a box does not open the event');
  await page.select('#groupadd', await groupId('Malware'));
  await page.waitForFunction(() => document.querySelectorAll('#win .row .gtag').length === 2, { timeout: 8000 }).catch(() => {});
  ok(await chipCount('Malware') === 2 && await count('#win .row .gtag') === 2, 'ticked events join the group and are marked in the main timeline');
  await setQ('source:prefetch', 2);
  await page.select('#groupadd', await groupId('Malware'));
  await page.waitForFunction(() => document.querySelectorAll('#win .row .gtag').length === 2, { timeout: 8000 }).catch(() => {});
  ok(await chipCount('Malware') === 4, 'everything a search shows can be added in one step');
  await setQ('', total);
  await page.evaluate(() => [...document.querySelectorAll('#groups .chip')].find((c) => c.firstChild.textContent === 'Malware').click());
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '4');
  ok(await count('#win .row') === 4 && await count('#bars div') >= 2, 'the group is a timeline of its own, with its own chart');
  ok((await page.evaluate(() => location.hash)).includes('group=Malware'), 'the open group is in the address bar');
  const gcsv = await (await apiFetch('api/export?format=csv&group=Malware')).text();
  ok(gcsv.trim().split('\n').length === 5, 'exporting from a group exports that group');
  await shot('04b-group');
  await (await page.$('#win .row input[type=checkbox]')).click();
  ok((await text('#groupremove')) === 'Remove 1 from "Malware"', 'inside a group, ticked events can be removed');
  await page.click('#groupremove');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '3');
  ok(await chipCount('Malware') === 3, 'removal takes the event out of the group');
  await page.evaluate(() => [...document.querySelectorAll('#groups .chip')].find((c) => c.textContent === 'Everything').click());
  await page.waitForFunction((t) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(t), {}, total);
  ok(await count('#win .row') > 4, '"Everything" returns to the whole timeline, where nothing was removed');

  // ---- histogram zoom ----
  const box = await (await page.$('#histo')).boundingBox();
  await page.mouse.move(box.x + box.width * 0.55, box.y + 40);
  ok(await visible('#tip'), 'hovering the histogram shows the bucket time range');
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.75, box.y + 40, { steps: 5 });
  ok(await visible('#sel'), 'dragging shows the selection');
  await page.mouse.up();
  await page.waitForFunction((t) => Number(document.querySelector('#summary b').textContent.replace(/,/g, '')) < t, {}, total);
  const zoomed = await summaryCount();
  ok(zoomed > 0 && zoomed < total, `dragging across the chart zooms (${zoomed} events in range)`);
  ok(await visible('#zoomout') && await visible('#zoomreset'), 'zoom controls appear');
  ok((await page.evaluate(() => location.hash)).includes('from='), 'the zoom range is in the address bar');
  await shot('04-zoomed');
  await page.click('#zoomout');
  await page.waitForFunction((t) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(t), {}, total);
  ok(!(await visible('#zoomreset')), '"Zoom out" returns to the whole timeline');

  // ---- long list: paging while scrolling ----
  const reached = await page.evaluate(async () => {
    const el = document.getElementById('rows');
    for (let i = 0; i < 40; i++) { el.scrollTop = el.scrollHeight; await new Promise((r) => setTimeout(r, 150)); }
    return { h: el.scrollHeight, last: document.querySelector('#win .row:last-child .time').textContent, shown: document.querySelectorAll('#win .row').length };
  });
  ok(reached.h === total * 26, `scrolling loads every page (scroll height ${reached.h} = ${total} rows)`);
  ok(reached.shown < 120, `only rows in view are in the document (${reached.shown})`);
  ok(reached.last.startsWith('2024-07-15 12:00:00'), 'last row is the latest event: ' + reached.last);
  const firstRowStarts = (prefix) => page.waitForFunction((p) => {
    const el = document.querySelector('#win .row .time');
    return el && el.textContent.startsWith(p) && document.getElementById('rows').scrollTop === 0;
  }, { timeout: 8000 }, prefix).then(() => true, () => false);
  await page.click('#order');
  ok(await firstRowStarts('2024-07-15 12:00:00'), '"Newest first" reverses the order');
  await page.click('#order');
  ok(await firstRowStarts('2007-10-11'), '"Oldest first" restores it');

  // ---- detail, keyboard, annotations ----
  await page.click('#win .row');
  await page.waitForSelector('#detail:not([hidden]) dl');
  const d = await text('#detail');
  ok(d.includes('Where this came from') && d.includes('SHA-256') && d.includes('As found') && d.includes('NTUSER.DAT'), 'detail shows raw value, provenance and source');
  const firstId = await page.evaluate(() => location.hash);
  await page.keyboard.press('ArrowDown');
  await sleep(400);
  ok((await page.evaluate(() => location.hash)) !== firstId && await count('#win .row.sel') === 1, 'arrow keys move the selection');
  await page.type('#detail .annform input', 'suspicious');
  await page.keyboard.press('Enter');
  await page.waitForSelector('#win .row.sel .tag');
  ok((await text('#win .row.sel .tag')) === 'suspicious', 'a tag appears on the row');
  await page.type('#detail .annform input', 'needs a second look by the registry specialist');
  await page.evaluate(() => [...document.querySelectorAll('#detail .annform button')].find((b) => b.textContent === 'Add comment').click());
  await page.waitForFunction(() => document.querySelectorAll('#detail .ann').length === 2);
  await shot('05-detail');
  await setQ('tag:suspicious', 1);
  await page.click('#win .row');
  await page.waitForSelector('#detail .ann button.link');
  await page.click('#detail .ann button.link');
  await page.waitForSelector('#detail .ann.retracted');
  ok(await count('#win .row .tag') === 0, 'a withdrawn tag leaves the row');
  ok(await count('#detail .ann') === 2, 'the withdrawn tag stays visible in the notes, struck through');
  await setQ('', total);

  // ---- bookmarkable state ----
  await setQ('source:prefetch', 2);
  await page.click('#win .row');
  await sleep(300);
  const hash = await page.evaluate(() => location.hash);
  await page.goto('about:blank');
  await page.goto(URL + hash, { waitUntil: 'networkidle0' });
  ok((await page.$eval('#q', (i) => i.value)) === 'source:prefetch' && await summaryCount() === 2 && await visible('#detail'), 'reopening the address restores search and selected event');
  await setQ('', total);

  // ---- text search over files with no parser ----
  const blob = path.join(OUT, 'blob.bin');
  fs.writeFileSync(blob, Buffer.concat([Buffer.alloc(300, 0xfe), Buffer.from('C:\\Temp\\zebrapayload.exe'), Buffer.alloc(50, 1)]));
  await (await page.$('#pickfiles')).uploadFile(blob);
  await page.waitForFunction(() => document.getElementById('evcount').textContent === '7', { timeout: 30000 });
  await settled();
  await setQ('zebrapayload', 0);
  await page.waitForSelector('#texthits:not([hidden])', { timeout: 5000 }).catch(() => {});
  ok(await visible('#texthits') && (await text('#texthits')).includes('blob.bin'), 'a term found only inside an unparsed file is reported, not shown as nothing');
  await shot('06-texthit');
  await page.click('#texthits button.link');
  await page.waitForSelector('#view-evidence:not([hidden]) .evdetail');
  ok((await text('#evrows .erow.sel')).includes('blob.bin'), 'the hit links to the evidence item');

  // ---- evidence view ----
  ok(await count('#evrows .erow') === 7, 'evidence view lists every item');
  ok((await text('#evrows .evdetail')).includes('SHA-1') && (await text('#evrows .evdetail')).includes('Identified as'), 'evidence detail shows hashes and how it was identified');
  await page.type('#evq', 'registry');
  ok(await count('#evrows .erow') === 1, 'evidence filter narrows the list');
  await page.click('#evrows .erow');
  await shot('07-evidence');
  await page.evaluate(() => [...document.querySelectorAll('#evrows .evdetail button')].find((b) => b.textContent.startsWith('Show its')).click());
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '1,157');
  ok(await visible('#view-timeline') && (await page.$eval('#q', (i) => i.value)).startsWith('evidence:'), '"Show its events" filters the timeline to that item');

  // ---- re-parse ----
  await page.click('#nav [data-view=evidence]');
  await page.focus('#evq'); await page.keyboard.down('Control'); await page.keyboard.press('a'); await page.keyboard.up('Control'); await page.keyboard.press('Backspace');
  await page.type('#evq', 'evil');
  await page.click('#evrows .erow');
  await page.evaluate(() => [...document.querySelectorAll('#evrows .evdetail button')].find((b) => b.textContent === 'Parse again').click());
  // The row says a run is waiting or under way, not the last run's status.
  const marked = await page.waitForFunction(() => ['queued', 'processing'].includes(document.querySelector('#evrows .erow .pill')?.textContent), { polling: 'raf', timeout: 3000 }).then(() => true, () => false);
  ok(marked, '"Parse again" marks the row queued or processing at once');
  await sleep(1500); await settled();
  await page.waitForFunction(() => document.querySelector('#evrows .erow .pill')?.textContent === 'parsed', { timeout: 10000 }).catch(() => {});
  ok(await page.$eval('#evrows .erow .pill', (p) => p.textContent) === 'parsed', "the row shows the new run's status when it ends");
  await page.click('#nav [data-view=timeline]');
  await setQ('', total);
  ok(true, 're-parse leaves the timeline with the same number of events');

  // ---- exclude and include again ----
  await page.click('#nav [data-view=evidence]');
  await page.waitForSelector('#evrows .erow');
  const evilEvents = await page.$eval('#evrows .erow .num', (n) => Number(n.textContent.replace(/,/g, '') || 0));
  if (!(await visible('#evrows .evdetail'))) await page.click('#evrows .erow');
  await page.evaluate(() => [...document.querySelectorAll('#evrows .evdetail button')].find((b) => b.textContent === 'Exclude from case…').click());
  await page.waitForSelector('.excludeform input');
  await page.evaluate(() => [...document.querySelectorAll('.excludeform button')].find((b) => b.textContent === 'Exclude').click());
  await sleep(300);
  ok(await page.$eval('#evrows .erow .pill', (p) => p.textContent) !== 'excluded', 'excluding without a reason is refused');
  await page.type('.excludeform input', 'added by mistake');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.querySelector('#evrows .erow .pill')?.textContent === 'excluded', { timeout: 8000 }).catch(() => {});
  ok(await page.$eval('#evrows .erow .pill', (p) => p.textContent) === 'excluded' && (await text('#evrows .evdetail')).includes('added by mistake'),
    'Exclude from case marks the item excluded, with the reason');
  await page.click('#nav [data-view=timeline]');
  await setQ('', total - evilEvents);
  ok(true, `the excluded item's ${evilEvents} events leave the timeline`);
  ok(!(await page.$eval('#origin', (s) => [...s.options].some((x) => x.value.toLowerCase() === 'item:evil.log'))), 'and the From list');
  await page.click('#nav [data-view=evidence]');
  await page.waitForSelector('#evrows .evdetail');
  await page.evaluate(() => [...document.querySelectorAll('#evrows .evdetail button')].find((b) => b.textContent === 'Include again').click());
  await page.waitForFunction(() => document.querySelector('#evrows .erow .pill')?.textContent === 'parsed', { timeout: 8000 }).catch(() => {});
  ok(await page.$eval('#evrows .erow .pill', (p) => p.textContent) === 'parsed', 'Include again restores it');
  await page.click('#nav [data-view=timeline]');
  await setQ('', total);
  ok(true, 'and its events come back');

  // ---- drop ----
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['2025-02-02T02:02:02Z dropped on the page\n'], 'dropped.log'));
    window.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
  });
  ok(await visible('#drop'), 'dragging files over the page shows the drop target');
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['2025-02-02T02:02:02Z dropped on the page\n'], 'dropped.log'));
    window.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
  });
  await page.waitForSelector('#dlg[open] select');
  await page.select('#dlg select', 'none');
  await page.type('#dlg textarea', 'dropped by the browser check');
  await page.evaluate(() => [...document.querySelectorAll('#dlg button')].find((b) => b.textContent === 'Add').click());
  await page.waitForFunction((t) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(t + 1), { timeout: 30000 }, total);
  ok(!(await visible('#drop')), 'dropped file is ingested and the timeline refreshes by itself');

  // ---- a large drop goes in chunks, survives a chunk that breaks off, and shows its progress ----
  await page.evaluate(() => {
    window.__progress = [];
    new MutationObserver(() => { const t = document.getElementById('ingest').textContent; if (t) window.__progress.push(t); })
      .observe(document.getElementById('ingest'), { childList: true, subtree: true, characterData: true });
  });
  await page.setRequestInterception(true);
  let cut = 0, chunkNo = 0;
  const cutOne = (r) => {
    // Break the second chunk off once, as a locked file would.
    if (r.method() === 'POST' && /\/api\/upload\?batch=\d+&final=0/.test(r.url()) && ++chunkNo === 2) { cut++; r.abort('failed'); } else r.continue();
  };
  page.on('request', cutOne);
  await page.evaluate(() => {
    const dt = new DataTransfer();
    for (let i = 0; i < 230; i++) dt.items.add(new File([`2025-03-03T03:${String(i % 60).padStart(2, '0')}:00Z bulk line ${i}
`], `bulk-${i}.log`));
    window.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
  });
  await page.waitForSelector('#dlg[open] select');
  await page.select('#dlg select', 'none');
  await page.type('#dlg textarea', 'dropped by the browser check');
  await page.evaluate(() => [...document.querySelectorAll('#dlg button')].find((b) => b.textContent === 'Add').click());
  await page.waitForFunction((t) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(t + 231), { timeout: 60000 }, total).catch(() => {});
  page.off('request', cutOne);
  await page.setRequestInterception(false);
  // The cut was deliberate: it is not a page error.
  const expected = (e) => /requestfailed: \S+\/api\/upload\?batch=\d+&final=0 net::ERR_FAILED/.test(e) || e === 'console error: Failed to load resource: net::ERR_FAILED';
  if (errors.filter(expected).length <= 2) errors.splice(0, errors.length, ...errors.filter((e) => !expected(e)));
  const bulk = (await (await apiFetch('api/evidence')).json()).evidence.filter((e) => e.name.startsWith('bulk-'));
  ok(cut === 1 && bulk.length === 230 && new Set(bulk.map((e) => e.batch_id)).size === 1 && (await summaryCount()) === total + 231,
    `230 dropped files arrive in one submission despite a chunk breaking off (${bulk.length} stored, ${new Set(bulk.map((e) => e.batch_id)).size} submission(s), ${cut} cut, timeline +${(await summaryCount()) - total})`);
  const seen = await page.evaluate(() => window.__progress);
  ok(seen.some((t) => /Uploading \d+ of 230 files .* of .* \(\d+%\)/.test(t)), 'the upload shows files and bytes sent with a percentage');

  // ---- files: looking inside an image ----
  const before = { ev: Number(await text('#evcount')), n: await summaryCount() };
  await (await page.$('#pickfiles')).uploadFile(path.join(OUT, 'disc.iso'));
  await page.waitForFunction((n) => document.getElementById('evcount').textContent === String(n), { timeout: 30000 }, before.ev + 1);
  await settled();
  ok(await summaryCount() === before.n, 'adding a disc image does not unpack it onto the timeline');
  ok((await text('#imgcount')) === '2', 'both images (the NTFS volume added earlier and this disc) are counted on the Images tab');
  ok((await page.$eval('button[data-view="files"]', (b) => b.firstChild.textContent.trim())) === 'Images', 'the tab for looking inside images is called Images');
  await page.click('#nav [data-view=files]');
  await page.waitForSelector('#imgrows .frow');
  ok((await text('#imgdesc')).includes('NTFS') && (await page.$$eval('#imgrows .frow .fname', (els) => els.some((e) => e.textContent === '$MFT'))), 'an NTFS volume can be browsed too, down to its $MFT');
  const discValue = await page.$eval('#imgpick', (s) => [...s.options].find((o) => o.textContent.includes('disc.iso')).value);
  await page.select('#imgpick', discValue);
  await page.waitForFunction(() => document.getElementById('imgdesc').textContent.includes('ISO 9660'));
  ok((await text('#imgdesc')).includes('ISO 9660'), 'Images says what the image is: ' + await text('#imgdesc'));
  const rowNames = () => page.$$eval('#imgrows .frow .fname', (els) => els.map((e) => e.textContent).join(' '));
  ok(await rowNames() === 'SUB/ APP.LOG NOTES.TXT', 'the image root is listed, folders first: ' + await rowNames());
  await page.click('#imgrows .frow.dir');
  await page.waitForFunction(() => document.querySelector('#imgrows .frow .fname').textContent === 'DEEP.LOG');
  ok((await text('#crumbs')).replace(/\s+/g, '') === 'imageroot/SUB', 'opening a folder shows where you are: ' + await text('#crumbs'));
  await page.click('#crumbs button');
  await page.waitForFunction(() => document.querySelectorAll('#imgrows .frow').length === 3);
  ok(await page.$eval('#imgadd', (b) => b.disabled), 'nothing can be added until something is chosen');
  const fboxes = await page.$$('#imgrows .frow input[type=checkbox]');
  await fboxes[0].click(); await fboxes[1].click();
  ok((await text('#imgadd')) === 'Add 2 selected to timeline', 'ticking a folder and a file enables the button');
  await page.click('#imgadd');
  await page.waitForFunction((n) => document.getElementById('evcount').textContent === String(n), { timeout: 30000 }, before.ev + 3);
  await settled();
  await shot('07b-files');
  await page.click('#nav [data-view=timeline]');
  await setQ('discmarker', 3);
  ok(true, 'events from files chosen inside the image are on the timeline');
  await page.click('#win .row');
  await page.waitForSelector('#detail:not([hidden]) dl');
  ok((await text('#detail')).includes('disc.iso!/'), 'each such event traces back through the image: origin shows the path inside it');
  ok((await text('#detail')).includes('Show everything that came out of disc.iso'), 'and the event offers everything else from the same image');
  await setQ('', before.n + 3);

  // ---- finding what came from where ----
  const items = () => page.$$eval('#win .row', (rs) => rs.map((r) => r.children[9].textContent));
  ok((await items()).every((t) => t.length > 0), 'every row names the evidence item it was read from');
  const fromValue = await page.$eval('#origin', (s) => { const o = [...s.options].find((x) => x.textContent.includes('disc.iso')); return o ? o.value : ''; });
  ok(/^from:\d+$/.test(fromValue), 'the From list offers the image that files were taken out of: ' + fromValue);
  ok((await page.$eval('#origin', (s) => [...s.options].some((x) => x.value.startsWith('submission:')))), 'and each submission');
  await page.select('#origin', fromValue);
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '3');
  ok((await page.$eval('#q', (i) => i.value)) === fromValue, 'choosing an image writes a from: filter into the search box');
  // Items: every name in the Item column, from the evidence parsed.
  const evList = (await (await apiFetch('api/evidence')).json()).evidence;
  const nameEvents = {};
  for (const e of evList) if (!e.duplicate_of && e.event_count) nameEvents[e.name.toLowerCase()] = (nameEvents[e.name.toLowerCase()] || 0) + e.event_count;
  const itemOpts = await page.$eval('#origin', (s) => [...s.options].filter((x) => x.value.startsWith('item:')).map((x) => x.value.slice(5).replace(/"/g, '').toLowerCase()));
  ok(itemOpts.slice().sort().join('|') === Object.keys(nameEvents).sort().join('|'), 'the From list offers every item name in the Item column: ' + itemOpts.join(', '));
  const someName = itemOpts.find((k) => nameEvents[k] < total) || itemOpts[0];
  const someValue = await page.$eval('#origin', (s, n) => [...s.options].find((x) => x.value.startsWith('item:') && x.value.slice(5).replace(/"/g, '').toLowerCase() === n).value, someName);
  await page.select('#origin', someValue);
  await page.waitForFunction((n) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(n), { timeout: 8000 }, nameEvents[someName]).catch(() => {});
  ok((await page.$eval('#q', (i) => i.value)) === someValue && (await text('#summary b')).replace(/,/g, '') === String(nameEvents[someName]),
    'choosing an item shows the events of every item of that name: ' + someValue);
  ok(await page.evaluate(() => [...document.querySelectorAll('#win .row')].every((r) => r.children[9].textContent.toLowerCase() === document.querySelector('#q').value.slice(5).replace(/"/g, '').toLowerCase())),
    'and the Item column shows only that name');
  await page.select('#origin', fromValue);
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '3');
  const sourceSum = () => page.evaluate(() => {
    const kids = [...document.querySelectorAll('#facets .facetrow > *')];
    let on = false, sum = 0;
    for (const k of kids) {
      if (k.classList.contains('label')) on = k.textContent === 'Source';
      else if (on) sum += Number(k.querySelector('i').textContent.replace(/,/g, ''));
    }
    return sum;
  });
  await sleep(300);
  ok(await sourceSum() === 3, `the Source counts follow the From choice: they add up to the 3 events from the image (${await sourceSum()})`);
  ok((await items()).every((t) => /\.LOG$|\.TXT$/.test(t)), 'and the timeline then shows only what came out of it: ' + (await items()).join(' '));
  await setQ(fromValue + ' file:deep.log', 1);
  await setQ('-' + fromValue, before.n);
  await setQ(fromValue, 3);
  await page.select('#origin', '');
  await page.waitForFunction((n) => document.querySelector('#summary b').textContent.replace(/,/g, '') === String(n), {}, before.n + 3);
  ok((await page.$eval('#q', (i) => i.value)) === '', 'choosing "all evidence" takes the filter out again');
  await sleep(300);
  ok(await sourceSum() === before.n + 3, 'and the Source counts return to the whole case');
  await page.click('#nav [data-view=files]');
  await page.select('#imgpick', discValue);
  await page.waitForSelector('#imgrows .frow');
  await page.click('#imgshow');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '3');
  ok(!(await page.$eval('#view-timeline', (v) => v.hidden)) && (await page.$eval('#q', (i) => i.value)) === fromValue, 'the Images tab leads straight to the events of the image being browsed');
  await setQ('', before.n + 3);

  // ---- the evidence list can be re-ordered and thinned ----
  await page.click('#nav [data-view=evidence]');
  await page.$eval('#evq', (i) => { i.value = ''; i.dispatchEvent(new Event('input')); });
  await page.waitForSelector('#evrows .erow');
  const allRows = await count('#evrows .erow');
  await page.select('#evsort', 'events');
  const evCounts = await page.$$eval('#evrows .erow', (rs) => rs.map((r) => Number(r.children[4].textContent.replace(/,/g, '') || 0)));
  ok(evCounts.every((n, i) => i === 0 || evCounts[i - 1] >= n), 'the evidence list sorts by number of events');
  await page.click('#evonly');
  const withEvents = await count('#evrows .erow');
  ok(withEvents > 0 && withEvents < allRows && withEvents === evCounts.filter((n) => n > 0).length, `"With events only" hides the rest (${withEvents} of ${allRows})`);
  await page.click('#evonly');
  await page.select('#evsort', 'tree');
  ok(await page.$eval('#evstale', (b) => b.hidden), 'nothing is marked out of date straight after being parsed by this version');
  await page.evaluate(() => [...document.querySelectorAll('#evrows .erow')].find((r) => r.children[1].textContent.includes('disc.iso')).click());
  await page.waitForSelector('#evrows .evdetail');
  ok((await text('#evrows .evdetail')).includes('events from it and what came out of it'), 'an image offers the events of everything taken out of it');
  await shot('07c-evidence-sorted');

  // ---- the user guide ----
  await page.click('#nav [data-view=help]');
  ok(!(await page.$eval('#view-help', (v) => v.hidden)) && await count('#view-help h2') >= 15, 'Help opens a guide with a section for each part of the interface');
  const tocTargets = await page.$$eval('#helptoc button', (bs) => bs.map((b) => b.dataset.to));
  ok(tocTargets.length === await count('#view-help h2') && await page.evaluate((ids) => ids.every((id) => document.getElementById(id)), tocTargets), 'every entry in its contents list leads to a section');
  const shownTopics = () => page.$$eval('.helptopic', (ts) => ts.filter((t) => !t.hidden).map((t) => t.dataset.id));
  ok((await shownTopics()).join() === 'h-start' && (await text('.helptopic:not([hidden])')).includes('Atropos user guide'), 'the guide opens on its first topic alone, with its introduction');
  await page.click('#helptoc button[data-to=h-search]');
  await sleep(200);
  ok((await shownTopics()).join() === 'h-search' && await page.evaluate(() => { const r = document.getElementById('h-search').getBoundingClientRect(); return r.top >= 0 && r.top < window.innerHeight / 2; }) &&
    await page.$eval('#helptoc button.on', (b) => b.dataset.to) === 'h-search', 'choosing an entry shows that topic alone, marked in the contents');
  ok(page.url().includes('view=help') && page.url().includes('topic=h-search'), 'the address bar remembers the guide and its topic');
  await page.evaluate(() => [...document.querySelectorAll('.helptopic:not([hidden]) .helpfoot button')].pop().click());
  ok((await shownTopics()).join() === 'h-from', 'the button at the foot of a topic goes on to the next');
  await page.type('#helpq', 'logon type');
  await sleep(200);
  const hitsShown = await page.$$eval('#helptoc button[data-to]', (bs) => bs.filter((b) => !b.hidden).map((b) => b.dataset.to));
  ok(hitsShown.includes('h-evidenceof') && hitsShown.length < 6 && (await shownTopics()).join() === hitsShown[0] && (await text('#helphits')).includes('mention'),
    'searching the guide lists only the topics that mention the words, and opens the first: ' + hitsShown.join(', '));
  await page.click('#helpq', { clickCount: 3 }); await page.keyboard.press('Escape');
  ok((await page.$$eval('#helptoc button[data-to]', (bs) => bs.filter((b) => b.hidden).length)) === 0, 'clearing the search brings every topic back');
  await page.click('#helptoc button[data-to=h-evidenceof]');
  ok((await page.$$eval('.helptopic:not([hidden]) .evcard', (r) => r.length)) === 13, 'the guide explains every kind of "Evidence of"');
  await shot('07d-help');
  await page.click('#nav [data-view=timeline]');
  await page.keyboard.press('?');
  ok(!(await page.$eval('#view-help', (v) => v.hidden)), 'pressing ? opens the guide');
  await page.click('#nav [data-view=timeline]');

  // ---- details, with no host named by the evidence ----
  await page.click('#nav [data-view=details]');
  await page.waitForSelector('#dtbody .dtform');
  ok(await count('#dtbody .dtnohost') === 1 && (await text('#dtbody .dtnohost')).includes('SYSTEM registry hive') && await count('#dtbody .dtform') === 2 &&
    await count('#dtbody input[aria-label="Computer name"]') === 1, 'with no host named by the evidence, a host form is there to fill in, starting with its name');
  await page.evaluate(() => [...document.querySelectorAll('#dtbody .dtsave button')].pop().click());
  ok((await text('#toast')).includes("computer's name"), 'saving it without a name asks for one');
  await page.type('#dtbody input[aria-label="Computer name"]', 'LAB-PC-01');
  await page.type('#dtbody input[aria-label="Serial number"]', 'SN-12345');
  await page.evaluate(() => [...document.querySelectorAll('#dtbody .dtsave button')].pop().click());
  await page.waitForFunction(() => [...document.querySelectorAll('#dtbody .dtform summary')].some((s) => s.textContent.includes('LAB-PC-01')), { timeout: 8000 }).catch(() => {});
  ok(await page.evaluate(() => [...document.querySelectorAll('#dtbody .dtform summary')].some((s) => s.textContent.includes('Host LAB-PC-01') && s.textContent.includes('1 of'))) &&
    await page.$eval('#dtbody input[aria-label="LAB-PC-01: Serial number"]', (el) => el.value) === 'SN-12345' && await count('#dtbody .dtnohost') === 0,
    'the host is saved under that name with what was filled in');
  await page.click('#nav [data-view=timeline]');

  // ---- audit and verify ----
  await page.click('#nav [data-view=audit]');
  await page.waitForSelector('#auditrows .arow');
  const audit = await text('#auditrows');
  ok(audit.includes('evidence.intake') && audit.includes('parse.complete') && audit.includes('annotation.retract') && audit.includes('parse.requested') && audit.includes('image.extract'), 'audit log shows intake, parsing, annotations, the re-parse request and the extraction from the image');
  await shot('08-audit');
  await page.click('#verify');
  await page.waitForSelector('#dlg .verdict', { timeout: 60000 });
  ok((await text('#dlg .verdict')) === 'Everything verifies', 'verify reports success: ' + await text('#dlg .verdict'));
  ok(await count('#dlg .check .mark.ok') === 4 && /^[0-9a-f]{64}$/.test(await text('#dlg pre')), 'all four checks pass and the chain head is shown');
  await shot('09-verify');
  await page.keyboard.press('Escape');

  // ---- case report ----
  const rep = await (await apiFetch('api/report?format=html')).text();
  ok(rep.includes('Everything verified') && rep.includes('Malware') && rep.includes('Timelines built by the examiner') && !rep.includes('<script'),
    'the case report verifies the case and includes the group timeline');
  ok(await count('#report option') === 3, 'the report menu is in the top bar');

  // ---- export ----
  const csv = await (await apiFetch('api/export?format=csv&q=source:prefetch')).text();
  ok(csv.trim().split('\n').length === 3, 'export returns the filtered events');

  // ---- analysis ----
  await page.click('#nav [data-view=analysis]');
  await page.waitForFunction(() => document.querySelector('#anrows .annotes'), { timeout: 20000 });
  ok((await text('#ansummary')).includes('out of place in') && (await text('#anrows')).includes('places to look first'),
    'the analysis tab opens on things out of place and says what they are not');
  await page.click('#anmode [data-mode=timestamps]');
  await page.waitForFunction(() => document.getElementById('ansummary').textContent.includes('finding'), { timeout: 20000 });
  ok(await page.$eval('#antag', (el) => el.hidden), 'the tag button belongs to the out-of-place checks only');
  ok((await text('#ansummary')).startsWith('0 findings'), 'the analysis tab reports no findings where nothing contradicts');
  ok((await text('#anrows')).includes('No ShimCache') || (await text('#anrows')).includes('No file table'), 'and says which artefacts it had nothing to compare with');
  await shot('13-analysis-empty');

  // A seeded case whose artefacts disagree about three files.
  await page.goto(process.env.ATROPOS_URL2 + '?token=' + process.env.ATROPOS_TOKEN2 + '#view=analysis', { waitUntil: 'networkidle0' });
  await page.waitForFunction(() => document.querySelectorAll('#anrows .anrow').length === 3, { timeout: 20000 });
  ok((await text('#ansummary')).startsWith('3 things out of place'), 'three things out of place are found in the seeded case');
  const oop = await text('#anrows');
  ok(oop.includes('Name one character away from a Windows program') && oop.includes('close to svchost.exe') && oop.includes('mft, registry'),
    'a look-alike name is one finding across the artefacts that show it');
  ok(oop.includes('Program run from a folder programs do not belong in') && oop.includes('Program file in a folder programs do not belong in') && !oop.includes('calc.exe'),
    'a program in Users\\Public is reported, and ordinary files are not');
  await shot('16-out-of-place');
  await page.click('#antag');
  await page.waitForFunction(() => document.getElementById('ansummary').textContent.includes('tags added'), { timeout: 20000 });
  const tagged = await (await page.evaluate(async () => (await fetch('api/events?q=tag:anomaly&limit=50')).json()));
  ok(tagged.events.length === 6 && tagged.events.every((e) => e.tags.includes('anomaly')), 'tagging marks every event listed, findable with tag:anomaly');
  await page.click('#antag');
  await page.waitForFunction(() => document.getElementById('ansummary').textContent.includes('already'), { timeout: 20000 });
  ok(true, 'tagging again adds nothing');
  await page.click('#anmode [data-mode=timestamps]');
  await page.waitForFunction(() => document.getElementById('ansummary').textContent.includes('findings'), { timeout: 20000 });
  ok((await text('#ansummary')).startsWith('3 findings'), 'three contradictions are found in the seeded case');
  const an = await text('#anrows');
  ok(an.includes('Modified earlier than ShimCache recorded') && an.includes('Built after its own creation') && an.includes('Created earlier than the change journal'),
    'each kind of finding has its heading');
  ok(an.includes('/Windows/System32/svch0st.exe') && an.includes('also flagged in the file table') && an.includes('Caution:') && !an.includes('calc.exe'),
    'a finding names the file, carries its caution, and consistent files are not listed');
  await shot('14-analysis');
  await page.click('#anrows .anrow button.link');
  await page.waitForFunction(() => !document.getElementById('view-timeline').hidden && document.querySelectorAll('#win .row').length === 2, { timeout: 20000 });
  ok((await page.$eval('#q', (el) => el.value)).startsWith('id:') && await summaryCount() === 2, 'a finding opens the two events it compared on the timeline');
  await shot('15-analysis-events');

  // ---- case and host details ----
  await page.click('#nav [data-view=details]');
  await page.waitForSelector('#dtbody .dtform');
  ok(await count('#dtbody .dtform') === 2 && await page.evaluate(() => [...document.querySelectorAll('#dtbody .dtform summary')].some((x) => x.textContent.includes('WKSTN-07 (named by the evidence)'))) && await count('#dtbody .dtnohost') === 0,
    'a host the evidence names has its form ready beside the case form');
  await page.type('#dthost', 'WKSTN-07');
  await page.click('#dtadd');
  await page.waitForSelector('#dtbody .dtform[open] input[aria-label="WKSTN-07: Serial number"]');
  await page.type('#dtbody .dtform[open] input[aria-label="WKSTN-07: Serial number"]', 'PF3<b>ABC</b>');
  await page.type('#dtbody .dtform[open] input[aria-label="WKSTN-07: Clock difference"]', '4 minutes fast');
  await page.click('#dtbody .dtform[open] .dtsave button');
  await page.waitForFunction(() => document.getElementById('dtsummary').textContent.startsWith('1 host'), { timeout: 20000 });
  ok(await page.$eval('#dtbody input[aria-label="WKSTN-07: Serial number"]', (el) => el.value) === 'PF3<b>ABC</b>' && await count('#dtbody b b') === 0,
    'a host detail is saved and shown again as text, never as markup');
  ok((await text('#dtbody')).includes('2 of ') && (await text('#dtbody')).includes('Stated by uicheck'), 'the form says how much is stated and by whom');
  const rep2 = await (await page.evaluate(async () => (await fetch('api/report?format=html')).text()));
  ok(rep2.includes('Hosts examined') && rep2.includes('PF3&lt;b&gt;ABC&lt;/b&gt;') && rep2.includes('4 minutes fast'), 'the case report carries the host details, escaped');

  // ---- browser history, read out ----
  await page.click('#nav [data-view=timeline]');
  await setQ('item:sqlite-database', 5);
  const chipLabels = await page.$$eval('#facets .chip', (cs) => cs.map((c) => c.firstChild.textContent));
  ok(chipLabels.includes('browser-synced') && chipLabels.includes('browser-automatic'),
    'synced visits are a source of their own and pages the browser loaded by itself a kind of their own: ' + chipLabels.join(', '));
  ok((await page.$$eval('#win .row', (rs) => rs.map((r) => r.children[5].textContent))).includes('url-visited (typed)'), 'the Meaning column says how a page was reached');
  // Two chips in one row mean either: browser, then browser-automatic as well.
  const chip = (label) => page.evaluate((l) => [...document.querySelectorAll('#facets .facetrow')][0].querySelectorAll('.chip').forEach((c) => { if (c.firstChild.textContent === l) c.click(); }), label);
  await chip('browser');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '4', { timeout: 8000 }).catch(() => {});
  const auto = await page.evaluate(() => [...[...document.querySelectorAll('#facets .facetrow')][0].querySelectorAll('.chip')].find((c) => c.firstChild.textContent === 'browser-automatic').querySelector('i').textContent);
  await chip('browser-automatic');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '5', { timeout: 8000 }).catch(() => {});
  ok(auto === '1' && await summaryCount() === 5, `a second chip in the same row adds its events (browser 4 + browser-automatic ${auto} = ${await summaryCount()})`);
  await setQ('item:sqlite-database', 5);
  await page.evaluate(() => [...document.querySelectorAll('#win .row')].find((r) => r.textContent.includes('files.test/landing')).click());
  await page.waitForFunction(() => [...document.querySelectorAll('#detail h3')].some((x) => x.textContent === 'Browsing'));
  const visitText = await text('#detail');
  ok(visitText.includes('How it was reached') && visitText.includes('link, after a redirect') && visitText.includes('Came from') && visitText.includes('https://search.test/?q=how+to'),
    'a visit is read out: how it was reached and where it came from');
  ok(await page.$$eval('#detail a', (a) => a.length) === 0, 'addresses in the panel are text, never links');
  await page.evaluate(() => [...document.querySelectorAll('#detail button')].find((b) => b.textContent === 'open the visit it came from').click());
  await page.waitForFunction(() => document.getElementById('detail').textContent.includes('Searched for'), { timeout: 8000 }).catch(() => {});
  const fromText = await text('#detail');
  ok(fromText.includes('Searched for') && fromText.includes('how to') && fromText.includes('Profile of') && fromText.includes('inferred'),
    'the referring visit opens, with its search and the profile owner marked as inferred');
  await shot('14-browsing');
  await page.evaluate(() => [...document.querySelectorAll('#detail button')].find((b) => b.textContent === 'everything from this site').click());
  await page.waitForFunction(() => document.querySelector('#q').value === 'domain:search.test');
  await page.waitForFunction(() => document.querySelector('#summary b').textContent === '3', { timeout: 8000 }).catch(() => {});
  ok(await summaryCount() === 3, 'everything from a site includes its subdomains (search.test, go.search.test, www.search.test)');
  await setQ('item:sqlite-database download', 1);
  await page.click('#win .row');
  await page.waitForFunction(() => [...document.querySelectorAll('#detail h3')].some((x) => x.textContent === 'Download'));
  ok(await page.$$eval('#detail ol.chain li', (l) => l.length) === 2 && (await text('#detail')).includes('Saved to'), 'a download is read out with its redirect chain');
  await page.keyboard.press('Escape');
  await shot('17-details');
  await page.goto(URL, { waitUntil: 'networkidle0' });

  // ---- a picture is shown with its evidence ----
  const pic = path.join(OUT, 'pixel.png');
  fs.writeFileSync(pic, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4DwABAQEABRjYTgAAAABJRU5ErkJggg==', 'base64'));
  const evBefore = Number(await text('#evcount'));
  await (await page.$('#pickfiles')).uploadFile(pic);
  await page.waitForFunction((n) => document.getElementById('evcount').textContent === String(n), { timeout: 30000 }, evBefore + 1);
  await settled();
  await page.click('#nav [data-view=evidence]');
  await page.type('#evq', 'pixel.png');
  await page.click('#evrows .erow');
  await page.waitForSelector('#evrows .evdetail img.evpic');
  await page.waitForFunction(() => { const i = document.querySelector('#evrows .evdetail img.evpic'); return i && i.complete; }, { timeout: 10000 });
  ok(await page.$eval('#evrows .evdetail img.evpic', (i) => i.naturalWidth === 1 && i.getAttribute('src').endsWith('/picture')), 'a picture in the case is shown in its evidence detail');
  await page.focus('#evq'); await page.keyboard.down('Control'); await page.keyboard.press('a'); await page.keyboard.up('Control'); await page.keyboard.press('Backspace');
  await page.goto(URL, { waitUntil: 'networkidle0' });

  // ---- connections between hosts ----
  // Three made-up hosts (scripts/mklateral), described first, each one's logs
  // added under it through the add dialog.
  const rdpHosts = [['WS-ALICE', '10.1.1.20', '3 minutes ahead'], ['SRV-FILE01', '10.1.1.50', ''], ['DC01', '10.1.1.10', '']];
  for (const [name, ip, clock] of rdpHosts) {
    const hst = await page.evaluate(async (n, a, c) => {
      const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then((r) => r.json());
      const x = await post('api/hosts', { name: n });
      await post('api/details', { host: n, values: { ip_addresses: a, clock_offset: c, other_names: n + '.corp.example', time_zone: 'UTC' } });
      return x;
    }, name, ip, clock);
    const files = fs.readdirSync(path.join(OUT, 'lateral', name)).map((f) => path.join(OUT, 'lateral', name, f));
    const before = Number(await text('#evcount'));
    await page.click('#add');
    await page.waitForSelector('#dlg[open] select');
    await page.select('#dlg select', 'h' + hst.id);
    const [chooser] = await Promise.all([page.waitForFileChooser(),
      page.evaluate(() => [...document.querySelectorAll('#dlg button')].find((b) => b.textContent === 'Choose files').click())]);
    await chooser.accept(files);
    await page.waitForFunction((n) => document.getElementById('evcount').textContent === String(n), { timeout: 30000 }, before + files.length);
    await settled();
  }
  await page.click('#nav [data-view=connections]');
  await page.waitForFunction(() => document.querySelectorAll('#cnrows .cnrow').length >= 15, { timeout: 20000 }).catch(() => {});
  // The case holds another host from earlier checks, with no connections.
  ok(/^15 connections \(9 seen at both ends, 2 with no time\) between 4 hosts and 3 other computers or addresses: 6 remote desktop, 3 file share, 6 started remotely/.test(await text('#cnsummary')),
    'the Connections tab finds the fifteen connections of three kinds, two from the registry alone: ' + await text('#cnsummary'));
  ok(await count('.cngraph .cnnode') === 7 && await count('.cngraph .cnnode.host') === 4 && await count('.cngraph .cnedge') === 11 && await count('.cngraph .cnedge.strong') === 6,
    'the graph draws each host and address once, an arrow for each way and kind of connection, the paired ones strong');
  ok((await page.$$eval('.cngraph .cncount', (t) => t.map((x) => x.textContent))).sort().join() === 'Exec 2,Exec 2,Exec 2,RDP 1,RDP 1,RDP 1,RDP 1,RDP 1,RDP 1,Share 1,Share 2',
    'each arrow is labelled with its kind and count');
  ok(await count('#cnrows .cnconf.undated') === 2 && (await text('#cnrows')).includes('WS-ALICE opened a file on a share on SRV-FILE01') &&
    (await text('#cnrows')).includes("WS-ALICE's registry names JUMP-OLD as a computer this account connected to by Remote Desktop"),
    'the registry and the jump list add to the connecting end: a file opened on a share, and computers named with no time');
  const cnText = await text('#cnrows');
  ok(cnText.includes('WS-ALICE → SRV-FILE01') && cnText.includes("after correcting WS-ALICE's clock (stated as 3 minutes ahead)") && cnText.includes('203.0.113.45 is not a host of this case') &&
    cnText.includes('services installed on DC01: PSEXESVC') && cnText.includes('shares on SRV-FILE01: Finance'),
    'each connection says why: the names, the clock correction, an address outside the case, the shares and services');
  ok((await page.$$eval('#cnrows .cnrow .anpath', (r) => r.map((x) => x.firstChild.textContent))).join() ===
    '2026-11-02 14:00:00,2026-11-20 08:55:10,2026-11-20 09:14:18,2026-11-20 09:22:30,2026-11-20 09:41:03,2026-11-20 09:48:10,2026-11-20 10:05:42,2026-11-20 10:20:00,2026-11-20 10:20:01,2026-11-20 10:30:15,2026-11-20 10:50:05,2026-11-20 11:20:30,2026-11-20 11:35:40,2026-11-20 11:50:20,2026-11-20 12:05:10', 'connections are listed in corrected time order');
  await shot('18-connections-graph');
  await page.click('#cnkind [data-kind=exec]');
  ok(/^6 connections \(started remotely\)/.test(await text('#cnsummary')) && await count('#cnrows .cnrow') === 6 && await count('.cngraph .cnedge') === 3 &&
    (await text('#cnrows')).includes('PsExec') && (await text('#cnrows')).includes('Program started by WMI') && (await text('#cnrows')).includes('scheduled tasks on DC01: \\Cleanup') &&
    (await text('#cnrows')).includes('a program started remotely by DCOM'), 'the kind buttons show one kind at a time: ' + await text('#cnsummary'));
  await page.click('#cnkind [data-kind=""]');
  await page.evaluate(() => [...document.querySelectorAll('.cngraph .cnnode')].find((g) => g.textContent.endsWith('WS-ALICE')).dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerId: 1 })));
  await page.evaluate(() => [...document.querySelectorAll('.cngraph .cnnode')].find((g) => g.textContent.endsWith('WS-ALICE')).dispatchEvent(new PointerEvent('pointerup', { bubbles: true, pointerId: 1 })));
  await page.waitForFunction(() => document.querySelectorAll('#cnrows .cnrow').length === 11, { timeout: 5000 }).catch(() => {});
  ok(await count('#cnrows .cnrow') === 11 && !(await page.$eval('#cnall', (b) => b.hidden)), 'picking a host lists only its connections, with a way back to all');
  await page.click('#cnmode [data-mode=lanes]');
  ok(await count('.cnlanes .cnconn') === 15 && await count('.cnlanes .cnconn.dim') === 4 && await count('.cnlanes .cnend.missing') === 6 && await count('.cnlanes .cnkindtag') === 15 &&
    await count('.cnlanes .cnconn.undated') === 2,
    "the lanes draw every connection in time with its kind, the picked host's in full, with a hollow end where nothing was recorded, and those with no time dotted");
  ok(await count('.cnlanes .cnsession') === 4 && await count('.cnlanes .cnsession.dim') === 2 && (await text('#cnlegend')).includes('bar: a Remote Desktop session'),
    'each Remote Desktop session with an end found is a bar along the lane of the computer connected to, and the legend says so');
  // The registry key written 18 days before does not stretch the time
  // across: it is drawn at the edge, and the day's connections keep their room.
  const xs = await page.$$eval('.cnlanes .cnconn .cnconnline', (ls) => ls.map((l) => Number(l.getAttribute('x1'))));
  ok(xs[1] - xs[0] < 100 && xs[xs.length - 1] - xs[1] > 300, 'a connection with no time far from the rest does not squash the lanes: ' + xs.slice(0, 3).join());
  await page.click('#cnall');
  // A period: typed, then dragged across the lanes.
  await page.type('#cnfrom', '2026-11-20 09:00');
  await page.type('#cnto', '10:00');
  await page.keyboard.press('Enter');
  ok(/^5 connections from 2026-11-20 09:00 to 2026-11-20 10:00 UTC \(2 with no time left out\) .*: 3 remote desktop, 1 file share, 1 started remotely$/.test(await text('#cnsummary')) && await count('#cnrows .cnrow') === 5 &&
    await count('.cnlanes .cnconn') === 4 && await count('.cnlanes .cnsession') === 3 && await visible('#cnwhole') && (await text('.cnlanes')).includes('09:30'),
    'a period typed shows the connections in it, a session that runs into it among them (its bar drawn, not its arrow), and the lanes span it: ' + await text('#cnsummary'));
  await page.click('#cnmode [data-mode=graph]');
  ok(await count('.cngraph .cnedge') < 11 && (await page.$$eval('.cngraph .cncount', (t) => t.reduce((n, x) => n + Number(x.textContent.split(' ')[1]), 0))) === 5, 'the graph shows only the arrows of the period, counted in it');
  await page.click('#cnmode [data-mode=lanes]');
  await page.$eval('#cnfrom', (el) => { el.value = ''; });
  await page.type('#cnfrom', 'yesterday');
  await page.keyboard.press('Enter');
  ok(await page.$eval('#cnfrom', (el) => el.classList.contains('bad')) && await count('#cnrows .cnrow') === 5, 'a time that cannot be read is marked, and the period stays');
  await page.click('#cnwhole');
  ok(await count('#cnrows .cnrow') === 15 && !(await visible('#cnwhole')) && (await page.$eval('#cnfrom', (el) => el.value)) === '', '"Whole time" shows every connection again');
  await page.$eval('.cnlanes', (el) => el.scrollIntoView({ block: 'center' }));
  const lb = await page.$eval('.cnlanes', (el) => { const b = el.getBoundingClientRect(); return { x: b.left, y: b.top, w: b.width }; });
  const plot = (f) => lb.x + 150 + f * (lb.w - 180);
  await page.mouse.move(plot(0.3), lb.y + 31);
  await page.mouse.down();
  await page.mouse.move(plot(0.45), lb.y + 31, { steps: 4 });
  await page.mouse.move(plot(0.6), lb.y + 31, { steps: 4 });
  await page.mouse.up();
  await page.waitForFunction(() => document.getElementById('cnfrom').value !== '', { timeout: 5000 }).catch(() => {});
  const dragged = await count('#cnrows .cnrow');
  ok(dragged >= 1 && dragged < 15 && await count('.cnlanes .cnconn') <= dragged && /^2026-11-20 \d\d:\d\d:\d\d$/.test(await page.$eval('#cnto', (el) => el.value)) &&
    await count('.cnbrush') === 0, `dragging across the lanes chooses that period and zooms to it: ${dragged} connections, ${await page.$eval('#cnfrom', (el) => el.value)} to ${await page.$eval('#cnto', (el) => el.value)}`);
  await shot('19b-connections-period');
  await page.click('#cnwhole');
  await page.evaluate(() => [...document.querySelectorAll('#cnrows .cnrow')][2].querySelector('.cnactions button').click());
  ok((await text('#cnrows .cnrow.on')).includes('Remote Desktop client connecting (1024)') && (await text('#cnrows .cnrow.on')).includes('by its clock') &&
    (await text('#cnrows .cnrow.on')).includes("Also named in WS-ALICE's registry"),
    "a connection opens each end's events, with the time as that host's clock had it, and the registry's records that support it");
  ok((await text('#cnrows .cnrow.on .cnsess')) === 'session 39 min' && (await text('#cnrows .cnrow.on')).includes('the session lasted 38 minutes 40 seconds') &&
    (await text('#cnrows .cnrow.on')).includes('Remote Desktop session logoff (23)'), "a session's length is on its row, with the logoff among the events of the end connected to");
  await shot('19-connections-lanes');
  await page.evaluate(() => [...document.querySelectorAll('#cnrows .cnrow')][2].querySelectorAll('.cnactions button')[1].click());
  await page.waitForFunction(() => !document.getElementById('view-timeline').hidden && document.querySelectorAll('#win .row').length === 13, { timeout: 20000 }).catch(() => {});
  ok((await page.$eval('#q', (el) => el.value)).startsWith('id:') && await summaryCount() === 13, 'a connection opens its 13 events, from both hosts and the registry, the session\'s end among them, on the timeline');
  // And back: an event of a connection offers its connections.
  await page.click('#win .row');
  await page.waitForSelector('#detail:not([hidden]) .cnfrom', { timeout: 10000 }).catch(() => {});
  const evId = await page.$eval('#detail h2', (x) => x.firstChild.textContent.replace('Event ', '')).catch(() => '');
  ok(await count('#detail .cnfrom button') === 1, 'an event read for the Connections tab says so in its panel, with "Show its connections"');
  await page.click('#detail .cnfrom button');
  await page.waitForFunction(() => !document.getElementById('view-connections').hidden && document.querySelector('#cnrows .cnpicked'), { timeout: 20000 }).catch(() => {});
  const evRows = await count('#cnrows .cnrow');
  ok(evRows >= 1 && evRows < 15 && (await text('#cnrows .cnpicked')).startsWith(`Connections that event #${evId} is part of`) && await visible('#cnall') &&
    await count('.cngraph .cnedge.dim, .cnlanes .cnconn.dim') > 0, `"Show its connections" opens the Connections tab on the ${evRows} connection(s) event #${evId} is part of, the rest dimmed`);
  await page.click('#cnall');
  ok(await count('#cnrows .cnrow') === 15, '"Show all" brings back every connection');
  await page.goto(URL, { waitUntil: 'networkidle0' });

  // ---- narrow window ----
  await page.setViewport({ width: 700, height: 900 });
  await page.click('#nav [data-view=timeline]');
  await page.click('#win .row');
  await sleep(500);
  ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'no horizontal page scroll at 700px wide');
  await page.click('#nav [data-view=help]');
  ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth) &&
    await page.evaluate(() => [...document.querySelectorAll('.helpbody table')].every((t) => t.getBoundingClientRect().right <= window.innerWidth + 1)), 'the guide fits a narrow window');
  await page.click('#nav [data-view=timeline]');
  await shot('10-narrow');

  await page.setViewport({ width: 1500, height: 900 });
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }]);
  await sleep(300);
  await shot('11-light');
  await page.click('#nav [data-view=evidence]');
  await sleep(500);
  await shot('12-light-evidence');

  ok(errors.length === 0, 'no console errors, failed requests or policy violations' + (errors.length ? ':\n     ' + errors.join('\n     ') : ''));
  await browser.close();
  console.log(problems.length ? `\n${problems.length} PROBLEM(S)` : `\nall ${step} checks passed`);
  process.exit(problems.length ? 1 : 0);
})().catch((e) => { console.error('driver crashed:', e); process.exit(2); });
