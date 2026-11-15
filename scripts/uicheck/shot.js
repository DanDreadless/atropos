// Screenshots of the top bar in the light and dark themes, for looking at.
//   ATROPOS_URL, ATROPOS_TOKEN, BROWSER and OUT as for drive.js
const puppeteer = require('puppeteer-core');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({ executablePath: process.env.BROWSER, headless: 'new', args: ['--no-first-run'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1100, height: 420, deviceScaleFactor: 2 });
  for (const scheme of ['light', 'dark']) {
    await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: scheme }]);
    await page.goto(process.env.ATROPOS_URL + '?token=' + process.env.ATROPOS_TOKEN, { waitUntil: 'networkidle0' });
    await page.screenshot({ path: path.join(process.env.OUT, 'top-' + scheme + '.png'), clip: { x: 0, y: 0, width: 620, height: 60 } });
  }
  await browser.close();
})();
