#!/usr/bin/env node
// Export a ReplayBundle as an MP4 video, headless, with the same code the
// replay viewer's Export MP4 button runs: the bundle is verified (signature,
// evidence chain, re execution) before a single frame is drawn.
//
//   node scripts/export-replay.cjs <bundle.json> <keyring.json> <redaction.hex> <out.mp4> [--speed N] [--fps N]
//
// Needs Playwright with Chromium (WebCodecs) and a built replay-viewer/pkg
// (scripts/build-wasm.sh).

'use strict';
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? Number(args.splice(i, 2)[1]) : undefined;
};
const speed = flag('--speed');
const fps = flag('--fps');
const [bundleFile, keyringFile, keyFile, out] = args;
if (!out) {
  console.error('usage: export-replay.cjs <bundle.json> <keyring.json> <redaction.hex> <out.mp4> [--speed N] [--fps N]');
  process.exit(2);
}

const root = path.join(__dirname, '..', 'replay-viewer');
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const file = path.join(root, decodeURIComponent(new URL(req.url, 'http://x').pathname));
  if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    // WebCodecs needs a secure context: localhost is one.
    await page.goto(`http://localhost:${server.address().port}/index.html`);
    await page.waitForFunction(() => typeof window.ivarExportMp4 === 'function');
    const started = Date.now();
    const r = await page.evaluate(
      ([b, k, h, o]) => window.ivarExportMp4(b, k, h, o),
      [fs.readFileSync(bundleFile, 'utf8'), fs.readFileSync(keyringFile, 'utf8'), fs.readFileSync(keyFile, 'utf8').trim(), { speed, fps }],
    );
    fs.writeFileSync(out, Buffer.from(r.base64, 'base64'));
    console.log(`${out}: ${r.codec}, ${r.seconds.toFixed(1)} s at playback x${r.speed}, ${r.frames} frames, ${r.verdicts} verdicts verified, rendered in ${((Date.now() - started) / 1000).toFixed(1)} s`);
    if (errors.length) console.error(errors.join('\n'));
  } finally {
    await browser.close();
    server.close();
  }
})().catch((e) => {
  console.error(String(e.message ?? e));
  process.exit(1);
});
