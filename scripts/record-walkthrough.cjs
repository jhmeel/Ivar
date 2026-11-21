#!/usr/bin/env node
// Records the operator console walkthrough video in the README: the real
// console, driven through a signed ReplayBundle, captured at 1920x1080 with
// Chromium's screencast and encoded to H.264 with ffmpeg.
//
//   node scripts/record-walkthrough.cjs <bundle.json> <keyring.json> <redaction.hex> <out.mp4>
//
// Needs Playwright with Chromium, ffmpeg, and a built replay-viewer/pkg.

'use strict';
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { chromium } = require('playwright');

const [bundleFile, keyringFile, keyFile, out] = process.argv.slice(2);
if (!out) {
  console.error('usage: record-walkthrough.cjs <bundle.json> <keyring.json> <redaction.hex> <out.mp4>');
  process.exit(2);
}
const root = path.join(__dirname, '..', 'replay-viewer');
const brand = path.join(__dirname, '..', 'docs', 'brand');
const frames = fs.mkdtempSync(path.join(os.tmpdir(), 'ivar-walkthrough-'));

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml' };
function serve() {
  const srv = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url.split('?')[0]);
    const file = url.startsWith('/brand/') ? path.join(brand, url.slice(7)) : path.join(root, url === '/' ? 'index.html' : url);
    if (!file.startsWith(root) && !file.startsWith(brand)) return res.writeHead(403).end();
    fs.readFile(file, (err, data) => {
      if (err) return res.writeHead(404).end();
      res.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream' }).end(data);
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv)));
}

// Captions, a visible cursor and the title and end cards, drawn over the
// console in the page itself so they are part of every captured frame.
const OVERLAY = `
(() => {
  // Headless Chromium resizes the captured surface for the Fullscreen API,
  // so the full screen replay is recorded as the page overlay it already is.
  Element.prototype.requestFullscreen = function () { return Promise.resolve(); };
  document.exitFullscreen = function () { return Promise.resolve(); };
  const css = document.createElement('style');
  css.textContent = \`
    #wt-cursor { position: fixed; left: 0; top: 0; width: 22px; height: 22px; z-index: 2147483647; pointer-events: none; transform: translate(-3px, -2px); transition: transform .08s; }
    #wt-cursor.down { transform: translate(-3px, -2px) scale(.86); }
    #wt-ripple { position: fixed; width: 34px; height: 34px; margin: -17px 0 0 -17px; border-radius: 50%; border: 2px solid #eb6834; opacity: 0; z-index: 2147483646; pointer-events: none; }
    #wt-ripple.go { animation: wt-ripple .5s ease-out; }
    @keyframes wt-ripple { from { opacity: .9; transform: scale(.4); } to { opacity: 0; transform: scale(1.4); } }
    #wt-caption { position: fixed; left: 50%; bottom: 112px; transform: translate(-50%, 12px); max-width: 980px; padding: 16px 26px 18px; border-radius: 18px;
      background: rgba(18, 18, 20, .82); backdrop-filter: blur(24px) saturate(1.6); -webkit-backdrop-filter: blur(24px) saturate(1.6);
      box-shadow: 0 0 0 .5px rgba(255,255,255,.14), 0 18px 50px rgba(0,0,0,.45); color: #f5f5f7; z-index: 2147483645; opacity: 0;
      transition: opacity .45s ease, transform .45s ease; pointer-events: none; font: 15.5px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", Inter, system-ui, sans-serif; text-align: center; }
    #wt-caption.on { opacity: 1; transform: translate(-50%, 0); }
    #wt-caption b { display: block; font-size: 19px; font-weight: 650; letter-spacing: -.01em; margin-bottom: 3px; }
    #wt-caption b i { font-style: normal; color: #eb6834; margin-right: 10px; font-variant-numeric: tabular-nums; }
    #wt-card { position: fixed; inset: 0; z-index: 2147483644; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 18px;
      background: radial-gradient(1200px 600px at 50% 40%, #1c1c1f, #0b0b0c); color: #f5f5f7; opacity: 0; transition: opacity .6s ease; pointer-events: none;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", Inter, system-ui, sans-serif; }
    #wt-card.on { opacity: 1; }
    #wt-card img { width: 420px; }
    #wt-card .u { margin-top: 6px; font: 17px ui-monospace, "SF Mono", Menlo, monospace; color: #a1a1a6; letter-spacing: .02em; }
    #wt-card svg.intro { width: 720px; overflow: visible; }
    .intro .ghost rect { fill: #fff; opacity: 0; animation: wt-ghost 3.9s ease-out .1s forwards; }
    @keyframes wt-ghost { 0% { opacity: 0; } 25% { opacity: .05; } 80% { opacity: .05; } 100% { opacity: 0; } }
    .intro .px rect { fill: #f5f5f7; opacity: 0; transform-box: fill-box; transform-origin: center; animation: wt-pop .42s cubic-bezier(.3, 1.5, .5, 1) forwards; }
    @keyframes wt-pop { from { opacity: 0; transform: scale(.35); } to { opacity: 1; transform: scale(1); } }
    .intro .scan { fill: #eb6834; opacity: 0; animation: wt-scan .9s cubic-bezier(.5, 0, .3, 1) 1.45s forwards; }
    @keyframes wt-scan { 0% { opacity: 0; transform: translateY(0); } 15% { opacity: .9; } 85% { opacity: .9; } 100% { opacity: 0; transform: translateY(116px); } }
    .intro .hit { fill: #eb6834; opacity: 0; transform-box: fill-box; transform-origin: center; animation: wt-hit .5s cubic-bezier(.3, 1.6, .5, 1) 1.62s forwards; }
    @keyframes wt-hit { from { opacity: 0; transform: scale(1.8); } to { opacity: 1; transform: scale(1); } }
    .intro .ring { fill: none; stroke: #eb6834; stroke-width: 1.6; opacity: 0; transform-box: fill-box; transform-origin: center; animation: wt-ring 1.1s ease-out 1.7s 2; }
    @keyframes wt-ring { 0% { opacity: .8; transform: scale(1); } 100% { opacity: 0; transform: scale(3.2); } }
    .intro .mk { transform: translateX(143px); animation: wt-slide .9s cubic-bezier(.6, 0, .2, 1) 2.55s forwards; }
    @keyframes wt-slide { to { transform: translateX(0); } }
    .intro .wm path { fill: #f5f5f7; opacity: 0; transform: translateY(14px); animation: wt-letter .7s cubic-bezier(.2, .8, .2, 1) forwards; }
    @keyframes wt-letter { to { opacity: 1; transform: translateY(0); } }
  \`;
  document.head.appendChild(css);
  const cursor = document.createElement('div');
  cursor.id = 'wt-cursor';
  cursor.innerHTML = '<svg viewBox="0 0 22 22" width="22" height="22"><path d="M3 2l14 9.2-6.3 1.1 3.6 6.6-2.6 1.3-3.5-6.7L3 17.6z" fill="#fff" stroke="#111" stroke-width="1.3" stroke-linejoin="round"/></svg>';
  const ripple = document.createElement('div');
  ripple.id = 'wt-ripple';
  const cap = document.createElement('div');
  cap.id = 'wt-caption';
  const card = document.createElement('div');
  card.id = 'wt-card';
  document.body.append(cursor, ripple, cap, card);
  addEventListener('mousemove', (e) => { cursor.style.left = e.clientX + 'px'; cursor.style.top = e.clientY + 'px'; }, true);
  addEventListener('mousedown', (e) => {
    cursor.classList.add('down');
    ripple.style.left = e.clientX + 'px'; ripple.style.top = e.clientY + 'px';
    ripple.classList.remove('go'); void ripple.offsetWidth; ripple.classList.add('go');
  }, true);
  addEventListener('mouseup', () => cursor.classList.remove('down'), true);
  window.wt = {
    caption(step, title, text) {
      cap.classList.remove('on');
      setTimeout(() => { cap.innerHTML = '<b><i>' + step + '</i>' + title + '</b>' + text; cap.classList.add('on'); }, title ? 350 : 0);
    },
    hide() { cap.classList.remove('on'); },
    card(html) { card.innerHTML = html; card.classList.add('on'); cursor.style.opacity = '0'; },
    uncard() { card.classList.remove('on'); cursor.style.opacity = '1'; },
  };
})();`;

  // The logo assembling: the pattern, the V, a scan that finds the one pixel
  // that does not belong, then the wordmark.
  function introSvg() {
    const cell = (i, j, extra = '') => `<rect x="${8 + i * 21.5}" y="${8 + j * 21.5}" width="17.5" height="17.5" rx="4"${extra}/>`;
    const grid = [];
    for (let j = 0; j < 5; j++) for (let i = 0; i < 5; i++) grid.push(cell(i, j));
    const v = [[0, 0], [0, 1], [1, 2], [1, 3], [2, 4], [3, 3], [3, 2], [4, 1], [4, 0]];
    const px = v.map(([i, j], k) => cell(i, j, ` style="animation-delay:${(0.35 + k * 0.085).toFixed(3)}s"`)).join('');
    const letters = ['M18 20h44v15h-14.5v50h14.5v15h-44v-15h14.5v-50h-14.5z', 'M90 20h16l14 58 14-58h16l-22 80h-16z',
      'M170 100l22-80h16l22 80h-16l-4.6-17h-19.8l-4.6 17zM193.4 69h13.2l-6.6-25z', 'M252 100v-80h32a23 23 0 0 1 6 45.2l18 34.8h-17l-16.5-33h-7.5v33zM267 34v24h16a12 12 0 0 0 0-24z'];
    const wm = letters.map((d, k) => `<path d="${d}" style="animation-delay:${(2.85 + k * 0.11).toFixed(2)}s"/>`).join('');
    return `<svg class="intro" viewBox="0 0 430 120" aria-label="IVAR"><g class="mk"><g class="ghost">${grid.join('')}</g><g class="px">${px}</g>` +
      `<rect class="scan" x="2" y="2" width="116" height="2.2" rx="1.1"/>${cell(2, 1, ' class="ring"')}${cell(2, 1, ' class="hit"')}</g>` +
      `<g transform="translate(146,24) scale(0.82)"><g class="wm">${wm}</g></g></svg>`;
  }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const srv = await serve();
  const base = `http://127.0.0.1:${srv.address().port}`;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1.2, colorScheme: 'dark' });
  page.on('pageerror', (e) => console.error('page error:', e.message));

  // Capture: every screencast frame with its timestamp, held until the next.
  const cdp = await page.context().newCDPSession(page);
  const shots = [];
  cdp.on('Page.screencastFrame', async (f) => {
    const file = path.join(frames, `${String(shots.length).padStart(6, '0')}.jpg`);
    fs.writeFileSync(file, Buffer.from(f.data, 'base64'));
    shots.push({ file, t: f.metadata.timestamp });
    await cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {});
  });

  await page.goto(`${base}/index.html`);
  await page.evaluate(OVERLAY);
  await page.mouse.move(800, 450);
  const at = { x: 800, y: 450 };
  const moveTo = async (sel, opts = {}) => {
    const el = typeof sel === 'string' ? page.locator(sel).first() : sel;
    await el.scrollIntoViewIfNeeded();
    const b = await el.boundingBox();
    const x = b.x + b.width * (opts.fx ?? 0.5), y = b.y + b.height * (opts.fy ?? 0.5);
    const steps = Math.max(18, Math.round(Math.hypot(x - at.x, y - at.y) / 14));
    await page.mouse.move(x, y, { steps });
    at.x = x; at.y = y;
  };
  const click = async (sel, opts) => {
    await moveTo(sel, opts);
    await sleep(180);
    await page.mouse.down(); await sleep(90); await page.mouse.up();
  };
  const view = async (name) => {
    await click(`a[data-view="${name}"]`);
    await page.evaluate(() => window.scrollTo({ top: 0 }));
    await sleep(250);
  };
  const caption = (step, title, text) => page.evaluate(([s, a, b]) => window.wt.caption(s, a, b), [step, title, text]);
  const scrollMain = (y) => page.evaluate((y) => window.scrollTo({ top: y, behavior: 'smooth' }), y);

  await cdp.send('Page.startScreencast', { format: 'jpeg', quality: 92, everyNthFrame: 1, maxWidth: 1920, maxHeight: 1080 });

  // Intro: the logo alone, animated.
  await page.evaluate((html) => window.wt.card(html), introSvg());
  await sleep(5200);
  await page.evaluate(() => window.wt.uncard());
  await sleep(900);

  // 1. Load and verify.
  await caption('1', 'Load a signed replay', 'Open a ReplayBundle with the keyring that signed it.');
  await sleep(1800);
  await moveTo('label.file:has(#bundle-file)');
  await page.setInputFiles('#keyring-file', keyringFile);
  await page.fill('#redaction-key', fs.readFileSync(keyFile, 'utf8').trim());
  await page.setInputFiles('#bundle-file', bundleFile);
  await page.waitForSelector('#seal.ok, #seal.verified, .seal.ok', { timeout: 60000 }).catch(() => {});
  await page.waitForSelector('#app:not([hidden])', { timeout: 60000 });
  await sleep(600);
  await moveTo('#seal', { fx: 0.2 });
  await caption('2', 'Verified before anything renders', 'The browser checks the signature and the evidence hash chain, then re-executes every event: 139 of 139 verdicts reproduced.');
  await sleep(5200);

  // 2. Overview.
  await moveTo('.hero .h-value');
  await caption('3', 'The outcome at a glance', 'What was blocked or contained, and the pipeline from events to findings, verdicts, enforcement and response actions.');
  await sleep(4200);
  await moveTo('.flow .step:nth-child(3)');
  await sleep(1400);
  await moveTo('.flow .step:nth-child(5)');
  await sleep(1600);
  await scrollMain(430);
  await moveTo('#ov-activity', { fx: 0.62, fy: 0.35 });
  await caption('4', 'Activity over time', 'Verdicts per interval, coloured by decision, with the events, findings and actions under them.');
  await sleep(4400);

  // 3. Playback.
  await scrollMain(0);
  await sleep(500);
  await click('label.toggle:has(#follow)');
  await page.selectOption('#speed', '4');
  await caption('5', 'Replay it as it happened', 'With "As of playhead" on, every view shows only what was known at that moment of the attack.');
  await sleep(1200);
  await page.evaluate(() => { const s = document.querySelector('#scrub'); s.value = '0'; s.dispatchEvent(new Event('input', { bubbles: true })); });
  await click('#play');
  await sleep(7600);
  await click('#play');
  await click('label.toggle:has(#follow)');
  await sleep(600);

  // 4. Events and the inspector.
  await view('events');
  await caption('6', 'Every event, searchable', 'Filter by kind, decision, sensor or entity. Open any frame to inspect it.');
  await sleep(2200);
  await click('.chip[data-kind="verdict"]');
  await sleep(1300);
  const contain = page.locator('.row', { hasText: 'contain' }).first();
  await click(contain);
  await sleep(700);
  await caption('7', 'Why a source was contained', 'The decision, its risk and reasons, the policy version in force and the sensors that saw it.');
  await sleep(4600);
  await click('#drawer-tabs [data-tab="chain"]');
  await caption('8', 'From event to receipt', 'The decision chain links the request, the findings, the verdict and the response action it caused.');
  await sleep(4600);
  await click('#drawer-tabs [data-tab="evidence"]');
  await caption('9', 'Sealed evidence', 'Each record and its place in the hash chain, signed by the shard that wrote it.');
  await sleep(4000);
  await click('.chip[data-kind="verdict"]');
  await click('.chip[data-kind="event"]');
  await sleep(900);
  const request = page.locator('.row', { hasText: 'POST' }).first();
  await click((await request.count()) ? request : page.locator('.row').nth(3));
  await sleep(500);
  await click('#drawer-tabs [data-tab="request"]');
  await caption('10', 'What was sent and received', 'Method, route, status and every field checked against the declared API schema. Payload values stay redacted at the sensor.');
  await sleep(5200);
  await click('#drawer-close');
  await sleep(500);

  // 5. Sessions.
  await view('sessions');
  await caption('11', 'Every session as a transcript', 'What the client sent (→) and what came back (←), with IVAR findings, verdicts and actions in line.');
  await sleep(2600);
  await click('.card[data-key]:nth-child(1)');
  await sleep(2400);
  const spray = page.locator('.card[data-key]', { hasText: 'throttle' }).first();
  if (await spray.count()) {
    await click(spray);
    await caption('12', 'A credential spray, throttled', 'One address trying many accounts, correlated in the core and slowed at the edge.');
    await sleep(3600);
  }
  await page.evaluate(() => document.querySelector('.tx, .transcript, [aria-label="Session transcript"]')?.scrollBy({ top: 420, behavior: 'smooth' }));
  await sleep(2600);

  // 6. Entities and graph.
  await view('entities');
  await caption('13', 'Who was involved', 'Every address, user, service and session, ranked by peak risk.');
  await sleep(2400);
  await click('tr[data-key]:nth-child(1)');
  await sleep(3000);
  await view('graph');
  await caption('14', 'How it connects', 'The trust graph of the incident, the estate by layer and the latency of every hop.');
  await sleep(5000);

  // 7. Full screen replay.
  await page.evaluate(() => window.wt.hide());
  await view('overview');
  await sleep(600);
  await click('#fullscreen');
  await sleep(500);
  await page.evaluate(() => { const s = document.querySelector('.theater input[type=range]'); if (s) { s.value = s.max * 0.55; s.dispatchEvent(new Event('input', { bubbles: true })); } });
  await page.evaluate(() => document.querySelector('.theater .btn-play')?.click());
  await caption('15', 'Full screen replay', 'Drawn by the same renderer as the MP4 export.');
  await sleep(7000);
  await page.evaluate(() => window.wt.hide());
  await page.keyboard.press('Escape');
  await sleep(500);

  // End card.
  await page.evaluate(() => window.wt.card('<img src="/brand/ivar-logo-dark.svg" alt="IVAR"><div class="u">github.com/jhmeel/Ivar</div>'));
  await sleep(4200);
  await cdp.send('Page.stopScreencast');
  await browser.close();
  srv.close();

  // Encode: each frame is shown until the next one arrived.
  const list = shots.map((s, i) => `file '${s.file}'\nduration ${((shots[i + 1]?.t ?? s.t + 0.5) - s.t).toFixed(4)}`).join('\n') + `\nfile '${shots[shots.length - 1].file}'\n`;
  const listFile = path.join(frames, 'frames.txt');
  fs.writeFileSync(listFile, list);
  execFileSync('ffmpeg', ['-v', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', listFile, '-vf', 'fps=30,scale=1920:1080:flags=lanczos,format=yuv420p',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-tune', 'stillimage', '-movflags', '+faststart', out], { stdio: 'inherit' });
  fs.rmSync(frames, { recursive: true, force: true });
  const secs = shots[shots.length - 1].t - shots[0].t;
  console.log(`${out}: 1920x1080 H.264, ${secs.toFixed(1)} s, ${shots.length} captured frames`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
