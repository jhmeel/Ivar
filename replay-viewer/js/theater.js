// Full screen replay: the verified replay drawn by the same renderer as the
// MP4 export, so what you watch full screen is exactly what the video holds.
// Playback runs on the real elapsed clock scaled by one speed (section
// 13.2); the controls fade while the pointer is idle.

import { WIDTH, HEIGHT, prepare, drawFrame, frameAt } from './video/render.js';
import { formatElapsed } from './player.js';

export class Theater {
  constructor({ onExit, onExport }) {
    this.onExit = onExit;
    this.onExport = onExport;
    this.el = null;
    this.playing = false;
    this.t = 0;
    this.speed = 1;
  }

  get isOpen() {
    return !!this.el;
  }

  open(bundle, startMs = 0, speed = 1) {
    if (this.el) this.close();
    this.bundle = bundle;
    this.P = prepare(bundle);
    this.t = Math.min(startMs, this.P.span);
    this.speed = speed;
    const el = document.createElement('div');
    el.className = 'theater';
    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-label', 'Full screen replay');
    el.innerHTML = `
      <canvas width="${WIDTH}" height="${HEIGHT}" aria-label="Replay"></canvas>
      <div class="theater-bar">
        <button type="button" class="btn btn-icon" data-act="back" aria-label="Back 2 seconds" title="Back 2 s (left arrow)"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M9 5 4 10l5 5M16 5l-5 5 5 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
        <button type="button" class="btn btn-play" data-act="play" aria-label="Play" title="Play or pause (space)"><svg class="i-play" viewBox="0 0 20 20" aria-hidden="true"><path d="M6 4l10 6-10 6z" fill="currentColor"/></svg><svg class="i-pause" viewBox="0 0 20 20" aria-hidden="true"><path d="M5 4h3.5v12H5zM11.5 4H15v12h-3.5z" fill="currentColor"/></svg></button>
        <button type="button" class="btn btn-icon" data-act="fwd" aria-label="Forward 2 seconds" title="Forward 2 s (right arrow)"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m11 5 5 5-5 5M4 5l5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
        <select data-act="speed" aria-label="Speed">${[0.25, 0.5, 1, 2, 4, 16, 64].map((s) => `<option value="${s}" ${s === speed ? 'selected' : ''}>${s}×</option>`).join('')}</select>
        <input type="range" min="0" max="${this.P.span}" step="1" value="${this.t}" aria-label="Position">
        <div class="clock"><div><span class="clock-label">Real elapsed</span><span data-clock></span></div><div><span class="clock-label">Frame</span><span data-frame></span></div></div>
        <button type="button" class="btn" data-act="export">Export MP4</button>
        <button type="button" class="btn" data-act="exit" title="Exit full screen (Esc)">Done</button>
      </div>`;
    document.body.appendChild(el);
    this.el = el;
    this.canvas = el.querySelector('canvas');
    this.g = this.canvas.getContext('2d', { alpha: false });
    this.range = el.querySelector('input[type=range]');
    this.playBtn = el.querySelector('[data-act=play]');
    el.querySelector('[data-act=play]').addEventListener('click', () => this.toggle());
    el.querySelector('[data-act=back]').addEventListener('click', () => this.seek(this.t - 2000));
    el.querySelector('[data-act=fwd]').addEventListener('click', () => this.seek(this.t + 2000));
    el.querySelector('[data-act=speed]').addEventListener('change', (e) => (this.speed = Number(e.target.value)));
    el.querySelector('[data-act=export]').addEventListener('click', () => this.onExport?.(this.speed));
    el.querySelector('[data-act=exit]').addEventListener('click', () => this.close());
    this.range.addEventListener('input', () => this.seek(Number(this.range.value)));
    this.keys = (e) => this.key(e);
    document.addEventListener('keydown', this.keys, true);
    this.idle = () => {
      el.classList.remove('idle');
      clearTimeout(this.idleTimer);
      this.idleTimer = setTimeout(() => this.playing && el.classList.add('idle'), 2200);
    };
    el.addEventListener('mousemove', this.idle);
    this.fsChange = () => {
      if (!document.fullscreenElement && this.el && this.wasFullscreen) this.close();
    };
    document.addEventListener('fullscreenchange', this.fsChange);
    this.wasFullscreen = false;
    el.requestFullscreen?.().then(() => (this.wasFullscreen = true)).catch(() => {});
    this.draw();
    this.play();
  }

  key(e) {
    if (!this.el) return;
    const k = e.key;
    if (k === 'Escape' || k === 'f' || k === 'F') this.close();
    else if (k === ' ') this.toggle();
    else if (k === 'ArrowRight') this.seek(this.t + 2000);
    else if (k === 'ArrowLeft') this.seek(this.t - 2000);
    else if (k === 'Home') this.seek(0);
    else if (k === 'End') this.seek(this.P.span);
    else return;
    e.preventDefault();
    e.stopPropagation();
    this.idle();
  }

  toggle() {
    if (this.playing) this.pause();
    else this.play();
  }

  play() {
    if (this.t >= this.P.span) this.t = 0;
    this.playing = true;
    this.playBtn.classList.add('playing');
    this.last = performance.now();
    const loop = (now) => {
      if (!this.playing || !this.el) return;
      this.t = Math.min(this.P.span, this.t + (now - this.last) * this.speed);
      this.last = now;
      this.draw();
      if (this.t >= this.P.span) return this.pause();
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
    this.idle();
  }

  pause() {
    this.playing = false;
    cancelAnimationFrame(this.raf);
    this.playBtn?.classList.remove('playing');
    this.el?.classList.remove('idle');
  }

  seek(ms) {
    this.t = Math.max(0, Math.min(this.P.span, ms));
    this.last = performance.now();
    this.draw();
  }

  draw() {
    drawFrame(this.g, this.bundle, this.P, this.t, this.speed);
    this.range.value = String(Math.round(this.t));
    const idx = frameAt(this.P.frames, this.t);
    this.el.querySelector('[data-clock]').textContent = formatElapsed(Math.round(this.t));
    this.el.querySelector('[data-frame]').textContent = `${idx + 1} / ${this.P.frames.length}`;
    this.index = idx;
  }

  close() {
    if (!this.el) return;
    this.pause();
    document.removeEventListener('keydown', this.keys, true);
    document.removeEventListener('fullscreenchange', this.fsChange);
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    const index = Math.max(0, this.index ?? 0);
    this.el.remove();
    this.el = null;
    this.onExit?.(index);
  }
}
