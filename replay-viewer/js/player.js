// Playback clock. Speed changes only how fast the clock runs between frames;
// the real elapsed time of each frame is always what the clock shows.

export class Player {
  constructor(onFrame) {
    this.onFrame = onFrame;
    this.frames = [];
    this.index = 0;
    this.speed = 1;
    this.timer = null;
  }

  load(frames, index = 0) {
    this.pause();
    this.frames = frames;
    this.seek(Math.min(index, Math.max(frames.length - 1, 0)));
  }

  get playing() {
    return this.timer !== null;
  }

  seek(i) {
    if (!this.frames.length) return;
    this.index = Math.max(0, Math.min(i, this.frames.length - 1));
    this.onFrame(this.index);
  }

  step(delta = 1) {
    this.pause();
    this.seek(this.index + delta);
  }

  play() {
    if (this.playing || !this.frames.length) return;
    if (this.index >= this.frames.length - 1) this.seek(0);
    this.schedule();
    this.onFrame(this.index);
  }

  pause() {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  schedule() {
    const cur = this.frames[this.index];
    const next = this.frames[this.index + 1];
    if (!next) {
      this.timer = null;
      this.onFrame(this.index);
      return;
    }
    const wait = Math.max(0, next.elapsed_ms - cur.elapsed_ms) / this.speed;
    this.timer = setTimeout(() => {
      this.index += 1;
      this.onFrame(this.index);
      this.schedule();
    }, wait);
  }
}

export function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const parts = [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60].map((n) => String(n).padStart(2, '0'));
  return `${parts.join(':')}.${String(ms % 1000).padStart(3, '0')}`;
}
