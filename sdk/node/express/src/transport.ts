// Delivery of events to the core ingest gateway. Batches off the request
// path, buffers while the core is unreachable (sensors keep enforcing their
// last signed policy), and sends a heartbeat so silence raises a tamper alert.

import type { Verdict } from './types';

export interface Transport {
  /** Queue an event. Urgent events (authentication, business actions) are
   *  sent at once rather than on the next batch, so a fast attack such as a
   *  credential spray meets the core's verdict within a few requests. */
  send(event: Record<string, unknown>, urgent?: boolean): void;
  close(): void;
}

interface Ack {
  verdicts?: Verdict[];
  verdict_cursor?: number;
}

export class HttpTransport implements Transport {
  private queue: Record<string, unknown>[] = [];
  private dropped = 0;
  private timer: NodeJS.Timeout;
  private heartbeat: NodeJS.Timeout;
  private inFlight?: Promise<void>;
  private again = false;
  /** Position in the core's verdict feed: verdicts other sensors caused reach this app too. */
  private cursor = 0;
  private lastPoll = 0;

  constructor(private url: string, private sensorId: string, private onVerdicts: (v: Verdict[]) => void, private capacity = 10_000) {
    this.timer = setInterval(() => void (this.queue.length ? this.flush() : this.pollFeed()), 200);
    this.heartbeat = setInterval(() => this.send({ activity_name: 'sensor.heartbeat', time: Date.now(), ivar: { sensor_id: sensorId, sensor_type: 'app_sdk' } }), 20_000);
    this.timer.unref();
    this.heartbeat.unref();
  }

  send(event: Record<string, unknown>, urgent = false): void {
    if (this.queue.length >= this.capacity) {
      this.queue.shift();
      this.dropped += 1;
    }
    this.queue.push(event);
    if (urgent) void this.flush();
  }

  /** Send what is queued. One request at a time; a flush asked for while one
   *  is in flight runs straight after it. */
  flush(): Promise<void> {
    if (this.inFlight) {
      this.again = true;
      return this.inFlight;
    }
    this.inFlight = this.deliver().finally(() => {
      this.inFlight = undefined;
      if (this.again) {
        this.again = false;
        void this.flush();
      }
    });
    return this.inFlight;
  }

  private async deliver(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, 500);
    try {
      const res = await fetch(`${this.url.replace(/\/$/, '')}/v1/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ivar-dropped': String(this.dropped) },
        body: JSON.stringify({ sensor_id: this.sensorId, events: batch, verdict_cursor: this.cursor }),
      });
      if (!res.ok) throw new Error(`ingest ${res.status}`);
      this.accept((await res.json()) as Ack);
    } catch {
      this.queue.unshift(...batch.slice(0, Math.max(0, this.capacity - this.queue.length)));
    }
  }

  private accept(ack: Ack): void {
    if (typeof ack.verdict_cursor === 'number') this.cursor = Math.max(this.cursor, ack.verdict_cursor);
    if (ack.verdicts?.length) this.onVerdicts(ack.verdicts);
  }

  /** While idle, fetch standing verdicts about once a second. */
  private async pollFeed(): Promise<void> {
    const now = Date.now();
    if (this.inFlight || now - this.lastPoll < 1_000) return;
    this.lastPoll = now;
    try {
      const res = await fetch(`${this.url.replace(/\/$/, '')}/v1/verdicts?since=${this.cursor}`, { signal: AbortSignal.timeout(2_000) });
      if (res.ok) this.accept((await res.json()) as Ack);
    } catch {
      // The core is unreachable: the cached verdicts and signed policy stay in force.
    }
  }

  close(): void {
    clearInterval(this.timer);
    clearInterval(this.heartbeat);
  }
}
