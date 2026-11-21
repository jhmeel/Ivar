// Delivery of events to the core ingest gateway. Batches off the request
// path, buffers while the core is unreachable (sensors keep enforcing their
// last signed policy), and sends a heartbeat so silence raises a tamper alert.

import type { Verdict } from './types';

export interface Transport {
  send(event: Record<string, unknown>): void;
  close(): void;
}

export class HttpTransport implements Transport {
  private queue: Record<string, unknown>[] = [];
  private dropped = 0;
  private timer: NodeJS.Timeout;
  private heartbeat: NodeJS.Timeout;

  constructor(private url: string, private sensorId: string, private onVerdicts: (v: Verdict[]) => void, private capacity = 10_000) {
    this.timer = setInterval(() => void this.flush(), 200);
    this.heartbeat = setInterval(() => this.send({ activity_name: 'sensor.heartbeat', time: Date.now(), ivar: { sensor_id: sensorId, sensor_type: 'app_sdk' } }), 20_000);
    this.timer.unref();
    this.heartbeat.unref();
  }

  send(event: Record<string, unknown>): void {
    if (this.queue.length >= this.capacity) {
      this.queue.shift();
      this.dropped += 1;
    }
    this.queue.push(event);
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, 500);
    try {
      const res = await fetch(`${this.url.replace(/\/$/, '')}/v1/events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ivar-dropped': String(this.dropped) },
        body: JSON.stringify({ sensor_id: this.sensorId, events: batch }),
      });
      if (!res.ok) throw new Error(`ingest ${res.status}`);
      const ack = (await res.json()) as { verdicts?: Verdict[] };
      if (ack.verdicts?.length) this.onVerdicts(ack.verdicts);
    } catch {
      this.queue.unshift(...batch.slice(0, Math.max(0, this.capacity - this.queue.length)));
    }
  }

  close(): void {
    clearInterval(this.timer);
    clearInterval(this.heartbeat);
  }
}
