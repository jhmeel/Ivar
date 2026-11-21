// Export a verified replay as an MP4 video, entirely in the browser: frames
// are drawn on a canvas, encoded with WebCodecs (H.264, or VP9 where H.264
// encoding is unavailable) and muxed into MP4. Nothing leaves the machine,
// so an auditor can export offline.

import { Muxer, ArrayBufferTarget } from '../../vendor/mp4-muxer/mp4-muxer.mjs';
import { WIDTH, HEIGHT, prepare, drawTitle, drawFrame, drawSummary } from './render.js';

const CODECS = [
  { encoder: 'avc1.640028', muxer: 'avc', label: 'H.264' },
  { encoder: 'vp09.00.40.08', muxer: 'vp9', label: 'VP9' },
];

async function pickCodec(bitrate, framerate) {
  if (typeof VideoEncoder === 'undefined') throw new Error('this browser has no WebCodecs video encoder; use a current Chrome, Edge or Firefox over https or localhost');
  for (const c of CODECS) {
    const config = { codec: c.encoder, width: WIDTH, height: HEIGHT, bitrate, framerate };
    if ((await VideoEncoder.isConfigSupported(config)).supported) return { ...c, config };
  }
  throw new Error('no supported MP4 video codec (H.264 or VP9) in this browser');
}

/**
 * The playback speed for a replay: 1 unless the incident is long, then the
 * smallest whole speed that fits it in `maxSeconds`. Speed changes only the
 * clock; the video always shows real elapsed time.
 */
export function defaultSpeed(bundle, maxSeconds = 90) {
  const span = bundle.frames[bundle.frames.length - 1].elapsed_ms;
  return Math.max(1, Math.ceil(span / (maxSeconds * 1000)));
}

/**
 * Render and encode. Returns { blob, codec, seconds }.
 * options: speed (playback speed), fps, titleSeconds, summarySeconds,
 * tailSeconds (hold after the last frame), onProgress(fraction).
 */
export async function exportMp4(bundle, options = {}) {
  const fps = options.fps ?? 30;
  const speed = options.speed ?? defaultSpeed(bundle);
  const titleSeconds = options.titleSeconds ?? 3;
  const summarySeconds = options.summarySeconds ?? 4;
  const tailSeconds = options.tailSeconds ?? 1.5;
  const codec = await pickCodec(options.bitrate ?? 5_000_000, fps);
  const P = prepare(bundle);

  const canvas = typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(WIDTH, HEIGHT) : Object.assign(document.createElement('canvas'), { width: WIDTH, height: HEIGHT });
  const g = canvas.getContext('2d', { alpha: false });
  const muxer = new Muxer({ target: new ArrayBufferTarget(), video: { codec: codec.muxer, width: WIDTH, height: HEIGHT, frameRate: fps }, fastStart: 'in-memory', firstTimestampBehavior: 'offset' });
  let failure;
  const encoder = new VideoEncoder({ output: (chunk, meta) => muxer.addVideoChunk(chunk, meta), error: (e) => (failure = e) });
  encoder.configure(codec.config);

  const playMs = P.span / speed;
  const total = Math.ceil((titleSeconds + playMs / 1000 + tailSeconds + summarySeconds) * fps);
  const frameUs = 1_000_000 / fps;
  for (let i = 0; i < total; i++) {
    if (failure) throw failure;
    const sec = i / fps;
    if (sec < titleSeconds) drawTitle(g, bundle, P);
    else if (sec < titleSeconds + playMs / 1000 + tailSeconds) drawFrame(g, bundle, P, (sec - titleSeconds) * 1000 * speed, speed);
    else drawSummary(g, bundle, P);
    const frame = new VideoFrame(canvas, { timestamp: Math.round(i * frameUs), duration: Math.round(frameUs) });
    encoder.encode(frame, { keyFrame: i % (fps * 2) === 0 });
    frame.close();
    // Back pressure: keep the encoder queue short so memory stays flat.
    while (encoder.encodeQueueSize > 8) await new Promise((r) => setTimeout(r, 1));
    if (i % fps === 0) options.onProgress?.(i / total);
  }
  await encoder.flush();
  if (failure) throw failure;
  encoder.close();
  muxer.finalize();
  options.onProgress?.(1);
  return { blob: new Blob([muxer.target.buffer], { type: 'video/mp4' }), codec: codec.label, seconds: total / fps, speed };
}
