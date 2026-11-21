#!/usr/bin/env python3
"""The background score for the console walkthrough video.

Synthesised here rather than licensed: soft pads on a slow progression in D,
a sub bass, a quiet arpeggio, and accents timed to the logo intro (a tick per
pixel, a bell when the scan finds the orange pixel, a swell for the wordmark).

    python3 scripts/walkthrough-score.py <seconds> <out.wav>

Mixed quietly by the caller (ffmpeg loudnorm), under the captions.
"""

import sys
import wave

import numpy as np

SR = 48000
RNG = np.random.default_rng(7)


def hz(midi):
    return 440.0 * 2 ** ((midi - 69) / 12)


def env(n, attack, release):
    """Linear attack and release in seconds over n samples, flat between."""
    e = np.ones(n)
    a, r = min(int(attack * SR), n // 2), min(int(release * SR), n // 2)
    if a:
        e[:a] = np.linspace(0, 1, a) ** 2
    if r:
        e[-r:] *= np.linspace(1, 0, r) ** 2
    return e


def place(buf, start, sig, pan=0.0):
    """Mix a mono signal into the stereo buffer at start seconds, panned."""
    i = int(start * SR)
    if i >= buf.shape[1]:
        return
    sig = sig[: buf.shape[1] - i]
    left, right = np.cos((pan + 1) * np.pi / 4), np.sin((pan + 1) * np.pi / 4)
    buf[0, i : i + len(sig)] += sig * left
    buf[1, i : i + len(sig)] += sig * right


def pad_voice(midi, dur, attack=2.5, release=3.0):
    """A warm pad note: detuned voices with a soft harmonic roll off."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    out = np.zeros(n)
    for cents in (-7, 0, 7):
        f = hz(midi) * 2 ** (cents / 1200)
        phase = RNG.uniform(0, 2 * np.pi)
        for h in range(1, 7):
            if f * h > 5000:
                break
            out += np.sin(2 * np.pi * f * h * t + phase * h) * (0.55 ** (h - 1)) / h
    # A slow swell inside the note keeps the pad alive.
    out *= 0.85 + 0.15 * np.sin(2 * np.pi * 0.11 * t + RNG.uniform(0, 6))
    return out * env(n, attack, release) / 9


def bass_voice(midi, dur, attack=1.5, release=3.0):
    """A clean bass note: no detune, so low voices do not beat."""
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = hz(midi)
    out = np.sin(2 * np.pi * f * t) + 0.35 * np.sin(2 * np.pi * 2 * f * t) + 0.12 * np.sin(2 * np.pi * 3 * f * t)
    return out * env(n, attack, release) / 6


def highpass(buf, cutoff=45.0):
    """A smooth spectral high pass: keeps the bed clear of rumble."""
    out = np.empty_like(buf)
    for ch in range(2):
        spec = np.fft.rfft(buf[ch])
        f = np.fft.rfftfreq(buf.shape[1], 1 / SR)
        spec *= 1 / np.sqrt(1 + (cutoff / np.maximum(f, 1e-3)) ** 8)
        out[ch] = np.fft.irfft(spec, buf.shape[1])
    return out


def pluck(midi, dur=1.6, bright=1.0):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = hz(midi)
    sig = np.sin(2 * np.pi * f * t) + 0.3 * bright * np.sin(2 * np.pi * 2 * f * t) * np.exp(-t * 6)
    return sig * np.exp(-t * 3.2) * env(n, 0.004, 0.2)


def bell(midi, dur=4.5):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = hz(midi)
    sig = np.zeros(n)
    for ratio, amp, decay in ((1, 1, 1.1), (2.76, 0.45, 1.8), (5.4, 0.22, 3.0), (8.93, 0.1, 4.5)):
        sig += amp * np.sin(2 * np.pi * f * ratio * t) * np.exp(-t * decay)
    return sig * env(n, 0.002, 0.4)


def tick(dur=0.09):
    n = int(dur * SR)
    t = np.arange(n) / SR
    return np.sin(2 * np.pi * 2350 * t) * np.exp(-t * 70)


def reverb(buf, seconds=3.2, mix=0.32):
    """Convolution with decaying stereo noise: a soft, wide hall."""
    n = int(seconds * SR)
    t = np.arange(n) / SR
    out = np.empty_like(buf)
    for ch in range(2):
        ir = RNG.standard_normal(n) * np.exp(-t * 2.4)
        ir[: int(0.012 * SR)] = 0
        ir /= np.sqrt(np.sum(ir**2))
        size = 1 << int(np.ceil(np.log2(buf.shape[1] + n)))
        wet = np.fft.irfft(np.fft.rfft(buf[ch], size) * np.fft.rfft(ir, size), size)[: buf.shape[1]]
        out[ch] = buf[ch] * (1 - mix) + wet * mix
    return out


def main():
    total, path = float(sys.argv[1]), sys.argv[2]
    n = int(total * SR)
    buf = np.zeros((2, n))

    # D major: Dmaj9, Bm11, Gmaj9, Asus2. MIDI notes, root first.
    chords = [
        [50, 62, 66, 69, 73, 76],
        [47, 62, 66, 69, 71, 76],
        [43, 62, 67, 71, 74, 78],
        [45, 61, 64, 69, 71, 76],
    ]
    bar = 8.0

    # Intro: a low drone that opens as the logo assembles.
    place(buf, 0.0, bass_voice(50, 6.5, attack=1.2, release=2.5) * 0.9)
    place(buf, 0.0, pad_voice(50, 6.5, attack=1.8, release=2.5) * 0.7)
    for k in range(9):
        place(buf, 0.35 + k * 0.085 + 0.06, tick() * 0.05, pan=-0.6 + k * 0.15)
    place(buf, 1.66, bell(86) * 0.16, pan=0.1)
    place(buf, 1.66, bell(74) * 0.08, pan=-0.1)
    for k, m in enumerate([66, 69, 73, 76]):
        place(buf, 2.85 + k * 0.11, pluck(m + 12, 2.2, 0.6) * 0.05, pan=-0.3 + k * 0.2)

    # The bed: pads on the progression from the end of the intro.
    start = 5.0
    t0 = start
    i = 0
    while t0 < total:
        chord = chords[i % len(chords)]
        dur = min(bar + 3.0, total - t0 + 3.0)
        for j, m in enumerate(chord[1:]):
            place(buf, t0, pad_voice(m, dur) * 0.9, pan=-0.5 + j * 0.25)
        place(buf, t0, bass_voice(chord[0], dur) * 0.7)
        # A quiet arpeggio for motion: eighth notes at 75 bpm.
        step = 60 / 75 / 2
        tones = [chord[1] + 12, chord[3] + 12, chord[2] + 12, chord[4] + 12]
        for k in range(int(bar / step)):
            at = t0 + k * step
            if at > total - 5:
                break
            vel = 0.032 if k % 4 == 0 else 0.022
            place(buf, at, pluck(tones[k % len(tones)], 1.4, 0.8) * vel, pan=(-0.35, 0.35)[k % 2])
        t0 += bar
        i += 1

    # Add the room, clear the rumble, then fade at both ends.
    buf = highpass(reverb(buf))
    fade_in, fade_out = int(0.4 * SR), int(4.5 * SR)
    buf[:, :fade_in] *= np.linspace(0, 1, fade_in)
    buf[:, -fade_out:] *= np.linspace(1, 0, fade_out) ** 1.5
    buf /= np.max(np.abs(buf)) * 1.12

    pcm = (buf.T * 32767).astype("<i2")
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())
    print(f"{path}: {total:.1f} s score")


if __name__ == "__main__":
    main()
