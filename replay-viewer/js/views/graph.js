// Graph: the trust graph, estate map, pipeline latency and timeline of the
// replay, at the playhead.

import { renderTimeline } from '../panes/timeline.js';
import { renderEstate } from '../panes/estate.js';
import { renderPipeline } from '../panes/pipeline.js';
import { renderTrust } from '../panes/trust.js';
import { renderRisk } from '../panes/risk.js';

export function renderGraph(el, ctx) {
  const b = ctx.model.bundle;
  if (!b.frames.length) {
    el.innerHTML = '<div class="pane empty">No frames yet.</div>';
    return;
  }
  const i = Math.max(0, Math.min(ctx.cursor, b.frames.length - 1));
  el.innerHTML = `
    <section class="pane"><header><h2>Timeline</h2><span class="pane-note">corrected clock, skew shown · click a marker</span></header><div id="g-timeline"></div></section>
    <div class="grid-2">
      <section class="pane"><header><h2>Trust graph</h2><span class="pane-note">edges seen up to the playhead</span></header><div id="g-trust"></div></section>
      <section class="pane risk"><header><h2>Risk</h2><span class="pane-note">two timescales, policy bands</span></header><div id="g-risk"></div></section>
      <section class="pane"><header><h2>Estate</h2><span class="pane-note">sensors by layer</span></header><div id="g-estate"></div></section>
      <section class="pane"><header><h2>Pipeline</h2><span class="pane-note">per hop latency of the frame at the playhead</span></header><div id="g-pipeline"></div></section>
    </div>`;
  renderTimeline(el.querySelector('#g-timeline'), b, i, (k) => ctx.seek(k, true));
  renderTrust(el.querySelector('#g-trust'), b, i);
  renderRisk(el.querySelector('#g-risk'), b, i);
  renderEstate(el.querySelector('#g-estate'), b, i);
  renderPipeline(el.querySelector('#g-pipeline'), b, i);
}
