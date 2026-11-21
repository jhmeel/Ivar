// Starts the IVAR build runner sensor before the job's steps run.
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');

const input = (n, d = '') => process.env[`INPUT_${n.replace(/ /g, '_').replace(/-/g, '_').toUpperCase()}`] || d;
const bin = process.env.IVAR_BUILD_RUNNER_BIN || `${__dirname}/bin/ivar-build-runner`;
const cfg = `${process.env.RUNNER_TEMP}/ivar-sensor.yaml`;
fs.writeFileSync(cfg, `sensor_id: ${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_JOB}\nmode: ${input('mode', 'observe')}\ncore_url: ${input('core-url')}\nstate_dir: ${process.env.RUNNER_TEMP}/ivar\n`);
const child = spawn('sudo', ['-n', bin, 'start', '--config', cfg, '--allow', input('allowed-endpoints')], { detached: true, stdio: 'ignore' });
child.unref();
fs.writeFileSync(`${process.env.RUNNER_TEMP}/ivar.pid`, String(child.pid));
try {
  execFileSync('sleep', ['1']);
} catch {}
console.log(`IVAR build runner sensor started in ${input('mode', 'observe')} mode`);
