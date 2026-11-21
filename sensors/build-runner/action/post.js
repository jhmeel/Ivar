// After the job: verify installed packages against their pins when a lockfile exists.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const bin = process.env.IVAR_BUILD_RUNNER_BIN || `${__dirname}/bin/ivar-build-runner`;
const cfg = `${process.env.RUNNER_TEMP}/ivar-sensor.yaml`;
if (fs.existsSync('package-lock.json') && fs.existsSync('node_modules/.package-lock.json')) {
  execFileSync(bin, ['verify-packages', '--config', cfg], { stdio: 'inherit' });
}
