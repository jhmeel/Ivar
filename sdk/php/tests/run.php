<?php

declare(strict_types=1);

// Plain PHP tests (no framework needed): php tests/run.php

spl_autoload_register(function (string $c) {
    $f = __DIR__ . '/../src/' . str_replace(['Ivar\\', '\\'], ['', '/'], $c) . '.php';
    if (is_file($f)) require $f;
});

use Ivar\Guardian;
use Ivar\Ivar;
use Ivar\VerdictCache;

$failures = 0;
function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? 'PASS ' : 'FAIL ') . $name . PHP_EOL;
    $failures += $ok ? 0 : 1;
}

$req = fn (string $path, string $ip, array $h = []) => ['method' => 'GET', 'path' => $path, 'ip' => $ip, 'headers' => $h, 'identity' => 'svc', 'session' => 'ses_1'];
$quiet = fn () => null;
$cache = fn () => new VerdictCache(sys_get_temp_dir() . '/ivar-test-' . uniqid() . '.json');

$g = new Guardian(['mode' => 'observe', 'on_alert' => $quiet, 'verdict_cache' => $cache()]);
check('observe never affects requests', $g->inspect($req('/.env.backup', '203.0.113.4'))['status'] === 200);

// The spec default policy with DETECTION_MODE enforce. Decoded as objects so
// empty maps stay {} when re-encoded.
$enforce = (function (): string {
    $p = json_decode(Ivar::defaultPolicy());
    $p->settings->detection_mode = 'enforce';
    return json_encode($p);
})();

$g = new Guardian(['mode' => 'enforce', 'on_alert' => $quiet, 'verdict_cache' => $cache()]);
check('a signed observe policy never blocks, even in enforce', $g->inspect($req('/.env.backup', '203.0.113.9'))['status'] === 200);

$vc = $cache();
$g = new Guardian(['mode' => 'enforce', 'policy' => $enforce, 'on_alert' => $quiet, 'verdict_cache' => $vc]);
$d = $g->inspect($req('/.env.backup', '203.0.113.5'));
$g->report($g->event($req('/.env.backup', '203.0.113.5'), 'http.request', 4002, 404));
$g->flush();
check('enforce blocks a decoy route', $d['status'] === 403);
check('the source is contained by the core verdict', $g->inspect($req('/hello', '203.0.113.5'))['status'] === 403);
$next = new Guardian(['mode' => 'enforce', 'policy' => $enforce, 'on_alert' => $quiet, 'verdict_cache' => $vc]);
check('verdicts survive into the next PHP worker', $next->inspect($req('/hello', '203.0.113.5'))['status'] === 403);
check('other sources are unaffected', $next->inspect(['identity' => 'someone-else', 'session' => 'ses_2'] + $req('/hello', '198.51.100.3'))['status'] === 200);

$steps = ['authenticated_session' => str_repeat('22', 32), 'ledger_entry' => str_repeat('33', 32), 'payout_instruction' => str_repeat('44', 32)];
$keys = array_map(fn ($s) => Ivar::stepPublicKey($s), $steps);
$chain = function (string $id, int $limit) use ($steps): array {
    $m = Ivar::mintIntent(str_repeat('11', 32), $id, 'payout', 'ses_1', ['amount' => $limit]);
    $t = $m['token'];
    foreach ($steps as $step => $seed) $t = Ivar::attestStep($seed, $step, $t, $m['root_public_key']);
    return [$t, $m['root_public_key']];
};
[$t1, $root] = $chain('i1', 5000);
$guard = $g->guard('payout', $root, $keys, 'enforce');
check('stolen credential without a chain is refused', $guard->check($req('/payouts', '10.0.0.1'), null, 100)['status'] === 403);
check('full chain executes', $guard->check($req('/payouts', '10.0.0.1'), $t1, 100)['status'] === 200);
check('large payout is held', $guard->check($req('/payouts', '10.0.0.1'), $chain('i2', 100000)[0], 60000)['status'] === 202);

$times = [];
for ($i = 0; $i < 500; $i++) {
    $s = hrtime(true);
    $g->inspect($req('/x', '203.0.113.9'));
    $times[] = (hrtime(true) - $s) / 1e6;
}
sort($times);
printf("php local decision p99 %.3f ms\n", $times[495]);
check('latency', $times[495] < 5);

// Live policy: a newer signed bundle from the control plane is used from the
// next request on; a forged one is refused; the saved policy survives.
(function () use ($req) {
    $data = __DIR__ . '/../../testdata/policy';
    $keyring = file_get_contents("$data/keyring.json");
    $v1 = Ivar::verifyPolicyBundle(trim(file_get_contents("$data/v1.bundle")), $keyring);
    $dir = sys_get_temp_dir() . '/ivar-cp-' . uniqid();
    mkdir($dir);
    file_put_contents("$dir/serve", "$data/v2.bundle");
    file_put_contents("$dir/router.php", '<?php readfile(trim(file_get_contents(__DIR__ . "/serve")));');
    $port = 20000 + random_int(0, 20000);
    $server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", "$dir/router.php"], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) usleep(100000);
    $alerts = new ArrayObject();
    $opts = fn (array $extra = []) => $extra + ['mode' => 'enforce', 'policy' => $v1, 'policy_keyring' => $keyring, 'policy_state_file' => "$dir/policy.state", 'policy_refresh_s' => 0, 'on_alert' => function ($k) use ($alerts) { $alerts[] = $k; }];
    $decoy = fn (Guardian $g) => $g->inspect($req('/v2-decoy', '198.51.100.4'))['status'];
    check('policy: v1 has no such decoy', $decoy(new Guardian(['mode' => 'enforce', 'policy' => $v1, 'on_alert' => fn () => null])) !== 403);
    $g = new Guardian($opts(['control_url' => "http://127.0.0.1:$port"]));
    check('policy: a newer signed policy from the control plane is used', json_decode($g->policy(), true)['version'] === 2 && $decoy($g) === 403);
    file_put_contents("$dir/serve", "$data/forged-v3.bundle");
    $g = new Guardian($opts(['control_url' => "http://127.0.0.1:$port"]));
    check('policy: a forged bundle is refused and the saved policy kept', json_decode($g->policy(), true)['version'] === 2 && in_array('policy_rejected', $alerts->getArrayCopy(), true));
    $g = new Guardian($opts());
    check('policy: the saved policy is used without the control plane', json_decode($g->policy(), true)['version'] === 2);
    proc_terminate($server);
})();

exit($failures === 0 ? 0 : 1);
