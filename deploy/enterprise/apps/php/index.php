<?php
// The test shop API in plain PHP (built-in server or PHP-FPM) with Ivar\Guardian.
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Ivar\Guardian;
use Ivar\Ivar;
use Ivar\VerdictCache;

$dir = getenv('IVAR_DIR');
$state = "$dir/shop-db.json";
$db = is_file($state) ? json_decode((string) file_get_contents($state), true) : null;
if (!$db) {
    $db = ['users' => [], 'sessions' => []];
    for ($i = 1; $i <= 200; $i++) {
        $db['users']["user$i@corp.test"] = ['id' => "u$i", 'password' => hash('sha256', "pw$i"), 'roles' => [$i === 1 ? 'admin' : 'customer']];
    }
}
// By reference: an arrow function would save the database as it was here.
$save = function () use (&$db, $state) { file_put_contents($state, json_encode($db), LOCK_EX); };
$reply = function (int $code, $body) {
    http_response_code($code);
    header('content-type: application/json');
    echo json_encode($body);
};

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$raw = (string) file_get_contents('php://input');
$body = json_decode($raw, true);
$headers = array_change_key_case(getallheaders(), CASE_LOWER);
$sid = $headers['x-session'] ?? '';
$user = $db['sessions'][$sid] ?? null;
// The gateway on loopback is the only trusted proxy: its X-Forwarded-For names the client.
$ip = $_SERVER['REMOTE_ADDR'];
if ($ip === '127.0.0.1' && isset($headers['x-forwarded-for'])) {
    $hops = array_map('trim', explode(',', $headers['x-forwarded-for']));
    $ip = end($hops);
}
$info = [
    'method' => $method, 'path' => $path, 'ip' => $ip, 'headers' => $headers,
    'identity' => $user['id'] ?? '', 'session' => $user ? $sid : '', 'roles' => $user['roles'] ?? [],
    'body_keys' => is_array($body) ? array_keys($body) : [],
];

$g = new Guardian([
    'mode' => getenv('IVAR_MODE') ?: 'enforce',
    'core_url' => getenv('IVAR_CORE_URL') ?: null,
    'core_token' => getenv('IVAR_CORE_TOKEN') ?: '',
    'policy' => Ivar::verifyPolicyBundle((string) file_get_contents("$dir/policy.bundle"), (string) file_get_contents("$dir/keyring.json")),
    'redaction_key' => trim((string) file_get_contents("$dir/keys/redaction.hex")),
    'sensor_id' => getenv('SENSOR_ID') ?: 'shop-php',
    // Beside the app's state, so a fresh estate starts with no verdicts.
    'verdict_cache' => new VerdictCache("$dir/verdicts.json"),
    'on_alert' => fn ($k, $m) => error_log(json_encode(['ivar_alert' => $k, 'message' => $m])),
    'control_url' => getenv('IVAR_CONTROL_URL') ?: null,
    'policy_keyring' => (string) file_get_contents("$dir/keyring.json"),
    'policy_refresh_s' => 2,
    'policy_state_file' => "$dir/policy.state",
]);

$d = $g->inspect($info);
if ($d['action'] !== 'allow') {
    $reply($d['status'], $d['body'] ?? []);
    $g->report($g->event($info, 'http.request', 4002, $d['status']));
    $g->flush();
    return;
}

$status = 200;
if ($path === '/healthz') {
    echo 'ok';
} elseif ($method === 'POST' && $path === '/login') {
    $u = $db['users'][$body['email'] ?? ''] ?? null;
    $ok = $u !== null && $u['password'] === hash('sha256', (string) ($body['password'] ?? ''));
    $g->reportLogin($info, $ok, (string) ($body['email'] ?? ''));
    if (!$ok) {
        $reply($status = 401, ['error' => 'invalid credentials']);
    } else {
        $new = 'ses_' . bin2hex(random_bytes(12));
        $db['sessions'][$new] = $u;
        $save();
        $reply(200, ['session' => $new]);
    }
} elseif ($user === null) {
    $reply($status = 401, ['error' => 'login required']);
} elseif ($method === 'GET' && str_starts_with($path, '/accounts/')) {
    substr($path, 10) === $user['id'] ? $reply(200, ['id' => $user['id'], 'balance' => 100000]) : $reply($status = 403, ['error' => 'not your account']);
} elseif ($method === 'PATCH' && str_starts_with($path, '/users/')) {
    if (!empty($body['role'])) {
        $db['sessions'][$sid]['roles'][] = $body['role'];
        $save();
    }
    $reply(200, ['id' => $user['id'], 'roles' => $db['sessions'][$sid]['roles']]);
} elseif ($method === 'POST' && $path === '/payouts/intent') {
    $rootSeed = getenv('IVAR_ROOT_SEED');
    $rootPub = Ivar::mintIntent($rootSeed, 'boot', 'payout', 'boot', ['amount' => 1])['root_public_key'];
    $t = Ivar::mintIntent($rootSeed, 'int_' . bin2hex(random_bytes(6)), 'payout', $sid, ['amount' => (int) ($body['amount'] ?? 0)])['token'];
    foreach (['authenticated_session' => 'IVAR_STEP_SESSION', 'ledger_entry' => 'IVAR_STEP_LEDGER', 'payout_instruction' => 'IVAR_STEP_PAYOUT'] as $step => $var) {
        $t = Ivar::attestStep(getenv($var), $step, $t, $rootPub);
    }
    $reply(200, ['intent' => $t, 'header' => 'Ivar-Intent']);
} elseif ($method === 'POST' && $path === '/payouts') {
    $rootSeed = getenv('IVAR_ROOT_SEED');
    $rootPub = Ivar::mintIntent($rootSeed, 'boot', 'payout', 'boot', ['amount' => 1])['root_public_key'];
    $stepKeys = [];
    foreach (['authenticated_session' => 'IVAR_STEP_SESSION', 'ledger_entry' => 'IVAR_STEP_LEDGER', 'payout_instruction' => 'IVAR_STEP_PAYOUT'] as $step => $var) {
        $stepKeys[$step] = Ivar::stepPublicKey(getenv($var));
    }
    $c = $g->guard('payout', $rootPub, $stepKeys)->check($info, $headers['ivar-intent'] ?? null, (float) ($body['amount'] ?? 0));
    $c['action'] === 'allow' ? $reply(200, ['sent' => true]) : $reply($status = $c['status'], $c['body'] ?? []);
} elseif ($method === 'GET' && $path === '/admin/users') {
    in_array('admin', $user['roles'], true) ? $reply(200, ['users' => count($db['users'])]) : $reply($status = 403, ['error' => 'admins only']);
} else {
    $reply($status = 404, ['error' => 'not found']);
}
$g->report($g->event($info, 'http.request', 4002, $status));
$g->flush();
