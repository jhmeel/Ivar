<?php

declare(strict_types=1);

namespace Ivar;

/**
 * Framework independent SDK logic. Observe mode records decisions without
 * affecting a request; enforce mode blocks known attacks from cached, signed
 * policy and applies core verdicts. A fault fails open on public routes and
 * closed on admin routes. Events go to the core after the response.
 */
final class Guardian
{
    public const INTENT_HEADER = 'Ivar-Intent';

    private Handle $sensor;
    private ?Handle $core = null;
    private string $policy;
    private object $policyView;
    private array $pending = [];
    private static int $seq = 0;

    /**
     * @param array{mode?:string, core_url?:?string, core_token?:string, policy?:?string, redaction_key?:string, sensor_id?:string, admin_prefixes?:list<string>, budget_ms?:float, on_alert?:?callable, verdict_cache?:?VerdictCache, embedded?:bool, control_url?:?string, policy_keyring?:?string, policy_refresh_s?:int, policy_state_file?:?string} $options
     *
     * With control_url, policy_keyring and policy_state_file, newer signed
     * policy from the control plane is fetched at most once per
     * policy_refresh_s across every PHP worker, verified, saved to the state
     * file, and used from the next request on.
     */
    public function __construct(private array $options = [])
    {
        $this->options += ['mode' => 'observe', 'core_url' => null, 'core_token' => '', 'policy' => null, 'redaction_key' => '', 'sensor_id' => 'php-sdk', 'admin_prefixes' => ['/admin'], 'budget_ms' => 1.0, 'on_alert' => null, 'verdict_cache' => null, 'embedded' => false, 'control_url' => null, 'policy_keyring' => null, 'policy_refresh_s' => 30, 'policy_state_file' => null];
        if (!in_array($this->options['mode'], ['observe', 'enforce'], true)) {
            throw new \InvalidArgumentException('mode must be observe or enforce');
        }
        $this->policy = $this->resolvePolicy($this->options['policy'] ?? Ivar::defaultPolicy());
        $this->policyView = json_decode($this->policy, false, 512, JSON_THROW_ON_ERROR);
        $this->sensor = Ivar::sensor($this->policy);
        if ($this->options['embedded'] || $this->options['core_url'] === null) {
            $this->core = Ivar::core($this->policy, $this->options['redaction_key'] ?: '00');
        }
        $this->options['verdict_cache'] ??= new VerdictCache();
        foreach ($this->options['verdict_cache']->all() as $v) {
            $this->sensor->pushVerdict(['verdict' => $v]);
        }
    }

    /** The verified PolicyContent in force, as JSON. */
    public function policy(): string
    {
        return $this->policy;
    }

    private static function versionOf(string $policy): int
    {
        return (int) (json_decode($policy, true)['version'] ?? 0);
    }

    /**
     * The newest verified policy among the configured one, the state file and,
     * when due, the control plane. Anything that fails verification is
     * refused with an alert and the policy in hand is kept.
     */
    private function resolvePolicy(string $policy): string
    {
        $o = $this->options;
        if ($o['control_url'] === null && $o['policy_state_file'] === null) {
            return $policy;
        }
        if ($o['policy_keyring'] === null) {
            throw new \InvalidArgumentException('policy_keyring is required with control_url or policy_state_file');
        }
        $state = $o['policy_state_file'];
        if ($state !== null && is_readable($state) && ($saved = trim((string) file_get_contents($state))) !== '') {
            $policy = $this->adopt($policy, $saved, 'state_file', false);
        }
        if ($o['control_url'] !== null) {
            // One worker fetches per period; the rest read the state file.
            $stamp = ($state ?? sys_get_temp_dir() . '/ivar-policy-' . md5($o['control_url'])) . '.checked';
            $last = @filemtime($stamp);
            if ($last === false || time() - $last >= $o['policy_refresh_s']) {
                @touch($stamp);
                $url = rtrim($o['control_url'], '/') . '/v1/policy/bundle?' . http_build_query(['have' => self::versionOf($policy), 'sensor' => $o['sensor_id']]);
                $ctx = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);
                $body = @file_get_contents($url, false, $ctx);
                $status = isset($http_response_header[0]) && preg_match('#^HTTP/\S+ (\d{3})#', $http_response_header[0], $m) ? (int) $m[1] : 0;
                if ($body !== false && $status === 200) {
                    $policy = $this->adopt($policy, $body, 'control_plane', true);
                }
            }
        }
        return $policy;
    }

    private function adopt(string $current, string $archive, string $source, bool $save): string
    {
        $have = self::versionOf($current);
        try {
            $next = Ivar::verifyPolicyBundle(trim($archive), $this->options['policy_keyring'], $have);
        } catch (IvarException $e) {
            $this->alert('policy_rejected', "signed policy from $source refused, current policy kept: " . $e->getMessage());
            return $current;
        }
        $version = self::versionOf($next);
        if ($version <= $have) {
            return $current;
        }
        $state = $this->options['policy_state_file'];
        if ($save && $state !== null) {
            $tmp = $state . '.' . getmypid() . '.tmp';
            if (@file_put_contents($tmp, trim($archive)) === false || !@rename($tmp, $state)) {
                $this->alert('policy_state', "policy $version applied but not saved");
            }
        }
        if ($source === 'control_plane') {
            $this->alert('policy_applied', "policy $version applied from $source");
        }
        return $next;
    }

    public function mode(): string
    {
        return $this->options['mode'];
    }

    private function alert(string $kind, string $message): void
    {
        $cb = $this->options['on_alert'];
        $cb ? $cb($kind, $message) : error_log("ivar $kind: $message");
    }

    /** @param array{method:string,path:string,ip:string,headers:array<string,string>,identity?:string,session?:string,roles?:list<string>,tenant?:string,body_keys?:list<string>} $r */
    public function event(array $r, string $activity, int $classUid, int $status = 0, array $ext = []): array
    {
        $key = $this->options['redaction_key'];
        $actor = ['authorizations' => implode(',', $r['roles'] ?? [])];
        if (($r['identity'] ?? '') !== '') {
            $actor['user'] = ['uid' => Ivar::keyedHash($key, $r['identity']), 'type' => 'human'];
        }
        if (($r['session'] ?? '') !== '') {
            $actor['session'] = ['uid' => $r['session']];
        }
        $ev = [
            'class_uid' => $classUid, 'category_uid' => intdiv($classUid, 1000), 'activity_id' => 1, 'time' => Ivar::now(), 'status_id' => 1, 'activity_name' => $activity,
            'metadata' => ['version' => '1.3.0', 'extensions' => [['name' => 'ivar', 'uid' => '999', 'version' => '1.0.0']]],
            'actor' => $actor,
            'src_endpoint' => ['ip' => $r['ip']],
            'http_request' => ['http_method' => $r['method'], 'url_path' => $r['path'], 'user_agent' => substr($r['headers']['user-agent'] ?? '', 0, 256), 'body_keys' => array_slice($r['body_keys'] ?? [], 0, 64)],
            'ivar' => ['sensor_id' => $this->options['sensor_id'], 'sensor_type' => 'app_sdk', 'observation_point' => 'app_sdk', 'sensor_seq' => ++self::$seq, 'request_id' => $r['headers']['x-request-id'] ?? '', 'tenant' => $r['tenant'] ?? ''] + $ext,
        ];
        if ($status !== 0) {
            $ev['http_response'] = ['code' => $status];
        }
        return $ev;
    }

    /** @return array{action:string,status:int,body?:array} */
    public function inspect(array $r): array
    {
        $admin = false;
        foreach ($this->options['admin_prefixes'] as $p) {
            $admin = $admin || str_starts_with($r['path'], $p);
        }
        $started = hrtime(true);
        try {
            $local = $this->sensor->decide(['event' => $this->event($r, 'http.request', 4002), 'now_ms' => Ivar::now()]);
        } catch (\Throwable $e) {
            if ($admin) {
                $this->alert('sdk_fault', 'admin route failed closed: ' . $e->getMessage());
                return ['action' => 'unavailable', 'status' => 503, 'body' => ['error' => 'security check unavailable']];
            }
            $this->alert('fail_open', $e->getMessage());
            return ['action' => 'allow', 'status' => 200];
        }
        $ms = (hrtime(true) - $started) / 1e6;
        if ($ms > $this->options['budget_ms']) {
            $this->alert('budget_exceeded', sprintf('local decision took %.3f ms', $ms));
        }
        $v = $local['verdict'] ?? null;
        if ($v === null || $this->options['mode'] !== 'enforce' || ($v['mode'] ?? '') !== 'enforce') {
            return ['action' => 'allow', 'status' => 200];
        }
        return match ($v['decision']) {
            'block', 'contain', 'refuse' => ['action' => 'block', 'status' => 403, 'body' => ['error' => 'request blocked', 'verdict_id' => $v['verdict_id']]],
            'challenge' => ['action' => 'challenge', 'status' => 401, 'body' => ['error' => 'step up verification required', 'verdict_id' => $v['verdict_id']]],
            'throttle' => ['action' => 'throttle', 'status' => 429, 'body' => ['error' => 'slow down', 'verdict_id' => $v['verdict_id']]],
            default => ['action' => 'allow', 'status' => 200],
        };
    }

    public function report(array $event): void
    {
        $this->pending[] = $event;
    }

    /** Report a login so credential spraying and account takeover are correlated. */
    public function reportLogin(array $r, bool $success, string $account): void
    {
        $ev = $this->event($r, 'auth.login', 3002, 0, ['target_entity' => 'user:' . Ivar::keyedHash($this->options['redaction_key'], $account)]);
        $ev['status_id'] = $success ? 1 : 2;
        $this->report($ev);
    }

    /** Report a business action such as a payout, a role change or an export. */
    public function reportAction(array $r, string $name, float $value = 0, int $records = 0, bool $destructive = false): void
    {
        $this->report($this->event($r, 'business.action', 6003, 0, ['business_action' => $name, 'value_moved' => $value, 'records_read' => $records, 'destructive' => $destructive]));
    }

    /** Send pending events. Call after the response is sent (terminate middleware). */
    public function flush(): void
    {
        $events = $this->pending;
        $this->pending = [];
        $verdicts = [];
        try {
            if ($this->core !== null) {
                foreach ($events as $ev) {
                    $out = $this->core->process(['event' => $ev, 'now_ms' => Ivar::now()]);
                    $verdicts = array_merge($verdicts, $out['verdicts'] ?? []);
                }
            } elseif ($events !== []) {
                $headers = "content-type: application/json\r\n";
                if (($this->options['core_token'] ?? '') !== '') {
                    $headers .= 'authorization: Bearer ' . $this->options['core_token'] . "\r\n";
                }
                $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => $headers, 'content' => json_encode(['sensor_id' => $this->options['sensor_id'], 'events' => $events]), 'timeout' => 2, 'ignore_errors' => true]]);
                $body = @file_get_contents(rtrim($this->options['core_url'], '/') . '/v1/events', false, $ctx);
                $status = isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m) ? (int) $m[1] : 0;
                if ($body === false || $status === 0) {
                    $this->alert('sdk_fault', 'the core is unreachable, events are not scored until it returns');
                } elseif ($status === 401 || $status === 403) {
                    $this->alert('sdk_fault', "the core refused this sensor's token (HTTP $status): check core_token and the sensor id it is issued for");
                } elseif ($status !== 200) {
                    $this->alert('sdk_fault', "the core answered HTTP $status");
                } else {
                    $verdicts = json_decode($body, true)['verdicts'] ?? [];
                }
            }
        } catch (\Throwable $e) {
            $this->alert('sdk_fault', $e->getMessage());
        }
        foreach ($verdicts as $v) {
            $this->sensor->pushVerdict(['verdict' => $v]);
        }
        $this->options['verdict_cache']->add($verdicts);
    }

    /** Action sink for one high consequence action. Fails closed. */
    public function guard(string $action, string $rootPublicKey, array $stepKeys, ?string $intentBinding = null): ActionGuard
    {
        $modes = (array) ($this->policyView->intent_binding ?? []);
        if ($intentBinding !== null) {
            $modes[$action] = $intentBinding;
        }
        $invariants = json_encode($this->policyView->invariants ?? [], JSON_THROW_ON_ERROR);
        return new ActionGuard($this, $action, Ivar::sink($rootPublicKey, $stepKeys, $invariants, $modes[$action] ?? 'observe', $modes), fn ($k, $m) => $this->alert($k, $m));
    }
}
