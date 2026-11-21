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
     * @param array{mode?:string, core_url?:?string, policy?:?string, redaction_key?:string, sensor_id?:string, admin_prefixes?:list<string>, budget_ms?:float, on_alert?:?callable, verdict_cache?:?VerdictCache, embedded?:bool} $options
     */
    public function __construct(private array $options = [])
    {
        $this->options += ['mode' => 'observe', 'core_url' => null, 'policy' => null, 'redaction_key' => '', 'sensor_id' => 'php-sdk', 'admin_prefixes' => ['/admin'], 'budget_ms' => 1.0, 'on_alert' => null, 'verdict_cache' => null, 'embedded' => false];
        if (!in_array($this->options['mode'], ['observe', 'enforce'], true)) {
            throw new \InvalidArgumentException('mode must be observe or enforce');
        }
        $this->policy = $this->options['policy'] ?? Ivar::defaultPolicy();
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
                $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => "content-type: application/json\r\n", 'content' => json_encode(['sensor_id' => $this->options['sensor_id'], 'events' => $events]), 'timeout' => 2]]);
                $ack = json_decode((string) @file_get_contents(rtrim($this->options['core_url'], '/') . '/v1/events', false, $ctx), true);
                $verdicts = $ack['verdicts'] ?? [];
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
