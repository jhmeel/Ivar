<?php

declare(strict_types=1);

namespace Ivar;

/** Guards one high consequence action: intent binding, invariants, time locks. */
final class ActionGuard
{
    /** @param \Closure(string,string):void $alert */
    public function __construct(private Guardian $g, private string $action, private Handle $sink, private \Closure $alert)
    {
    }

    /** @return array{action:string,status:int,body?:array} */
    public function check(array $r, ?string $intentToken, float $value = 0, float $records = 0, bool $destructive = false): array
    {
        $req = [
            'action' => $this->action, 'subject' => ($r['session'] ?? '') !== '' ? $r['session'] : ($r['identity'] ?? ''), 'identity' => $r['identity'] ?? '',
            'business' => $r['tenant'] ?? '', 'value_moved' => $value, 'records_read' => $records, 'destructive' => $destructive, 'intent_token' => $intentToken,
        ];
        try {
            $d = $this->sink->guard(['request' => $req, 'now_ms' => Ivar::now()]);
        } catch (\Throwable $e) {
            ($this->alert)('sdk_fault', 'action sink failed closed: ' . $e->getMessage());
            return ['action' => 'unavailable', 'status' => 503, 'body' => ['error' => 'action check unavailable']];
        }
        $o = $d['outcome'];
        $this->g->report($this->g->event($r, 'business.action', 6003, 0, ['business_action' => $this->action, 'value_moved' => $value, 'attributes' => ['sink_outcome' => $o['outcome']]]));
        switch ($o['outcome']) {
            case 'executes':
                if (!empty($d['would_refuse'])) {
                    ($this->alert)('action_refused', "observe: would refuse {$this->action}: {$d['would_refuse']}");
                }
                return ['action' => 'allow', 'status' => 200];
            case 'refused':
                ($this->alert)('action_refused', $o['reason']);
                return ['action' => 'block', 'status' => 403, 'body' => ['error' => 'no valid intent chain for this action']];
            case 'blocked_alert':
                ($this->alert)('invariant_breach', $o['invariant_id']);
                return ['action' => 'block', 'status' => 409, 'body' => ['error' => 'consequence limit reached', 'invariant' => $o['invariant_id']]];
            default:
                ($this->alert)('time_lock', $o['lock']['lock_id']);
                return ['action' => 'held', 'status' => 202, 'body' => ['status' => 'held', 'lock_id' => $o['lock']['lock_id'], 'release_at' => $o['lock']['release_at']]];
        }
    }
}
