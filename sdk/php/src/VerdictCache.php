<?php

declare(strict_types=1);

namespace Ivar;

/**
 * PHP workers do not share memory, so verdicts from the core are kept in
 * APCu when it is available, or in a small file, and loaded into the local
 * sensor on each request.
 */
final class VerdictCache
{
    public function __construct(private string $file = '')
    {
        $this->file = $file ?: sys_get_temp_dir() . '/ivar-verdicts.json';
    }

    /** @return list<array> */
    public function all(): array
    {
        $now = Ivar::now();
        $list = function_exists('apcu_fetch') ? (apcu_fetch('ivar_verdicts') ?: []) : (is_file($this->file) ? (json_decode((string) file_get_contents($this->file), true) ?: []) : []);
        return array_values(array_filter($list, fn ($v) => ($v['expires_at'] ?? 0) === 0 || $v['expires_at'] > $now));
    }

    /** @param list<array> $verdicts */
    public function add(array $verdicts): void
    {
        if ($verdicts === []) {
            return;
        }
        $merged = array_slice(array_merge($this->all(), $verdicts), -5000);
        if (function_exists('apcu_store')) {
            apcu_store('ivar_verdicts', $merged);
            return;
        }
        $tmp = $this->file . '.' . getmypid();
        file_put_contents($tmp, json_encode($merged));
        rename($tmp, $this->file);
    }
}
