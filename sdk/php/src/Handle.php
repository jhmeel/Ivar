<?php

declare(strict_types=1);

namespace Ivar;

/** An object inside the core: a decision core, a local sensor or a sink. */
final class Handle
{
    private int $handle;

    public function __construct(private Runtime $rt, private string $kind, array $args)
    {
        $this->handle = (int) $rt->call("$kind.new", $args)['handle'];
    }

    public function __call(string $name, array $args): mixed
    {
        $op = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $name));
        return $this->rt->call("{$this->kind}.$op", $args[0] ?? [], $this->handle);
    }

    public function close(): void
    {
        $this->rt->call('free', [], $this->handle);
    }
}
