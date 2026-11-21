<?php

declare(strict_types=1);

namespace Ivar;

/** The decision core, local sensor, action sink and intent tokens. */
final class Ivar
{
    public static function now(): int
    {
        return (int) floor(microtime(true) * 1000);
    }

    /** The spec default PolicyContent, as JSON text. */
    public static function defaultPolicy(?Runtime $rt = null): string
    {
        return ($rt ?? Runtime::shared())->callRaw('policy.default', ['now_ms' => self::now()]);
    }

    /** Verified PolicyContent as JSON text; rollback and expired bundles are refused. */
    public static function verifyPolicyBundle(string $archiveBase64, string $keyringJson, int $currentVersion = 0, ?Runtime $rt = null): string
    {
        $rt ??= Runtime::shared();
        $raw = $rt->callRaw('policy.verify', ['archive_base64' => $archiveBase64, 'keyring' => $keyringJson, 'current_version' => $currentVersion, 'now_ms' => self::now()]);
        $v = json_decode($raw, true);
        if (is_array($v) && isset($v['error']) && count($v) === 1) {
            throw new IvarException($v['error']);
        }
        return $raw;
    }

    /** @param string $policy PolicyContent JSON text */
    public static function core(string $policy, string $redactionKeyHex = '00', ?Runtime $rt = null): Handle
    {
        return new Handle($rt ?? Runtime::shared(), 'core', ['policy' => $policy, 'redaction_key_hex' => $redactionKeyHex]);
    }

    /** @param string $policy PolicyContent JSON text */
    public static function sensor(string $policy, ?Runtime $rt = null): Handle
    {
        return new Handle($rt ?? Runtime::shared(), 'sensor', ['policy' => $policy]);
    }

    /** @param string $invariants JSON text of the invariants list */
    public static function sink(string $rootPublicKey, array $stepKeys, string $invariants, string $defaultMode = 'observe', array $modes = [], ?Runtime $rt = null): Handle
    {
        return new Handle($rt ?? Runtime::shared(), 'sink', ['root_public_key' => $rootPublicKey, 'step_keys' => (object) $stepKeys, 'invariants' => $invariants, 'default_mode' => $defaultMode, 'modes' => (object) $modes]);
    }

    public static function mintIntent(string $rootSeedHex, string $intentId, string $action, string $subject, array $limits, int $ttlMs = 300000, ?Runtime $rt = null): array
    {
        return ($rt ?? Runtime::shared())->call('intent.mint', ['root_seed_hex' => $rootSeedHex, 'intent_id' => $intentId, 'action' => $action, 'subject' => $subject, 'limits' => (object) $limits, 'expiry_ms' => self::now() + $ttlMs]);
    }

    public static function attestStep(string $stepSeedHex, string $step, string $token, string $rootPublicKey, ?Runtime $rt = null): string
    {
        return ($rt ?? Runtime::shared())->call('intent.attest', ['step_seed_hex' => $stepSeedHex, 'step' => $step, 'token' => $token, 'root_public_key' => $rootPublicKey, 'narrowing' => (object) []])['token'];
    }

    public static function stepPublicKey(string $stepSeedHex, ?Runtime $rt = null): string
    {
        return ($rt ?? Runtime::shared())->call('intent.step_public_key', ['step_seed_hex' => $stepSeedHex])['public_key'];
    }

    /** Matches ivar_core::redact::keyed_hash. */
    public static function keyedHash(string $keyHex, string $value): string
    {
        if ($value === '' || str_starts_with($value, 'kh_') || $keyHex === '') {
            return $value;
        }
        return 'kh_' . substr(hash_hmac('sha256', $value, hex2bin($keyHex)), 0, 24);
    }
}
