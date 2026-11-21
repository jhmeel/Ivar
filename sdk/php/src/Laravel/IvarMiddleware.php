<?php

declare(strict_types=1);

namespace Ivar\Laravel;

use Closure;
use Ivar\Guardian;

/**
 * Laravel middleware. Register it in bootstrap/app.php:
 *
 *     $middleware->append(\Ivar\Laravel\IvarMiddleware::class);
 *
 * and bind a Guardian in a service provider:
 *
 *     $this->app->singleton(Guardian::class, fn () => new Guardian(['mode' => 'observe', 'core_url' => env('IVAR_CORE_URL')]));
 *
 * Events are sent in terminate(), after the response has gone to the client.
 */
final class IvarMiddleware
{
    public function __construct(private Guardian $guardian)
    {
    }

    /** Request info from an Illuminate request. */
    public static function info($request): array
    {
        $user = method_exists($request, 'user') ? $request->user() : null;
        return [
            'method' => $request->method(),
            'path' => '/' . ltrim($request->path(), '/'),
            'ip' => (string) $request->ip(),
            'headers' => array_map(fn ($v) => is_array($v) ? (string) ($v[0] ?? '') : (string) $v, array_change_key_case($request->headers->all(), CASE_LOWER)),
            'identity' => $user ? (string) $user->getAuthIdentifier() : '',
            'session' => method_exists($request, 'hasSession') && $request->hasSession() ? (string) $request->session()->getId() : '',
            'body_keys' => array_keys((array) $request->json()->all()),
        ];
    }

    public function handle($request, Closure $next)
    {
        $info = self::info($request);
        $d = $this->guardian->inspect($info);
        if ($d['action'] !== 'allow') {
            $this->guardian->report($this->guardian->event($info, 'http.request', 4002, $d['status']));
            $headers = $d['action'] === 'challenge' ? ['WWW-Authenticate' => 'step-up'] : [];
            return response()->json($d['body'] ?? [], $d['status'], $headers);
        }
        $response = $next($request);
        $this->guardian->report($this->guardian->event($info, 'http.request', 4002, (int) $response->getStatusCode()));
        return $response;
    }

    public function terminate($request, $response): void
    {
        $this->guardian->flush();
    }
}
