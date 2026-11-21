<?php

declare(strict_types=1);

namespace Ivar;

use FFI;
use RuntimeException;

/**
 * One instance of the verified decision core, run by the wasmtime C API
 * through PHP FFI. The compiled module is cached on disk, so a request only
 * pays for instantiation.
 */
final class Runtime
{
    private const CDEF = <<<'C'
typedef struct wasm_engine_t wasm_engine_t;
typedef struct wasmtime_store wasmtime_store_t;
typedef struct wasmtime_context wasmtime_context_t;
typedef struct wasmtime_module wasmtime_module_t;
typedef struct wasmtime_linker wasmtime_linker_t;
typedef struct wasmtime_error wasmtime_error_t;
typedef struct wasm_trap_t wasm_trap_t;
typedef struct wasi_config_t wasi_config_t;
typedef struct { size_t size; uint8_t *data; } wasm_byte_vec_t;
typedef struct { uint64_t store_id; void *p; } wasmtime_func_t;
typedef struct { uint64_t store_id; uint32_t p1; } wasmtime_anon_t;
typedef struct { wasmtime_anon_t a; uint32_t p2; } wasmtime_memory_t;
typedef struct { wasmtime_anon_t a; uint32_t p2; } wasmtime_table_t;
typedef struct { uint64_t store_id; uint32_t p1; uint32_t p2; uint32_t p3; } wasmtime_global_t;
typedef union { wasmtime_func_t func; wasmtime_global_t global_; wasmtime_table_t table; wasmtime_memory_t memory; void *sharedmemory; } wasmtime_extern_union_t;
typedef struct { uint8_t kind; wasmtime_extern_union_t of; } wasmtime_extern_t;
typedef struct { uint64_t store_id; uint32_t p1; uint32_t p2; } wasmtime_anyref_t;
typedef union { int32_t i32; int64_t i64; float f32; double f64; wasmtime_anyref_t anyref; wasmtime_anyref_t externref; wasmtime_func_t funcref; uint8_t v128[16]; } wasmtime_valunion_t;
typedef struct { uint8_t kind; wasmtime_valunion_t of; } wasmtime_val_t;
typedef struct { uint64_t store_id; size_t p; } wasmtime_instance_t;
wasm_engine_t *wasm_engine_new(void);
wasmtime_store_t *wasmtime_store_new(wasm_engine_t *engine, void *data, void *finalizer);
wasmtime_context_t *wasmtime_store_context(wasmtime_store_t *store);
wasmtime_error_t *wasmtime_module_new(wasm_engine_t *engine, const uint8_t *wasm, size_t len, wasmtime_module_t **ret);
wasmtime_error_t *wasmtime_module_serialize(wasmtime_module_t *module, wasm_byte_vec_t *ret);
wasmtime_error_t *wasmtime_module_deserialize_file(wasm_engine_t *engine, const char *path, wasmtime_module_t **ret);
wasmtime_linker_t *wasmtime_linker_new(wasm_engine_t *engine);
wasmtime_error_t *wasmtime_linker_define_wasi(wasmtime_linker_t *linker);
wasi_config_t *wasi_config_new(void);
wasmtime_error_t *wasmtime_context_set_wasi(wasmtime_context_t *context, wasi_config_t *wasi);
wasmtime_error_t *wasmtime_linker_instantiate(const wasmtime_linker_t *linker, wasmtime_context_t *store, const wasmtime_module_t *module, wasmtime_instance_t *instance, wasm_trap_t **trap);
bool wasmtime_instance_export_get(wasmtime_context_t *store, const wasmtime_instance_t *instance, const char *name, size_t name_len, wasmtime_extern_t *item);
wasmtime_error_t *wasmtime_func_call(wasmtime_context_t *store, const wasmtime_func_t *func, const wasmtime_val_t *args, size_t nargs, wasmtime_val_t *results, size_t nresults, wasm_trap_t **trap);
uint8_t *wasmtime_memory_data(const wasmtime_context_t *store, const wasmtime_memory_t *memory);
void wasm_byte_vec_delete(wasm_byte_vec_t *v);
void wasmtime_error_message(const wasmtime_error_t *error, wasm_byte_vec_t *message);
void wasm_trap_message(const wasm_trap_t *trap, wasm_byte_vec_t *message);
C;

    private static ?self $shared = null;
    private FFI $ffi;
    private $ctx;
    private $memory;
    private $alloc;
    private $free;
    private $call;

    public static function shared(): self
    {
        return self::$shared ??= new self();
    }

    public function __construct(?string $wasmPath = null, ?string $libPath = null, ?string $cacheDir = null)
    {
        $libPath ??= getenv('IVAR_WASMTIME_LIB') ?: 'libwasmtime.so';
        $wasmPath ??= dirname(__DIR__) . '/wasm/ivar_core.wasm';
        $this->ffi = FFI::cdef(self::CDEF, $libPath);
        $engine = $this->ffi->wasm_engine_new();
        $store = $this->ffi->wasmtime_store_new($engine, null, null);
        $this->ctx = $this->ffi->wasmtime_store_context($store);
        $module = $this->loadModule($engine, $wasmPath, $cacheDir ?? sys_get_temp_dir());
        $linker = $this->ffi->wasmtime_linker_new($engine);
        $this->check($this->ffi->wasmtime_linker_define_wasi($linker));
        $this->check($this->ffi->wasmtime_context_set_wasi($this->ctx, $this->ffi->wasi_config_new()));
        $instance = $this->ffi->new('wasmtime_instance_t');
        $trap = $this->ffi->new('wasm_trap_t*');
        $this->check($this->ffi->wasmtime_linker_instantiate($linker, $this->ctx, $module, FFI::addr($instance), FFI::addr($trap)), $trap);
        $get = function (string $name) use ($instance) {
            $item = $this->ffi->new('wasmtime_extern_t');
            if (!$this->ffi->wasmtime_instance_export_get($this->ctx, FFI::addr($instance), $name, strlen($name), FFI::addr($item))) {
                return null;
            }
            return $item;
        };
        // Keep the owning extern structs alive: `->of->func` is a view into them.
        $this->memory = $get('memory');
        $this->alloc = $get('ivar_alloc');
        $this->free = $get('ivar_free');
        $this->call = $get('ivar_call');
        $init = $get('_initialize');
        if ($init !== null) {
            $this->invoke($init, [], 0);
        }
    }

    private function loadModule($engine, string $wasmPath, string $cacheDir)
    {
        $module = $this->ffi->new('wasmtime_module_t*');
        $cache = rtrim($cacheDir, '/') . '/ivar_core.' . sha1_file($wasmPath) . '.cwasm';
        if (is_file($cache) && $this->ffi->wasmtime_module_deserialize_file($engine, $cache, FFI::addr($module)) === null) {
            return $module;
        }
        $bytes = file_get_contents($wasmPath);
        $buf = $this->ffi->new('uint8_t[' . strlen($bytes) . ']');
        FFI::memcpy($buf, $bytes, strlen($bytes));
        $this->check($this->ffi->wasmtime_module_new($engine, $buf, strlen($bytes), FFI::addr($module)));
        $out = $this->ffi->new('wasm_byte_vec_t');
        if ($this->ffi->wasmtime_module_serialize($module, FFI::addr($out)) === null) {
            @file_put_contents($cache . '.tmp', FFI::string($out->data, $out->size));
            @rename($cache . '.tmp', $cache);
            $this->ffi->wasm_byte_vec_delete(FFI::addr($out));
        }
        return $module;
    }

    private function check($error, $trap = null): void
    {
        if ($error !== null) {
            $msg = $this->ffi->new('wasm_byte_vec_t');
            $this->ffi->wasmtime_error_message($error, FFI::addr($msg));
            throw new RuntimeException('wasmtime: ' . FFI::string($msg->data, $msg->size));
        }
        if ($trap !== null && !FFI::isNull($trap)) {
            $msg = $this->ffi->new('wasm_byte_vec_t');
            $this->ffi->wasm_trap_message($trap, FFI::addr($msg));
            throw new RuntimeException('wasm trap: ' . FFI::string($msg->data, $msg->size));
        }
    }

    /** @param list<array{0:int,1:int}> $args kind and value pairs; $func is a wasmtime_extern_t */
    private function invoke($func, array $args, int $nresults): array
    {
        $in = $this->ffi->new('wasmtime_val_t[' . max(1, count($args)) . ']');
        foreach ($args as $i => [$kind, $value]) {
            $in[$i]->kind = $kind;
            if ($kind === 0) {
                $in[$i]->of->i32 = $value;
            } else {
                $in[$i]->of->i64 = $value;
            }
        }
        $out = $this->ffi->new('wasmtime_val_t[' . max(1, $nresults) . ']');
        $trap = $this->ffi->new('wasm_trap_t*');
        $this->check($this->ffi->wasmtime_func_call($this->ctx, FFI::addr($func->of->func), $in, count($args), $out, $nresults, FFI::addr($trap)), $trap);
        $res = [];
        for ($i = 0; $i < $nresults; $i++) {
            $res[] = $out[$i]->kind === 0 ? $out[$i]->of->i32 : $out[$i]->of->i64;
        }
        return $res;
    }

    /** Send one JSON request to the core and decode the response into arrays. */
    public function call(string $op, array $args = [], int $handle = 0): mixed
    {
        $raw = $this->callRaw($op, $args, $handle);
        $value = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (is_array($value) && count($value) === 1 && array_key_exists('error', $value)) {
            throw new IvarException((string) $value['error']);
        }
        return $value;
    }

    /**
     * Send one request and return the raw JSON response. String arguments that
     * hold JSON (a policy, an event) are passed through untouched, so empty
     * objects keep their shape.
     */
    public function callRaw(string $op, array $args = [], int $handle = 0): string
    {
        $req = ['op' => $op, 'args' => (object) $args];
        if ($handle !== 0) {
            $req['handle'] = $handle;
        }
        $data = json_encode($req, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $len = strlen($data);
        $ptr = $this->invoke($this->alloc, [[0, $len]], 1)[0] & 0xFFFFFFFF;
        FFI::memcpy($this->ffi->wasmtime_memory_data($this->ctx, FFI::addr($this->memory->of->memory)) + $ptr, $data, $len);
        $packed = $this->invoke($this->call, [[0, $ptr], [0, $len]], 1)[0];
        $this->invoke($this->free, [[0, $ptr], [0, $len]], 0);
        $outPtr = ($packed >> 32) & 0xFFFFFFFF;
        $outLen = $packed & 0xFFFFFFFF;
        $raw = FFI::string($this->ffi->wasmtime_memory_data($this->ctx, FFI::addr($this->memory->of->memory)) + $outPtr, $outLen);
        $this->invoke($this->free, [[0, $outPtr], [0, max(1, $outLen)]], 0);
        return $raw;
    }
}
