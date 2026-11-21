// One WebAssembly instance of the verified decision core, run by Wasmtime.
// Calls are serialised.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Wasmtime;

namespace Ivar;

public sealed class IvarException(string message) : Exception(message);

public sealed class IvarRuntime : IDisposable
{
    private static readonly Lazy<IvarRuntime> SharedInstance = new(() => new IvarRuntime());
    public static IvarRuntime Shared => SharedInstance.Value;

    private readonly Engine _engine;
    private readonly Store _store;
    private readonly Memory _memory;
    private readonly Func<int, int> _alloc;
    private readonly Action<int, int> _free;
    private readonly Func<int, int, long> _call;
    private readonly object _lock = new();

    public IvarRuntime()
    {
        _engine = new Engine();
        using var stream = typeof(IvarRuntime).Assembly.GetManifestResourceStream("ivar_core.wasm") ?? throw new InvalidOperationException("ivar_core.wasm missing");
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var module = Module.FromBytes(_engine, "ivar_core", ms.ToArray());
        var linker = new Linker(_engine);
        linker.DefineWasi();
        _store = new Store(_engine);
        _store.SetWasiConfiguration(new WasiConfiguration());
        var instance = linker.Instantiate(_store, module);
        instance.GetAction("_initialize")?.Invoke();
        _memory = instance.GetMemory("memory") ?? throw new InvalidOperationException("memory export missing");
        _alloc = instance.GetFunction<int, int>("ivar_alloc") ?? throw new InvalidOperationException("ivar_alloc missing");
        _free = instance.GetAction<int, int>("ivar_free") ?? throw new InvalidOperationException("ivar_free missing");
        _call = instance.GetFunction<int, int, long>("ivar_call") ?? throw new InvalidOperationException("ivar_call missing");
    }

    /// <summary>Send one request; JSON text arguments pass through unchanged.</summary>
    public string CallRaw(string op, JsonObject? args = null, long handle = 0)
    {
        var req = new JsonObject { ["op"] = op, ["args"] = args ?? new JsonObject() };
        if (handle != 0) req["handle"] = handle;
        var data = Encoding.UTF8.GetBytes(req.ToJsonString());
        lock (_lock)
        {
            int ptr = _alloc(data.Length);
            data.CopyTo(_memory.GetSpan(ptr, data.Length));
            long packed = _call(ptr, data.Length);
            _free(ptr, data.Length);
            int outPtr = (int)((ulong)packed >> 32);
            int outLen = (int)(packed & 0xFFFFFFFF);
            var raw = Encoding.UTF8.GetString(_memory.GetSpan(outPtr, outLen));
            _free(outPtr, Math.Max(outLen, 1));
            return raw;
        }
    }

    public JsonNode Call(string op, JsonObject? args = null, long handle = 0)
    {
        var node = JsonNode.Parse(CallRaw(op, args, handle)) ?? throw new IvarException("empty response");
        if (node is JsonObject o && o.Count == 1 && o.TryGetPropertyValue("error", out var e)) throw new IvarException(e?.GetValue<string>() ?? "error");
        return node;
    }

    public void Dispose()
    {
        _store.Dispose();
        _engine.Dispose();
    }
}
