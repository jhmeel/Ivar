// The decision core, local sensor, action sink and intent tokens.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Ivar;

public static class IvarApi
{
    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>The spec default PolicyContent as JSON text.</summary>
    public static string DefaultPolicy(IvarRuntime rt) => rt.CallRaw("policy.default", new JsonObject { ["now_ms"] = Now() });

    /// <summary>Verified PolicyContent JSON; rollback and expired bundles are refused.</summary>
    public static string VerifyPolicyBundle(IvarRuntime rt, string archiveBase64, string keyringJson, long currentVersion)
    {
        var raw = rt.CallRaw("policy.verify", new JsonObject { ["archive_base64"] = archiveBase64, ["keyring"] = keyringJson, ["current_version"] = currentVersion, ["now_ms"] = Now() });
        if (JsonNode.Parse(raw) is JsonObject o && o.Count == 1 && o["error"] is { } e) throw new IvarException(e.GetValue<string>());
        return raw;
    }

    public static (string Token, string RootPublicKey) MintIntent(IvarRuntime rt, string rootSeedHex, string intentId, string action, string subject, IDictionary<string, long> limits, long ttlMs = 300_000)
    {
        var lim = new JsonObject();
        foreach (var (k, v) in limits) lim[k] = v;
        var r = rt.Call("intent.mint", new JsonObject { ["root_seed_hex"] = rootSeedHex, ["intent_id"] = intentId, ["action"] = action, ["subject"] = subject, ["limits"] = lim, ["expiry_ms"] = Now() + ttlMs });
        return (r["token"]!.GetValue<string>(), r["root_public_key"]!.GetValue<string>());
    }

    public static string AttestStep(IvarRuntime rt, string stepSeedHex, string step, string token, string rootPublicKey) =>
        rt.Call("intent.attest", new JsonObject { ["step_seed_hex"] = stepSeedHex, ["step"] = step, ["token"] = token, ["root_public_key"] = rootPublicKey, ["narrowing"] = new JsonObject() })["token"]!.GetValue<string>();

    public static string StepPublicKey(IvarRuntime rt, string stepSeedHex) =>
        rt.Call("intent.step_public_key", new JsonObject { ["step_seed_hex"] = stepSeedHex })["public_key"]!.GetValue<string>();

    /// <summary>Matches ivar_core::redact::keyed_hash.</summary>
    public static string KeyedHash(string keyHex, string value)
    {
        if (string.IsNullOrEmpty(value) || value.StartsWith("kh_") || string.IsNullOrEmpty(keyHex)) return value;
        using var h = new HMACSHA256(Convert.FromHexString(keyHex));
        return "kh_" + Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..24];
    }
}

public abstract class IvarHandle : IDisposable
{
    protected readonly IvarRuntime Rt;
    protected readonly long Handle;

    protected IvarHandle(IvarRuntime rt, string op, JsonObject args)
    {
        Rt = rt;
        Handle = rt.Call(op, args)["handle"]!.GetValue<long>();
    }

    public void Dispose() => Rt.Call("free", null, Handle);
}

/// <summary>The full core, embedded. Use it off the request path.</summary>
public sealed class Core(IvarRuntime rt, string policyJson, string redactionKeyHex)
    : IvarHandle(rt, "core.new", new JsonObject { ["policy"] = policyJson, ["redaction_key_hex"] = redactionKeyHex })
{
    public JsonNode Process(JsonNode ev, long now) => Rt.Call("core.process", new JsonObject { ["event"] = ev.DeepClone(), ["now_ms"] = now }, Handle);
    public JsonNode Evidence() => Rt.Call("core.evidence", null, Handle);
}

/// <summary>Known attacks are blocked here with no round trip (section 7.1).</summary>
public sealed class LocalSensor(IvarRuntime rt, string policyJson)
    : IvarHandle(rt, "sensor.new", new JsonObject { ["policy"] = policyJson })
{
    public JsonNode Decide(JsonNode ev, long now) => Rt.Call("sensor.decide", new JsonObject { ["event"] = ev.DeepClone(), ["now_ms"] = now }, Handle);
    public void PushVerdict(JsonNode verdict) => Rt.Call("sensor.push_verdict", new JsonObject { ["verdict"] = verdict.DeepClone() }, Handle);
}

/// <summary>The action sink: intent binding, consequence invariants and time locks.</summary>
public sealed class Sink(IvarRuntime rt, string rootPublicKey, IDictionary<string, string> stepKeys, string invariantsJson, string defaultMode, IDictionary<string, string> modes)
    : IvarHandle(rt, "sink.new", new JsonObject
    {
        ["root_public_key"] = rootPublicKey,
        ["step_keys"] = new JsonObject(stepKeys.Select(kv => KeyValuePair.Create(kv.Key, (JsonNode?)kv.Value))),
        ["invariants"] = invariantsJson,
        ["default_mode"] = defaultMode,
        ["modes"] = new JsonObject(modes.Select(kv => KeyValuePair.Create(kv.Key, (JsonNode?)kv.Value))),
    })
{
    public JsonNode Guard(JsonObject request, long now) => Rt.Call("sink.guard", new JsonObject { ["request"] = request, ["now_ms"] = now }, Handle);
}
