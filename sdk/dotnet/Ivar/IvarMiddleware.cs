// ASP.NET Core middleware.
//
//   builder.Services.AddIvar(o => { o.Mode = "observe"; o.Identity = ctx => ctx.User.Identity?.Name; });
//   app.UseIvar();
//
// Observe mode records decisions without affecting a request; enforce mode
// blocks known attacks in the middleware and applies core verdicts to later
// requests. Scoring runs on a background worker. Faults fail open on public
// routes and closed on admin routes.

using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ivar;

public sealed class IvarOptions
{
    public string Mode { get; set; } = "observe";
    public Func<HttpContext, string?> Identity { get; set; } = ctx => ctx.User.Identity?.Name;
    public Func<HttpContext, string?> Session { get; set; } = _ => null;
    public Func<HttpContext, IEnumerable<string>> Roles { get; set; } = _ => [];
    public string? CoreUrl { get; set; }
    /// <summary>The sensor token the core issued for SensorId.</summary>
    public string? CoreToken { get; set; }
    public string? PolicyJson { get; set; }
    public string RedactionKey { get; set; } = "";
    public string SensorId { get; set; } = "dotnet-sdk";
    public string[] AdminPrefixes { get; set; } = ["/admin"];
    public TimeSpan Budget { get; set; } = TimeSpan.FromMilliseconds(1);
    public Action<string, string> OnAlert { get; set; } = (k, m) => Console.Error.WriteLine($"[ivar] {k}: {m}");
}

public sealed class IvarGuardian
{
    public const string IntentHeader = "Ivar-Intent";
    public IvarOptions Options { get; }
    internal readonly IvarRuntime Rt = IvarRuntime.Shared;
    internal readonly string PolicyJson;
    public LocalSensor Sensor { get; }
    private readonly Core? _core;
    private readonly Channel<JsonNode> _queue = Channel.CreateBounded<JsonNode>(new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private long _seq;
    private int _pending;

    public IvarGuardian(IvarOptions options)
    {
        if (options.Mode is not ("observe" or "enforce")) throw new ArgumentException("mode must be observe or enforce");
        Options = options;
        PolicyJson = options.PolicyJson ?? IvarApi.DefaultPolicy(Rt);
        Sensor = new LocalSensor(Rt, PolicyJson);
        if (options.CoreUrl is null) _core = new Core(Rt, PolicyJson, string.IsNullOrEmpty(options.RedactionKey) ? "00" : options.RedactionKey);
        var warm = new JsonObject { ["activity_name"] = "http.request", ["http_request"] = new JsonObject { ["http_method"] = "GET", ["url_path"] = "/" }, ["ivar"] = new JsonObject() };
        for (var i = 0; i < 200; i++) Sensor.Decide(warm, IvarApi.Now());
        _ = Task.Run(DrainAsync);
    }

    public JsonObject Event(HttpContext ctx, string activity, int classUid, int status = 0, JsonObject? ext = null)
    {
        var actor = new JsonObject { ["authorizations"] = string.Join(",", Options.Roles(ctx)) };
        var id = Options.Identity(ctx);
        if (!string.IsNullOrEmpty(id)) actor["user"] = new JsonObject { ["uid"] = IvarApi.KeyedHash(Options.RedactionKey, id), ["type"] = "human" };
        var session = Options.Session(ctx);
        if (!string.IsNullOrEmpty(session)) actor["session"] = new JsonObject { ["uid"] = session };
        var x = new JsonObject
        {
            ["sensor_id"] = Options.SensorId, ["sensor_type"] = "app_sdk", ["observation_point"] = "app_sdk",
            ["sensor_seq"] = Interlocked.Increment(ref _seq), ["request_id"] = ctx.Request.Headers["X-Request-Id"].ToString(),
        };
        if (ext is not null) foreach (var (k, v) in ext) x[k] = v?.DeepClone();
        var ev = new JsonObject
        {
            ["class_uid"] = classUid, ["category_uid"] = classUid / 1000, ["activity_id"] = 1, ["time"] = IvarApi.Now(), ["status_id"] = 1, ["activity_name"] = activity,
            ["metadata"] = new JsonObject { ["version"] = "1.3.0", ["extensions"] = new JsonArray(new JsonObject { ["name"] = "ivar", ["uid"] = "999", ["version"] = "1.0.0" }) },
            ["actor"] = actor,
            ["src_endpoint"] = new JsonObject { ["ip"] = ctx.Connection.RemoteIpAddress?.ToString() ?? "" },
            ["http_request"] = new JsonObject { ["http_method"] = ctx.Request.Method, ["url_path"] = ctx.Request.Path.Value ?? "", ["user_agent"] = ctx.Request.Headers.UserAgent.ToString(), ["body_keys"] = new JsonArray(BodyKeys.Of(ctx).Select(k => (JsonNode)k!).ToArray()) },
            ["ivar"] = x,
        };
        if (status != 0) ev["http_response"] = new JsonObject { ["code"] = status };
        return ev;
    }

    public void Submit(JsonNode ev)
    {
        Interlocked.Increment(ref _pending);
        if (_queue.Writer.TryWrite(ev)) return;
        Interlocked.Decrement(ref _pending);
        Options.OnAlert("fail_open", "event buffer full");
    }

    /// <summary>Report a login so credential spraying and account takeover are correlated.</summary>
    public void ReportLogin(HttpContext ctx, bool success, string account)
    {
        var ev = Event(ctx, "auth.login", 3002, 0, new JsonObject { ["target_entity"] = "user:" + IvarApi.KeyedHash(Options.RedactionKey, account) });
        ev["status_id"] = success ? 1 : 2;
        Submit(ev);
    }

    /// <summary>Report a business action such as a payout, a role change or an export.</summary>
    public void ReportAction(HttpContext ctx, string name, double value = 0, long records = 0, bool destructive = false) =>
        Submit(Event(ctx, "business.action", 6003, 0, new JsonObject { ["business_action"] = name, ["value_moved"] = value, ["records_read"] = records, ["destructive"] = destructive }));

    private async Task DrainAsync()
    {
        var failing = false;
        var reader = _queue.Reader;
        while (await reader.WaitToReadAsync())
        {
            // Everything queued so far goes in one request, up to 500 events.
            var batch = new List<JsonNode>();
            while (batch.Count < 500 && reader.TryRead(out var ev)) batch.Add(ev);
            try
            {
                var verdicts = new List<JsonNode>();
                if (_core is not null)
                {
                    foreach (var ev in batch) if (_core.Process(ev, IvarApi.Now())["verdicts"] is JsonArray a) verdicts.AddRange(a.Where(v => v is not null)!);
                }
                else
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, Options.CoreUrl!.TrimEnd('/') + "/v1/events")
                    {
                        Content = JsonContent.Create(new JsonObject { ["sensor_id"] = Options.SensorId, ["events"] = new JsonArray(batch.Select(e => e.DeepClone()).ToArray()) }),
                    };
                    if (!string.IsNullOrEmpty(Options.CoreToken)) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Options.CoreToken);
                    using var resp = await _http.SendAsync(req);
                    if (!resp.IsSuccessStatusCode)
                    {
                        var code = (int)resp.StatusCode;
                        if (!failing) Options.OnAlert("sdk_fault", code is 401 or 403 ? $"the core refused this sensor's token (HTTP {code}): check CoreToken and the sensor id it is issued for" : $"the core answered HTTP {code}");
                        failing = true;
                        continue;
                    }
                    failing = false;
                    if (JsonNode.Parse(await resp.Content.ReadAsStringAsync())?["verdicts"] is JsonArray a) verdicts.AddRange(a.Where(v => v is not null)!);
                }
                foreach (var v in verdicts) Sensor.PushVerdict(v);
            }
            catch (Exception e)
            {
                if (!failing) Options.OnAlert("sdk_fault", "the core is unreachable, events are not scored until it returns: " + e.Message);
                failing = true;
            }
            finally { Interlocked.Add(ref _pending, -batch.Count); }
        }
    }

    /// <summary>Wait until queued events were scored.</summary>
    public async Task FlushAsync(TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (Volatile.Read(ref _pending) > 0 && sw.Elapsed < timeout) await Task.Delay(5);
    }

    /// <summary>Action sink for one high consequence action. Fails closed.</summary>
    public ActionGuard Guard(string action, string rootPublicKey, IDictionary<string, string> stepKeys, string? intentBinding = null)
    {
        var policy = JsonNode.Parse(PolicyJson)!;
        var modes = new Dictionary<string, string>();
        if (policy["intent_binding"] is JsonObject ib) foreach (var (k, v) in ib) modes[k] = v!.GetValue<string>();
        if (intentBinding is not null) modes[action] = intentBinding;
        var invariants = policy["invariants"]?.ToJsonString() ?? "[]";
        return new ActionGuard(this, action, new Sink(Rt, rootPublicKey, stepKeys, invariants, modes.GetValueOrDefault(action, "observe"), modes));
    }
}

public sealed class IvarMiddleware(RequestDelegate next, IvarGuardian g)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        await BodyKeys.ReadAsync(ctx);
        var o = g.Options;
        var admin = o.AdminPrefixes.Any(p => ctx.Request.Path.StartsWithSegments(p));
        var sw = Stopwatch.StartNew();
        JsonNode local;
        try { local = g.Sensor.Decide(g.Event(ctx, "http.request", 4002), IvarApi.Now()); }
        catch (Exception e)
        {
            if (admin)
            {
                o.OnAlert("sdk_fault", "admin route failed closed: " + e.Message);
                await Write(ctx, 503, new JsonObject { ["error"] = "security check unavailable" });
                return;
            }
            o.OnAlert("fail_open", e.Message);
            await next(ctx);
            return;
        }
        if (sw.Elapsed > o.Budget) o.OnAlert("budget_exceeded", $"local decision took {sw.Elapsed.TotalMilliseconds:F3} ms");
        if (local["verdict"] is JsonObject v && o.Mode == "enforce" && (string?)v["mode"] == "enforce")
        {
            var id = v["verdict_id"]!.GetValue<string>();
            int code = v["decision"]!.GetValue<string>() switch { "block" or "contain" or "refuse" => 403, "challenge" => 401, "throttle" => 429, _ => 0 };
            if (code != 0)
            {
                if (code == 401) ctx.Response.Headers.WWWAuthenticate = "step-up";
                await Write(ctx, code, new JsonObject { ["error"] = code == 401 ? "step up verification required" : code == 429 ? "slow down" : "request blocked", ["verdict_id"] = id });
                g.Submit(g.Event(ctx, "http.request", 4002, code));
                return;
            }
        }
        try { await next(ctx); }
        finally { g.Submit(g.Event(ctx, "http.request", 4002, ctx.Response.StatusCode)); }
    }

    internal static async Task Write(HttpContext ctx, int status, JsonObject body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(body.ToJsonString());
    }
}

public sealed class ActionGuard
{
    private readonly IvarGuardian _g;
    private readonly string _action;
    private readonly Sink _sink;

    internal ActionGuard(IvarGuardian g, string action, Sink sink) => (_g, _action, _sink) = (g, action, sink);

    /// <summary>Returns true when the action may run; otherwise the response was written.</summary>
    public async Task<bool> CheckAsync(HttpContext ctx, double value = 0, double records = 0, bool destructive = false)
    {
        var o = _g.Options;
        var identity = o.Identity(ctx) ?? "";
        var session = o.Session(ctx);
        var req = new JsonObject
        {
            ["action"] = _action, ["subject"] = string.IsNullOrEmpty(session) ? identity : session, ["identity"] = identity, ["business"] = "",
            ["value_moved"] = value, ["records_read"] = records, ["destructive"] = destructive,
        };
        var token = ctx.Request.Headers[IvarGuardian.IntentHeader].ToString();
        if (!string.IsNullOrEmpty(token)) req["intent_token"] = token;
        JsonNode d;
        try { d = _sink.Guard(req, IvarApi.Now()); }
        catch (Exception e)
        {
            o.OnAlert("sdk_fault", "action sink failed closed: " + e.Message);
            await IvarMiddleware.Write(ctx, 503, new JsonObject { ["error"] = "action check unavailable" });
            return false;
        }
        var outcome = d["outcome"]!;
        var kind = outcome["outcome"]!.GetValue<string>();
        _g.Submit(_g.Event(ctx, "business.action", 6003, 0, new JsonObject { ["business_action"] = _action, ["value_moved"] = value, ["attributes"] = new JsonObject { ["sink_outcome"] = kind } }));
        switch (kind)
        {
            case "executes":
                if (d["would_refuse"] is JsonValue w) o.OnAlert("action_refused", $"observe: would refuse {_action}: {w}");
                return true;
            case "refused":
                o.OnAlert("action_refused", outcome["reason"]!.GetValue<string>());
                await IvarMiddleware.Write(ctx, 403, new JsonObject { ["error"] = "no valid intent chain for this action" });
                return false;
            case "blocked_alert":
                o.OnAlert("invariant_breach", outcome["invariant_id"]!.GetValue<string>());
                await IvarMiddleware.Write(ctx, 409, new JsonObject { ["error"] = "consequence limit reached" });
                return false;
            default:
                var lockId = outcome["lock"]!["lock_id"]!.GetValue<string>();
                o.OnAlert("time_lock", lockId);
                await IvarMiddleware.Write(ctx, 202, new JsonObject { ["status"] = "held", ["lock_id"] = lockId });
                return false;
        }
    }
}

public static class IvarExtensions
{
    public static IServiceCollection AddIvar(this IServiceCollection services, Action<IvarOptions> configure)
    {
        var o = new IvarOptions();
        configure(o);
        return services.AddSingleton(new IvarGuardian(o));
    }

    public static IApplicationBuilder UseIvar(this IApplicationBuilder app) => app.UseMiddleware<IvarMiddleware>();
}
