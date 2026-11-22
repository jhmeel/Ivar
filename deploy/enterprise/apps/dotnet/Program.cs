// The test shop API in C# with ASP.NET Core minimal APIs and Ivar.AspNetCore.
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Ivar;

static string Env(string k) => Environment.GetEnvironmentVariable(k) ?? "";
static string H(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
string dir = Env("IVAR_DIR");
string Read(string f) => File.ReadAllText(Path.Combine(dir, f));

var users = new ConcurrentDictionary<string, User>();
for (var i = 1; i <= 200; i++) users[$"user{i}@corp.test"] = new User($"u{i}", H($"pw{i}"), i == 1 ? ["admin"] : ["customer"]);
var sessions = new ConcurrentDictionary<string, User>();
User? UserOf(HttpContext c) => sessions.TryGetValue(c.Request.Headers["X-Session"].ToString(), out var u) ? u : null;

var rt = new IvarRuntime();
var steps = new Dictionary<string, string> { ["authenticated_session"] = Env("IVAR_STEP_SESSION"), ["ledger_entry"] = Env("IVAR_STEP_LEDGER"), ["payout_instruction"] = Env("IVAR_STEP_PAYOUT") };
var stepKeys = steps.ToDictionary(kv => kv.Key, kv => IvarApi.StepPublicKey(rt, kv.Value));
var root = Env("IVAR_ROOT_SEED");
var rootPub = IvarApi.MintIntent(rt, root, "boot", "payout", "boot", new Dictionary<string, long> { ["amount"] = 1 }).RootPublicKey;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddIvar(o =>
{
    o.Mode = Env("IVAR_MODE") is "" ? "enforce" : Env("IVAR_MODE");
    o.Identity = ctx => UserOf(ctx)?.Id;
    o.Session = ctx => ctx.Request.Headers["X-Session"];
    o.Roles = ctx => UserOf(ctx)?.Roles ?? [];
    o.CoreUrl = Env("IVAR_CORE_URL");
    o.CoreToken = Env("IVAR_CORE_TOKEN") is "" ? null : Env("IVAR_CORE_TOKEN");
    o.PolicyJson = IvarApi.VerifyPolicyBundle(rt, Read("policy.bundle"), Read("keyring.json"), 0);
    o.RedactionKey = Read("keys/redaction.hex").Trim();
    o.SensorId = Env("SENSOR_ID");
    o.OnAlert = (k, m) => Console.WriteLine(new JsonObject { ["ivar_alert"] = k, ["message"] = m }.ToJsonString());
    o.ControlUrl = Env("IVAR_CONTROL_URL") is "" ? null : Env("IVAR_CONTROL_URL");
    o.PolicyKeyringJson = Read("keyring.json");
    o.PolicyRefresh = TimeSpan.FromSeconds(2);
    o.PolicyStateFile = Path.Combine(Env("IVAR_DIR"), "policy.state");
});
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o => o.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor);
var app = builder.Build();
// The gateway on loopback is a known proxy: its X-Forwarded-For names the client.
app.UseForwardedHeaders();
app.UseIvar();
var payoutGuard = app.Services.GetRequiredService<IvarGuardian>().Guard("payout", rootPub, stepKeys);

app.MapGet("/healthz", () => "ok");
app.MapPost("/login", (HttpContext ctx, Login b) =>
{
    var ok = users.TryGetValue(b.email ?? "", out var u) && u.Password == H(b.password ?? "");
    app.Services.GetRequiredService<IvarGuardian>().ReportLogin(ctx, ok, b.email ?? "");
    if (!ok) return Results.Json(new { error = "invalid credentials" }, statusCode: 401);
    var sid = "ses_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
    sessions[sid] = u!;
    return Results.Json(new { session = sid });
});
app.MapGet("/accounts/{id}", (HttpContext ctx, string id) => UserOf(ctx) is not { } u ? Results.Json(new { error = "login required" }, statusCode: 401)
    : u.Id == id ? Results.Json(new { id, balance = u.Balance }) : Results.Json(new { error = "not your account" }, statusCode: 403));
app.MapMethods("/users/{id}", ["PATCH"], (HttpContext ctx, Profile p) =>
{
    if (UserOf(ctx) is not { } u) return Results.Json(new { error = "login required" }, statusCode: 401);
    if (!string.IsNullOrEmpty(p.role)) u.Roles.Add(p.role);
    return Results.Json(new { id = u.Id, roles = u.Roles });
});
app.MapPost("/payouts/intent", (HttpContext ctx, Payout p) =>
{
    if (UserOf(ctx) is null) return Results.Json(new { error = "login required" }, statusCode: 401);
    var t = IvarApi.MintIntent(rt, root, "int_" + Guid.NewGuid().ToString("N")[..12], "payout", ctx.Request.Headers["X-Session"].ToString(), new Dictionary<string, long> { ["amount"] = (long)p.amount }).Token;
    foreach (var k in new[] { "authenticated_session", "ledger_entry", "payout_instruction" }) t = IvarApi.AttestStep(rt, steps[k], k, t, rootPub);
    return Results.Json(new { intent = t, header = IvarGuardian.IntentHeader });
});
app.MapPost("/payouts", async (HttpContext ctx, Payout p) =>
{
    if (UserOf(ctx) is null) return Results.Json(new { error = "login required" }, statusCode: 401);
    if (!await payoutGuard.CheckAsync(ctx, value: p.amount)) return Results.Empty;
    return Results.Json(new { sent = true });
});
app.MapGet("/admin/users", (HttpContext ctx) => UserOf(ctx) is not { } u ? Results.Json(new { error = "login required" }, statusCode: 401)
    : u.Roles.Contains("admin") ? Results.Json(new { users = users.Count }) : Results.Json(new { error = "admins only" }, statusCode: 403));
app.Run($"http://127.0.0.1:{Env("PORT")}");

record User(string Id, string Password, List<string> Roles) { public double Balance { get; set; } = 100000; }
record Login(string? email, string? password);
record Profile(string? name, string? role);
record Payout(double amount, string? account);
