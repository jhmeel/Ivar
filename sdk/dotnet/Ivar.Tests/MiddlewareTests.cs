using System.Diagnostics;
using System.Net;
using Ivar;
using Microsoft.AspNetCore.Http;
using Xunit;
using Xunit.Abstractions;

public class MiddlewareTests(ITestOutputHelper output)
{
    /// <summary>The spec default policy with DETECTION_MODE enforce.</summary>
    private static string EnforcePolicy()
    {
        var p = System.Text.Json.Nodes.JsonNode.Parse(IvarApi.DefaultPolicy(IvarRuntime.Shared))!;
        p["settings"]!["detection_mode"] = "enforce";
        return p.ToJsonString();
    }

    private static IvarGuardian Guardian(string mode, string? policy = null) => new(new IvarOptions
    {
        Mode = mode,
        PolicyJson = policy,
        Identity = ctx => ctx.Request.Headers["X-User"].ToString() is { Length: > 0 } u ? u : null,
        Session = ctx => ctx.Request.Headers["X-Session"].ToString(),
        OnAlert = (_, _) => { },
    });

    private static async Task<int> Run(IvarGuardian g, string path, string ip)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = path;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        ctx.Response.Body = new MemoryStream();
        await new IvarMiddleware(c => { c.Response.StatusCode = 200; return Task.CompletedTask; }, g).InvokeAsync(ctx);
        return ctx.Response.StatusCode;
    }

    [Fact]
    public async Task ObserveNeverAffectsRequests() => Assert.Equal(200, await Run(Guardian("observe"), "/.env.backup", "203.0.113.4"));

    [Fact]
    public async Task SignedObservePolicyNeverBlocks() => Assert.Equal(200, await Run(Guardian("enforce"), "/.env.backup", "203.0.113.9"));

    [Fact]
    public async Task EnforceBlocksDecoyThenContainsSource()
    {
        var g = Guardian("enforce", EnforcePolicy());
        Assert.Equal(403, await Run(g, "/.env.backup", "203.0.113.5"));
        await g.FlushAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(403, await Run(g, "/hello", "203.0.113.5"));
        Assert.Equal(200, await Run(g, "/hello", "198.51.100.8"));
    }

    [Fact]
    public async Task PayoutIntentChain()
    {
        var g = Guardian("enforce");
        var rt = IvarRuntime.Shared;
        var seeds = new (string Step, string Seed)[] { ("authenticated_session", new string('2', 64)), ("ledger_entry", new string('3', 64)), ("payout_instruction", new string('4', 64)) };
        var keys = seeds.ToDictionary(s => s.Step, s => IvarApi.StepPublicKey(rt, s.Seed));
        (string, string) Chain(string id, long limit)
        {
            var (t, root) = IvarApi.MintIntent(rt, new string('1', 64), id, "payout", "ses_1", new Dictionary<string, long> { ["amount"] = limit });
            foreach (var (step, seed) in seeds) t = IvarApi.AttestStep(rt, seed, step, t, root);
            return (t, root);
        }
        var (t1, rootKey) = Chain("i1", 5000);
        var guard = g.Guard("payout", rootKey, keys, "enforce");
        async Task<int> Pay(string? token, double value)
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Headers["X-User"] = "svc";
            ctx.Request.Headers["X-Session"] = "ses_1";
            if (token is not null) ctx.Request.Headers[IvarGuardian.IntentHeader] = token;
            ctx.Response.Body = new MemoryStream();
            return await guard.CheckAsync(ctx, value) ? 200 : ctx.Response.StatusCode;
        }
        Assert.Equal(403, await Pay(null, 100));
        Assert.Equal(200, await Pay(t1, 100));
        Assert.Equal(202, await Pay(Chain("i2", 100_000).Item1, 60_000));
    }

    [Fact]
    public void LocalDecisionLatency()
    {
        var g = Guardian("enforce");
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = "/x";
        var times = new List<double>();
        for (var i = 0; i < 1000; i++)
        {
            var sw = Stopwatch.StartNew();
            g.Sensor.Decide(g.Event(ctx, "http.request", 4002), IvarApi.Now());
            times.Add(sw.Elapsed.TotalMilliseconds);
        }
        times.Sort();
        output.WriteLine($"dotnet local decision p99 {times[990]:F3} ms");
        Assert.True(times[990] < 5);
    }
}
