using System.Net;
using System.Net.Sockets;
using Ivar;
using Microsoft.AspNetCore.Http;
using Xunit;

/// <summary>A newer signed policy applies live; a forged one is refused; a restart resumes at the saved one.</summary>
public class PolicyRefreshTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "testdata", "policy", name)).Trim();

    private static async Task<int> Decoy(IvarGuardian g)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = "/v2-decoy";
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.4");
        ctx.Response.Body = new MemoryStream();
        await new IvarMiddleware(c => { c.Response.StatusCode = 200; return Task.CompletedTask; }, g).InvokeAsync(ctx);
        return ctx.Response.StatusCode;
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task NewerSignedPolicyAppliesLiveAndForgedIsRefused()
    {
        var keyring = Fixture("keyring.json");
        var v1 = IvarApi.VerifyPolicyBundle(IvarRuntime.Shared, Fixture("v1.bundle"), keyring, 0);
        var serve = "v2.bundle";
        var port = FreePort();
        using var cp = new HttpListener();
        cp.Prefixes.Add($"http://127.0.0.1:{port}/");
        cp.Start();
        _ = Task.Run(async () =>
        {
            while (cp.IsListening)
            {
                HttpListenerContext c;
                try { c = await cp.GetContextAsync(); } catch { return; }
                var body = System.Text.Encoding.UTF8.GetBytes(Fixture(Volatile.Read(ref serve)));
                c.Response.ContentLength64 = body.Length;
                await c.Response.OutputStream.WriteAsync(body);
                c.Response.Close();
            }
        });

        Assert.NotEqual(403, await Decoy(new IvarGuardian(new IvarOptions { Mode = "enforce", PolicyJson = v1, OnAlert = (_, _) => { } })));
        var alerts = new List<string>();
        var state = Path.Combine(Path.GetTempPath(), $"ivar-{Guid.NewGuid():N}.state");
        var g = new IvarGuardian(new IvarOptions
        {
            Mode = "enforce", PolicyJson = v1, ControlUrl = $"http://127.0.0.1:{port}", PolicyKeyringJson = keyring,
            PolicyRefresh = TimeSpan.FromHours(1), PolicyStateFile = state, OnAlert = (k, _) => { lock (alerts) alerts.Add(k); },
        });
        await g.RefreshPolicyAsync();
        Assert.Contains("\"version\":2", g.PolicyJson.Replace(" ", ""));
        Assert.Equal(403, await Decoy(g));
        Volatile.Write(ref serve, "forged-v3.bundle");
        Assert.False(await g.RefreshPolicyAsync());
        Assert.Contains("\"version\":2", g.PolicyJson.Replace(" ", ""));
        lock (alerts) Assert.Contains("policy_rejected", alerts);

        var restarted = new IvarGuardian(new IvarOptions { Mode = "enforce", PolicyJson = v1, PolicyKeyringJson = keyring, PolicyStateFile = state, OnAlert = (_, _) => { } });
        Assert.Contains("\"version\":2", restarted.PolicyJson.Replace(" ", ""));
        cp.Stop();
    }
}
