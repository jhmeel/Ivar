// Reads the top level field names of a JSON request body and rewinds the
// body for the app. Values are never kept: only names leave the application
// (section 16).

using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Ivar;

internal static class BodyKeys
{
    private const string Item = "Ivar.BodyKeys";
    private const int MaxBytes = 64 * 1024;

    public static async Task ReadAsync(HttpContext ctx)
    {
        var req = ctx.Request;
        if (req.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) != true || req.ContentLength is null or > MaxBytes) return;
        req.EnableBuffering(MaxBytes);
        using var buffer = new MemoryStream();
        await req.Body.CopyToAsync(buffer);
        req.Body.Position = 0;
        var keys = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(buffer.ToArray());
            if (doc.RootElement.ValueKind == JsonValueKind.Object) keys.AddRange(doc.RootElement.EnumerateObject().Select(p => p.Name));
        }
        catch (JsonException)
        {
            // Not JSON after all: no names to report.
        }
        keys.Sort(StringComparer.Ordinal);
        ctx.Items[Item] = keys.Take(64).ToList();
    }

    public static IReadOnlyList<string> Of(HttpContext ctx) => ctx.Items.TryGetValue(Item, out var v) && v is List<string> l ? l : [];
}
