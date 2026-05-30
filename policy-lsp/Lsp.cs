// Minimal Language Server Protocol server (stdio JSON-RPC) for TSM policy files.
// Reuses PolicyValidator so editors get the exact diagnostics the linter produces.
// Handles: initialize, didOpen/didChange/didClose (full sync) → publishDiagnostics,
// shutdown/exit. No external LSP library — just System.Text.Json over stdio.

using System.Text;
using System.Text.Json;

static class Lsp
{
    static readonly Dictionary<string, string> Docs = new();
    static readonly Stream Out = Console.OpenStandardOutput();

    public static void Run()
    {
        var stdin = Console.OpenStandardInput();
        while (true)
        {
            var msg = ReadMessage(stdin);
            if (msg is null) break;
            try { Dispatch(msg); } catch { /* never let one bad message kill the server */ }
            msg.Dispose();
        }
    }

    static JsonDocument? ReadMessage(Stream s)
    {
        int contentLength = 0;
        var line = new List<byte>();
        while (true)
        {
            int b = s.ReadByte();
            if (b < 0) return null;
            line.Add((byte)b);
            if (b == '\n')
            {
                string l = Encoding.ASCII.GetString(line.ToArray()).Trim();
                line.Clear();
                if (l.Length == 0) break; // blank line ends the header block
                if (l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(l[15..].Trim(), out contentLength);
            }
        }
        if (contentLength <= 0) return null;
        var buf = new byte[contentLength];
        int got = 0;
        while (got < contentLength)
        {
            int n = s.Read(buf, got, contentLength - got);
            if (n <= 0) return null;
            got += n;
        }
        return JsonDocument.Parse(buf);
    }

    static void Dispatch(JsonDocument msg)
    {
        var root = msg.RootElement;
        string method = root.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";
        bool hasId = root.TryGetProperty("id", out var id);

        switch (method)
        {
            case "initialize":
                Reply(id, new
                {
                    capabilities = new { textDocumentSync = 1 },   // 1 = full document sync
                    serverInfo = new { name = "tsm-policy-lsp", version = "1.0.0" }
                });
                break;

            case "textDocument/didOpen":
            {
                var td = root.GetProperty("params").GetProperty("textDocument");
                string uri = td.GetProperty("uri").GetString()!;
                string text = td.GetProperty("text").GetString()!;
                Docs[uri] = text;
                Publish(uri, text);
                break;
            }

            case "textDocument/didChange":
            {
                var p = root.GetProperty("params");
                string uri = p.GetProperty("textDocument").GetProperty("uri").GetString()!;
                var changes = p.GetProperty("contentChanges");
                string text = changes[changes.GetArrayLength() - 1].GetProperty("text").GetString()!;
                Docs[uri] = text;
                Publish(uri, text);
                break;
            }

            case "textDocument/didClose":
                Docs.Remove(root.GetProperty("params").GetProperty("textDocument").GetProperty("uri").GetString()!);
                break;

            case "shutdown":
                if (hasId) Reply(id, null);
                break;

            case "exit":
                Environment.Exit(0);
                break;
        }
    }

    static void Publish(string uri, string text)
    {
        var diags = PolicyValidator.Validate(text).Select(d => new
        {
            range = new
            {
                start = new { line = d.Line, character = d.StartChar },
                end = new { line = d.Line, character = d.EndChar }
            },
            severity = d.Severity == "error" ? 1 : 2,   // 1 = Error, 2 = Warning
            source = "tsm-policy",
            message = d.Message
        }).ToArray();
        Notify("textDocument/publishDiagnostics", new { uri, diagnostics = diags });
    }

    static void Reply(JsonElement id, object? result) => Send(new { jsonrpc = "2.0", id, result });
    static void Notify(string method, object prms) => Send(new { jsonrpc = "2.0", method, @params = prms });

    static void Send(object payload)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(payload);
        byte[] header = Encoding.ASCII.GetBytes($"Content-Length: {json.Length}\r\n\r\n");
        lock (Out) { Out.Write(header); Out.Write(json); Out.Flush(); }
    }
}
