// TSM Policy Language Server / Linter — C#/.NET + LSP for policy-as-code.
//
// Validates TSM policy rule files ({"rules":[{name,priority,condition,action},...]})
// that BOTH the Python policy_engine and the Rust dataplane consume, and serves the
// same diagnostics over the Language Server Protocol (LSP) to any editor.
//
//   Lint mode (default):  tsm-policy-lsp <policy.json>     (reads stdin if no path)
//   LSP mode (editors):   tsm-policy-lsp --lsp             (stdio JSON-RPC)
//
// Self-contained: System.Text.Json only — no external LSP NuGet, so the build is
// reliable offline.

using System.Text;
using System.Text.Json;

// ── Diagnostic model ──────────────────────────────────────────────────────────
record Diag(int Line, int StartChar, int EndChar, string Severity, string Message);

// ── Validation engine (the value; the LSP and CLI both use it) ─────────────────
static class PolicyValidator
{
    static readonly string[] ValidActions = { "allow", "redact", "block", "route_local" };
    static readonly HashSet<string> KnownConditionFields = new()
    {
        "pii_types", "any_of", "all_of", "min_count", "risk_score_gte", "risk_score_gt",
        "severity", "user_role", "model_prefix", "model", "org_id"
    };

    public static List<Diag> Validate(string text)
    {
        var diags = new List<Diag>();
        JsonDocument doc;
        try { doc = JsonDocument.Parse(text); }
        catch (JsonException e)
        {
            int ln = (int)(e.LineNumber ?? 0);
            int col = (int)(e.BytePositionInLine ?? 0);
            diags.Add(new Diag(ln, col, col + 1, "error", "Invalid JSON: " + (e.Message.Split('.')[0])));
            return diags;
        }

        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            diags.Add(new Diag(0, 0, 1, "error", "Policy must be a JSON object with a \"rules\" array"));
            return diags;
        }
        if (!root.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
        {
            diags.Add(Locate(text, "rules", "error", "Missing or invalid \"rules\" array"));
            return diags;
        }

        var seen = new HashSet<string>();
        int idx = 0;
        foreach (var rule in rules.EnumerateArray())
        {
            if (rule.ValueKind != JsonValueKind.Object)
            {
                diags.Add(new Diag(0, 0, 1, "error", $"rule[{idx}] must be an object"));
                idx++; continue;
            }

            // name — required, non-empty, unique
            if (!rule.TryGetProperty("name", out var nameEl) || nameEl.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(nameEl.GetString()))
            {
                diags.Add(Locate(text, "{", "error", $"rule[{idx}]: required string \"name\" missing or empty", idx));
            }
            else
            {
                var nm = nameEl.GetString()!;
                if (!seen.Add(nm))
                    diags.Add(Locate(text, $"\"{nm}\"", "error", $"duplicate rule name \"{nm}\""));
            }

            // action — required, must be a known verdict
            if (!rule.TryGetProperty("action", out var actEl) || actEl.ValueKind != JsonValueKind.String)
            {
                diags.Add(Locate(text, "{", "error", $"rule[{idx}]: required string \"action\" missing", idx));
            }
            else
            {
                var act = actEl.GetString()!;
                if (Array.IndexOf(ValidActions, act) < 0)
                    diags.Add(Locate(text, $"\"{act}\"", "error",
                        $"invalid action \"{act}\" — expected one of: {string.Join(", ", ValidActions)}"));
            }

            // priority — optional, numeric
            if (rule.TryGetProperty("priority", out var prEl) && prEl.ValueKind != JsonValueKind.Number)
                diags.Add(Locate(text, "priority", "error", $"rule[{idx}]: \"priority\" must be a number"));

            // condition — optional object; warn on unknown fields
            if (rule.TryGetProperty("condition", out var condEl))
            {
                if (condEl.ValueKind != JsonValueKind.Object)
                    diags.Add(Locate(text, "condition", "error", $"rule[{idx}]: \"condition\" must be an object"));
                else
                    foreach (var f in condEl.EnumerateObject())
                        if (!KnownConditionFields.Contains(f.Name))
                            diags.Add(Locate(text, $"\"{f.Name}\"", "warning",
                                $"unknown condition field \"{f.Name}\" — won't match in the engine"));
            }
            idx++;
        }
        return diags;
    }

    // Best-effort position: find the nth occurrence (or first) of a token → (line, char).
    static Diag Locate(string text, string needle, string sev, string msg, int skip = 0)
    {
        int off = -1, from = 0;
        for (int k = 0; k <= skip; k++)
        {
            off = text.IndexOf(needle, from, StringComparison.Ordinal);
            if (off < 0) break;
            from = off + 1;
        }
        if (off < 0) return new Diag(0, 0, 1, sev, msg);
        int line = 0, lineStart = 0;
        for (int i = 0; i < off; i++) if (text[i] == '\n') { line++; lineStart = i + 1; }
        int ch = off - lineStart;
        return new Diag(line, ch, ch + Math.Max(1, needle.Length), sev, msg);
    }
}

// ── Entry point: CLI lint vs. LSP server ───────────────────────────────────────
static class Program
{
    static int Main(string[] args)
    {
        if (Array.IndexOf(args, "--lsp") >= 0) { Lsp.Run(); return 0; }

        string text = args.Length > 0 && File.Exists(args[0])
            ? File.ReadAllText(args[0])
            : Console.In.ReadToEnd();

        var diags = PolicyValidator.Validate(text);
        int errors = 0;
        foreach (var d in diags)
        {
            if (d.Severity == "error") errors++;
            Console.WriteLine($"  {d.Severity,-7} {d.Line + 1}:{d.StartChar + 1}  {d.Message}");
        }
        Console.WriteLine(diags.Count == 0
            ? "  OK — policy is valid"
            : $"  {errors} error(s), {diags.Count - errors} warning(s)");
        return errors > 0 ? 1 : 0;
    }
}
