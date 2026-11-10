using System.Text;

namespace Compliance_Scanner;

/// <summary>
/// Translates a Wazuh SCA <c>c:</c> rule (cmd.exe syntax) into the PowerShell script
/// executed by <see cref="RuleChecker"/> on Windows.
/// </summary>
/// <remarks>
/// Wazuh runs command rules through cmd.exe, so policies contain forms like
/// <c>powershell -NoProfile -Command "Get-Date"</c> or <c>cmd /c powershell "Get-Date"</c>.
/// The scanner runs every command as a PowerShell script instead, which means the
/// executable prefix and its switches must be removed before the remaining script is
/// passed to <c>-EncodedCommand</c>. Without this translation PowerShell would try to
/// parse <c>-NoProfile -Command "…"</c> as a script and fail with a CLIXML error dump.
/// </remarks>
public static class WindowsCommand
{
    /// <summary>
    /// Returns the PowerShell script to run for a Wazuh command rule. Bare commands
    /// (e.g. <c>secedit /export …</c>) are returned unchanged and run as a PowerShell script.
    /// </summary>
    public static string ToPowerShellScript(string command)
    {
        string script = Environment.ExpandEnvironmentVariables(command).Trim();

        // Unwrap "cmd /c …" (possibly nested) so the real command is translated further.
        while (TryUnwrapCmd(script, out string inner))
            script = inner;

        if (!TryGetPowerShellArguments(script, out string arguments))
            return script;

        return ResolveScriptFromArguments(arguments) ?? script;
    }

    // ── cmd.exe wrapper ──────────────────────────────────────────────────────

    private static bool TryUnwrapCmd(string command, out string inner)
    {
        inner = string.Empty;
        List<Token> tokens = Tokenize(command);
        if (tokens.Count < 3 || !IsExecutable(tokens[0].Value, "cmd"))
            return false;

        for (int i = 1; i < tokens.Count; i++)
        {
            string token = tokens[i].Value;
            if (token.Equals("/c", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= tokens.Count)
                    return false;
                inner = command[tokens[i].End..].Trim();
                // "cmd /c \"echo hi\"" passes the whole quoted string as one argument.
                List<Token> remainderTokens = Tokenize(inner);
                if (remainderTokens.Count == 1
                    && remainderTokens[0].Start == 0
                    && remainderTokens[0].End == inner.Length
                    && inner[0] == '"')
                {
                    inner = remainderTokens[0].Value;
                }
                return inner.Length > 0;
            }
            // Only cmd switches may precede /c (e.g. "cmd /d /c …").
            if (!token.StartsWith('/') && !token.StartsWith('-'))
                return false;
        }
        return false;
    }

    // ── PowerShell invocation ────────────────────────────────────────────────

    private static bool TryGetPowerShellArguments(string command, out string arguments)
    {
        arguments = string.Empty;
        List<Token> tokens = Tokenize(command);
        if (tokens.Count == 0 || !IsPowerShellExecutable(tokens[0].Value))
            return false;

        arguments = command[tokens[0].End..].Trim();
        return arguments.Length > 0;
    }

    /// <summary>
    /// Extracts the script from the arguments of a powershell/pwsh invocation.
    /// Returns null when no script can be derived (caller keeps the original command).
    /// </summary>
    private static string? ResolveScriptFromArguments(string arguments)
    {
        List<Token> tokens = Tokenize(arguments);

        for (int i = 0; i < tokens.Count; i++)
        {
            string token = tokens[i].Value;
            if (token.Length == 0)
                continue;

            // A positional argument is implicitly -Command.
            if (!token.StartsWith('-'))
                return ArgumentValue(arguments, tokens[i]);

            switch (token.ToLowerInvariant())
            {
                case "-command":
                case "-c":
                    return i + 1 < tokens.Count ? ArgumentValue(arguments, tokens[i + 1]) : null;

                case "-encodedcommand":
                case "-enc":
                    return i + 1 < tokens.Count ? DecodeBase64Command(tokens[i + 1].Value) : null;

                case "-file":
                case "-f":
                    return i + 1 < tokens.Count ? ToScriptPathCall(tokens[i + 1].Value) : null;

                // Switches that consume the next token.
                case "-executionpolicy":
                case "-ep":
                case "-windowstyle":
                case "-inputformat":
                case "-outputformat":
                case "-configurationname":
                case "-version":
                case "-psconsolefile":
                    i++;
                    break;

                // Other switches (-NoProfile, -NonInteractive, -Sta, -NoLogo, …) are irrelevant here.
                default:
                    break;
            }
        }
        return null;
    }

    /// <summary>
    /// Text of an argument: the tokenizer already removed the double quotes, so use its
    /// value when the argument was quoted and the raw remainder otherwise. Single quotes
    /// are preserved because PowerShell treats them as string literals.
    /// </summary>
    private static string ArgumentValue(string arguments, Token token) =>
        token.Start < arguments.Length && arguments[token.Start] == '"'
            ? token.Value
            : arguments[token.Start..].Trim();

    private static string? DecodeBase64Command(string encoded)
    {
        try
        {
            return Encoding.Unicode.GetString(Convert.FromBase64String(encoded)).Trim();
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string ToScriptPathCall(string path) => $"& '{path.Replace("'", "''")}'";

    // ── Tokenizing ───────────────────────────────────────────────────────────

    /// <summary>A whitespace-separated argument with its span in the original text.</summary>
    private readonly record struct Token(string Value, int Start, int End);

    /// <summary>
    /// Splits a Windows command line into arguments. Double quotes group text and are
    /// removed from <see cref="Token.Value"/>; single quotes are left untouched because
    /// they carry PowerShell string literals inside the rule.
    /// </summary>
    private static List<Token> Tokenize(string text)
    {
        List<Token> tokens = [];
        int i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && char.IsWhiteSpace(text[i]))
                i++;
            if (i >= text.Length)
                break;

            int start = i;
            if (text[i] == '"')
            {
                i++;
                StringBuilder value = new();
                while (i < text.Length && text[i] != '"')
                {
                    // cmd.exe/CommandLineToArgvW treat \" inside a quoted argument as a literal quote.
                    if (text[i] == '\\' && i + 1 < text.Length && text[i + 1] == '"')
                    {
                        value.Append('"');
                        i += 2;
                        continue;
                    }
                    value.Append(text[i++]);
                }
                if (i < text.Length)
                    i++; // closing quote
                tokens.Add(new Token(value.ToString(), start, i));
            }
            else
            {
                while (i < text.Length && !char.IsWhiteSpace(text[i]))
                    i++;
                tokens.Add(new Token(text[start..i], start, i));
            }
        }
        return tokens;
    }

    private static string Unquote(string value)
    {
        if (value.Length < 2)
            return value;

        return value[0] == '"' && value[^1] == '"' ? value[1..^1] : value;
    }

    // ── Executable detection ─────────────────────────────────────────────────

    private static bool IsPowerShellExecutable(string token) =>
        IsExecutable(token, "powershell") || IsExecutable(token, "pwsh");

    private static bool IsExecutable(string token, string name)
    {
        string fileName = Unquote(token);
        int separator  = fileName.LastIndexOfAny(['\\', '/']);
        if (separator >= 0)
            fileName = fileName[(separator + 1)..];

        return fileName.Equals(name, StringComparison.OrdinalIgnoreCase)
            || fileName.Equals($"{name}.exe", StringComparison.OrdinalIgnoreCase);
    }
}
