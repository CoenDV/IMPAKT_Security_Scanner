using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Syscollector;

public sealed class UpdateCollector(ICommandRunner runner, TimeSpan timeout, TimeSpan? maxCacheAge = null)
{
    private readonly TimeSpan cacheMaxAge = maxCacheAge ?? TimeSpan.FromDays(7);

    public async Task<SystemReport> CollectAsync(string platform)
    {
        // Collect independently: keep installed evidence even if the update service fails.
        var installed = await CollectSectionAsync(platform, installed: true);
        var available = await CollectSectionAsync(platform, installed: false);
        return new SystemReport("1.0", Environment.MachineName,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            DateTimeOffset.UtcNow, installed, available);
    }

    private async Task<CollectionSection> CollectSectionAsync(string platform, bool installed)
    {
        string source = platform;
        string scope = installed ? "Installed updates" : "Available updates";
        try
        {
            if (platform == "windows")
            {
                source = "Windows Update Agent";
                scope = installed ? "Installed software updates known to the local Windows Update Agent store; excludes superseded updates by default."
                    : "Applicable, non-hidden software updates from the configured Windows Update service (including WSUS).";
                string criteria = installed ? "IsInstalled=1 and Type='Software'" : "IsInstalled=0 and IsHidden=0 and Type='Software'";
                string onlineSetting = installed ? "$searcher.Online = $false\n" : "";
                string script = """
                    $ErrorActionPreference = 'Stop'
                    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $session.ClientApplicationID = 'IMPAKT Syscollector'
                    $searcher = $session.CreateUpdateSearcher()
                    """ + "\n" + onlineSetting + $"$result = $searcher.Search(\"{criteria}\")\n" + """
                    if ([int]$result.ResultCode -ne 2) { throw "Windows Update search incomplete (ResultCode=$($result.ResultCode))" }
                    $items = @($result.Updates | ForEach-Object {
                        [PSCustomObject]@{
                            Id = $_.Identity.UpdateID
                            Name = $_.Title
                            Version = [string]$_.Identity.RevisionNumber
                            KnowledgeBaseIds = @($_.KBArticleIDs | ForEach-Object { "KB$_" })
                        }
                    })
                    ConvertTo-Json -InputObject $items -Depth 5 -Compress
                    """;
                string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
                var result = await Run(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(script))]);
                var items = JsonSerializer.Deserialize<List<UpdateItem>>(result.Output,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? throw new FormatException("Windows Update returned null instead of an update list.");
                return Success(source, scope, items, result);
            }
            if (platform == "macos")
            {
                if (installed)
                {
                    source = "system_profiler SPInstallHistoryDataType";
                    scope = "macOS installation history, including older versions and third-party installer receipts; does not prove a package is still installed.";
                    var result = await Run("/usr/sbin/system_profiler", ["SPInstallHistoryDataType", "-json"]);
                    return Success(source, scope, ParseMacHistory(result.Output), result);
                }
                source = "softwareupdate --list";
                scope = "Updates offered by Apple Software Update; excludes Homebrew and third-party application updaters.";
                var available = await Run("/usr/sbin/softwareupdate", ["--list"]);
                return Success(source, scope, ParseMacAvailable(available.Output + "\n" + available.Error), available);
            }
            if (platform == "linux")
            {
                if (runner.Exists("dpkg-query") && runner.Exists("apt"))
                {
                    source = installed ? "dpkg-query" : "apt list --upgradable";
                    scope = installed ? "Currently installed Debian packages and versions; not a patch installation history."
                        : "Upgradeable Debian packages from the local APT indexes; indexes are not refreshed by Syscollector.";
                    var result = installed
                        ? await Run("dpkg-query", ["-W", "-f=${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\n"])
                        : await Run("apt", ["list", "--upgradable"]);
                    return Success(source, scope, installed ? ParseDpkg(result.Output) : ParseApt(result.Output), result,
                        installed ? null : runner.GetMetadataTimestampUtc("apt"));
                }
                if (runner.Exists("rpm") && runner.Exists("dnf"))
                {
                    source = installed ? "rpm -qa" : "dnf --cacheonly check-update";
                    scope = installed ? "Currently installed RPM packages and versions; not a patch installation history."
                        : "Upgradeable RPM packages from the local DNF cache; metadata is not refreshed by Syscollector.";
                    var result = installed
                        ? await Run("rpm", ["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"])
                        : await Run("dnf", ["--cacheonly", "-q", "check-update"], 0, 100);
                    var items = installed ? ParseRpm(result.Output) : ParseDnf(result.Output);
                    if (!installed && result.ExitCode == 100 && items.Count == 0)
                        throw new FormatException("DNF reports updates but returned no recognizable package rows.");
                    return Success(source, scope, items, result,
                        installed ? null : runner.GetMetadataTimestampUtc("dnf"));
                }
                throw new PlatformNotSupportedException("Supported Linux package managers: APT/dpkg and DNF/RPM.");
            }
            throw new PlatformNotSupportedException($"Unsupported platform: {platform}");
        }
        catch (Exception ex)
        {
            return new CollectionSection(source, scope, "error", [], ex.Message);
        }
    }

    private async Task<CommandResult> Run(string command, string[] arguments, params int[] successCodes)
    {
        var result = await runner.RunAsync(command, arguments, timeout);
        if (!(successCodes.Length == 0 ? result.ExitCode == 0 : successCodes.Contains(result.ExitCode)))
            throw new InvalidOperationException($"{command} exited with code {result.ExitCode}: {result.Error.Trim()} {result.Output.Trim()}");
        return result;
    }

    private CollectionSection Success(string source, string scope, IReadOnlyList<UpdateItem> items, CommandResult result,
        DateTimeOffset? metadataTimestampUtc = null)
    {
        bool? isStale = null;
        var diagnostics = new List<string>();
        if (!string.IsNullOrWhiteSpace(result.Error))
            diagnostics.Add(result.Error.Trim());

        if (metadataTimestampUtc.HasValue)
        {
            TimeSpan age = DateTimeOffset.UtcNow - metadataTimestampUtc.Value;
            isStale = age > cacheMaxAge;
            if (isStale == true)
            {
                diagnostics.Add(
                    $"Warning: Local package metadata is {(int)age.TotalDays} day(s) old (last updated {metadataTimestampUtc.Value:yyyy-MM-ddTHH:mm:ssZ}); available update list may be outdated.");
            }
        }

        string? combinedDiagnostics = diagnostics.Count > 0 ? string.Join("\n", diagnostics) : null;
        return new(source, scope, "success", items, Diagnostics: combinedDiagnostics,
            MetadataTimestampUtc: metadataTimestampUtc, IsMetadataStale: isStale);
    }

    public static List<UpdateItem> ParseDpkg(string output)
    {
        var items = new List<UpdateItem>();
        foreach (string line in Lines(output))
        {
            var fields = line.Split('\t');
            if (fields[0] != "installed") continue;
            if (fields.Length != 4) throw new FormatException($"Unexpected dpkg-query row: {line}");
            items.Add(new(fields[1], fields[1], fields[2], fields[3]));
        }
        return items;
    }

    public static List<UpdateItem> ParseRpm(string output) => Lines(output).Select(line =>
    {
        var fields = line.Split('\t');
        if (fields.Length != 3) throw new FormatException($"Unexpected RPM row: {line}");
        return new UpdateItem($"{fields[0]}.{fields[2]}", fields[0], fields[1], fields[2]);
    }).ToList();

    public static List<UpdateItem> ParseApt(string output)
    {
        var items = new List<UpdateItem>();
        foreach (string line in Lines(output))
        {
            if (line.StartsWith("Listing", StringComparison.Ordinal)) continue;
            var match = Regex.Match(line, @"^(?<name>[^/\s]+)/\S+\s+(?<version>\S+)\s+(?<arch>\S+)\s+\[upgradable from:");
            if (!match.Success) throw new FormatException($"Unexpected APT row: {line}");
            string name = match.Groups["name"].Value;
            items.Add(new(name, name, match.Groups["version"].Value, match.Groups["arch"].Value));
        }
        if (items.Count == 0 && !output.Contains("Listing", StringComparison.Ordinal))
            throw new FormatException("APT returned no recognizable listing.");
        return items;
    }

    public static List<UpdateItem> ParseDnf(string output)
    {
        var items = new List<UpdateItem>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        bool inObsoletingSection = false;

        foreach (string rawLine in output.Replace("\r\n", "\n").Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(rawLine)) continue;
            string trimmed = rawLine.Trim();

            if (trimmed.Equals("Obsoleting Packages", StringComparison.OrdinalIgnoreCase))
            {
                inObsoletingSection = true;
                continue;
            }

            if (trimmed.StartsWith("Last metadata expiration check:", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("Security:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Under "Obsoleting Packages", DNF indents the currently installed package being replaced.
            if (inObsoletingSection && (rawLine.StartsWith(' ') || rawLine.StartsWith('\t')))
            {
                continue;
            }

            var match = Regex.Match(trimmed, @"^(?<name>\S+)\.(?<arch>\S+)\s+(?<version>\S+)\s+(?<repo>\S+)\s*$");
            if (!match.Success) throw new FormatException($"Unexpected DNF row: {trimmed}");

            string id = $"{match.Groups["name"].Value}.{match.Groups["arch"].Value}";
            string version = match.Groups["version"].Value;
            if (seen.Add($"{id}@{version}"))
            {
                items.Add(new(id, match.Groups["name"].Value, version, match.Groups["arch"].Value));
            }
        }
        return items;
    }

    public static List<UpdateItem> ParseMacHistory(string output)
    {
        using var json = JsonDocument.Parse(output);
        return json.RootElement.GetProperty("SPInstallHistoryDataType").EnumerateArray().Select(item =>
            new UpdateItem(item.GetProperty("_name").GetString()!, item.GetProperty("_name").GetString()!,
                Optional(item, "install_version"), InstalledOn: Optional(item, "install_date"))).ToList();
    }

    public static List<UpdateItem> ParseMacAvailable(string output)
    {
        var items = new List<UpdateItem>();
        var matches = Regex.Matches(output, @"(?m)^\s*[*-]\s+Label:\s*(?<label>.+)\r?$");
        for (int i = 0; i < matches.Count; i++)
        {
            var label = matches[i];
            int end = i + 1 < matches.Count ? matches[i + 1].Index : output.Length;
            string details = output[(label.Index + label.Length)..end];
            var title = Regex.Match(details, @"Title:\s*(?<title>.+?), Version:\s*(?<version>[^,\r\n]+)");
            if (!title.Success) throw new FormatException($"Unrecognized softwareupdate details for {label.Groups["label"].Value}.");
            items.Add(new(label.Groups["label"].Value.Trim(), title.Groups["title"].Value.Trim(), title.Groups["version"].Value.Trim()));
        }
        if (items.Count == 0 && !output.Contains("No new software available", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("softwareupdate returned neither an update list nor an explicit 'No new software available' result.");
        return items;
    }

    private static IEnumerable<string> Lines(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string? Optional(JsonElement item, string name) =>
        item.TryGetProperty(name, out var value) ? value.GetString() : null;
}
