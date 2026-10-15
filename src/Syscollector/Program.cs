using System.Globalization;
using System.Text;
using System.Text.Json;
using Syscollector;

if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
{
    Console.Error.WriteLine("""
        Syscollector — collect installed and available updates without installing them
        Usage: Syscollector [options]
          --scan                      Collect using the default output path
          --output-dir <dir>          Root for default files (default: REPORTS_DIR or ./results/)
          --output, --json, -r, --report <path>  JSON report (default: patches-<host>.json)
          -l, --log <path>            Text log file (default: patches-<host>.log)
          --timeout <seconds>         Timeout per command (default: 300)
          --max-cache-age-days <days> Max age in days for Linux metadata cache before warning (default: 7)
          -c, --config <path>         Load configuration from YAML file (default: config.yml)
          --write-config [path]       Generate a template YAML config file (default: config.yml)
        Windows: Windows Update Agent (offline for installed, configured update service for available).
        Linux: APT/dpkg or DNF/RPM; available updates use existing local metadata and report cache age.
        macOS: installation history and Apple Software Update; excludes Homebrew.
        Exit 0: both sources collected. Exit 1: error or incomplete collection; inspect JSON.
        """);
    return 0;
}

string? logFile = null;
string? reportFile = null;

try
{
    string? configPath = null;
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--write-config")
        {
            string writePath = (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                ? args[++i]
                : "config.yml";
            SyscollectorConfig.WriteTemplate(writePath);
            Console.Error.WriteLine($"Info: Template config file created: {Path.GetFullPath(writePath)}");
            return 0;
        }
        if ((args[i] == "-c" || args[i] == "--config") && i + 1 < args.Length)
        {
            configPath = args[++i];
        }
    }

    var config = SyscollectorConfig.LoadConfig(configPath);
    string outputRoot = config.OutputDir ?? GetDefaultOutputRoot();
    reportFile = config.ReportFile;
    logFile = config.LogFile;
    double seconds = config.TimeoutSeconds ?? 300;
    double maxCacheAgeDays = config.MaxCacheAgeDays ?? 7;

    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--scan": break;
            case "-c":
            case "--config":
                Value(args, ref i);
                break;
            case "--output-dir":
                outputRoot = Value(args, ref i);
                break;
            case "--output":
            case "--json":
            case "-r":
            case "--report":
                reportFile = Value(args, ref i);
                break;
            case "-l":
            case "--log":
                logFile = Value(args, ref i);
                break;
            case "--timeout":
                seconds = ParsePositiveDouble(Value(args, ref i), 86400, "Timeout must be between 0 and 86400 seconds (exclusive of zero).");
                break;
            case "--max-cache-age-days":
                maxCacheAgeDays = ParsePositiveDouble(Value(args, ref i), 3650, "Max cache age must be between 0 and 3650 days (exclusive of zero).");
                break;
            default:
                throw new ArgumentException($"Unknown option: {args[i]}");
        }
    }

    ValidatePositive(seconds, 86400, "Timeout must be between 0 and 86400 seconds (exclusive of zero).");
    ValidatePositive(maxCacheAgeDays, 3650, "Max cache age must be between 0 and 3650 days (exclusive of zero).");

    string hostName = GetSafeHostName();
    reportFile ??= Path.Combine(outputRoot, $"patches-{hostName}.json");
    logFile ??= Path.Combine(outputRoot, $"patches-{hostName}.log");

    if (!string.Equals(Path.GetExtension(reportFile), ".json", StringComparison.OrdinalIgnoreCase))
        throw new ArgumentException("The report path must have a .json extension.");
    if (string.Equals(Path.GetFullPath(logFile), Path.GetFullPath(reportFile),
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        throw new ArgumentException("Log and JSON report must use different file paths.");

    EnsureOutputDirectory(outputRoot);
    EnsureParentDirectory(reportFile);
    EnsureParentDirectory(logFile);

    string platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" : "unsupported";
    var collector = new UpdateCollector(new CommandRunner(), TimeSpan.FromSeconds(seconds), TimeSpan.FromDays(maxCacheAgeDays));
    var report = await collector.CollectAsync(platform);

    string fullReportPath = Path.GetFullPath(reportFile);
    string fullLogPath = Path.GetFullPath(logFile);
    string json = JsonSerializer.Serialize(report,
        new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    await File.WriteAllTextAsync(fullReportPath, json, Encoding.UTF8);
    Console.WriteLine(json);

    var logLines = new List<string>
    {
        $"Report: {fullReportPath}",
        $"Installed: {report.Installed.Status}, {report.Installed.Items.Count} entries ({report.Installed.Source})",
        $"Available: {report.Available.Status}, {report.Available.Items.Count} entries ({report.Available.Source})"
    };
    foreach (var section in new[] { report.Installed, report.Available })
    {
        if (section.Diagnostics is not null) logLines.Add(section.Diagnostics);
        if (section.Error is not null) logLines.Add(section.Error);
    }

    foreach (string line in logLines)
        Console.Error.WriteLine(line);
    await File.WriteAllLinesAsync(fullLogPath, logLines, Encoding.UTF8);

    return report.Installed.Status == "success" && report.Available.Status == "success" ? 0 : 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Collection failed: {ex.Message}");
    return 1;
}
finally
{
    TightenReportPermissions(logFile, reportFile);
}

static string Value(string[] arguments, ref int index)
{
    string option = arguments[index];
    if (++index >= arguments.Length || arguments[index].StartsWith('-'))
        throw new ArgumentException($"{option} requires a value.");
    return arguments[index];
}

static double ParsePositiveDouble(string raw, double max, string message)
{
    if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
        throw new ArgumentException(message);
    ValidatePositive(value, max, message);
    return value;
}

static void ValidatePositive(double value, double max, string message)
{
    if (!double.IsFinite(value) || value <= 0 || value > max)
        throw new ArgumentException(message);
}

static string GetDefaultOutputRoot()
{
    string? reportsDir = Environment.GetEnvironmentVariable("REPORTS_DIR");
    return !string.IsNullOrWhiteSpace(reportsDir) ? reportsDir : "results";
}

static string GetSafeHostName()
{
    string hostName = Environment.MachineName;
    char[] invalidChars = Path.GetInvalidFileNameChars();
    string safe = new(hostName.Select(c => invalidChars.Contains(c) ? '_' : c).ToArray());
    return string.IsNullOrWhiteSpace(safe) ? "unknown-host" : safe;
}

static void TrySetUnixMode(string path, UnixFileMode mode)
{
    if (OperatingSystem.IsWindows()) return;
    try { File.SetUnixFileMode(path, mode); } catch { /* Best effort */ }
}

static void EnsureOutputDirectory(string outputRoot)
{
    Directory.CreateDirectory(outputRoot);
    TrySetUnixMode(outputRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                               UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
}

static void EnsureParentDirectory(string filePath)
{
    string? directory = Path.GetDirectoryName(Path.GetFullPath(filePath));
    if (!string.IsNullOrWhiteSpace(directory))
        EnsureOutputDirectory(directory);
}

static void TightenReportPermissions(params string?[] filePaths)
{
    foreach (string? filePath in filePaths)
    {
        if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath))
            TrySetUnixMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                     UnixFileMode.GroupRead | UnixFileMode.OtherRead);
    }
}
