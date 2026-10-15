using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Compliance_Scanner;

/// <summary>
/// Configuration object for Compliance_Scanner settings, deserialized from YAML config files.
/// All properties are optional; null values indicate no override from config file.
/// </summary>
public class ScannerConfig
{
    // ── Display Settings ──────────────────────────────────────────────────

    /// <summary>Output verbosity level: "standard", "detailed", or "compact".</summary>
    [YamlMember(Alias = "output_level")]
    public string? OutputLevelString { get; set; }

    /// <summary>Parsed OutputLevel from output_level string.</summary>
    [YamlIgnore]
    public Compliance_Scanner.OutputLevel? OutputLevel => ParseOutputLevel(OutputLevelString);

    /// <summary>Root directory for default scanner artifacts.</summary>
    [YamlMember(Alias = "output_dir")]
    public string? OutputDir { get; set; }

    // ── Report File Outputs ───────────────────────────────────────────────

    /// <summary>Path to log file for detailed output.</summary>
    [YamlMember(Alias = "log_file")]
    public string? LogFile { get; set; }

    /// <summary>Path to the JSON report file.</summary>
    [YamlMember(Alias = "report_file")]
    public string? ReportFile { get; set; }

    /// <summary>
    /// Creates a default (empty) config object.
    /// </summary>
    public static ScannerConfig CreateDefault() => new();

    /// <summary>
    /// Loads configuration from a YAML file. Returns empty config if file doesn't exist.
    /// </summary>
    /// <param name="path">Path to YAML config file.</param>
    /// <returns>Loaded config or empty config if file not found.</returns>
    /// <exception cref="InvalidOperationException">If YAML deserialization fails.</exception>
    public static ScannerConfig LoadFromFile(string path)
    {
        if (!File.Exists(path))
            return CreateDefault();

        try
        {
            string yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();

            return deserializer.Deserialize<ScannerConfig>(yaml) ?? CreateDefault();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse config file '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Writes a template configuration file with all available options and comments.
    /// </summary>
    /// <param name="path">Path where to write the template file.</param>
    public static void WriteTemplate(string path)
    {
        string template = @"# Compliance_Scanner Configuration File
# Uncomment and modify values as needed
# All values are optional; CLI arguments always override config file settings

# Display Settings
# output_level can be: standard | detailed | compact
# output_level: standard
# output_dir: results

# Report File Outputs
# Paths can be relative or absolute. If omitted, reports are written to REPORTS_DIR
# or ./results/.
# log_file: scan-results.log
# report_file: scan-results.json

";

        try
        {
            File.WriteAllText(path, template);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to write config template to '{path}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Parses output level string to OutputLevel enum.
    /// </summary>
    private static Compliance_Scanner.OutputLevel? ParseOutputLevel(string? level)
    {
        if (level is null)
            return null;

        return level.ToLower() switch
        {
            "standard" => Compliance_Scanner.OutputLevel.Standard,
            "detailed" => Compliance_Scanner.OutputLevel.Detailed,
            "compact" => Compliance_Scanner.OutputLevel.Compact,
            _ => throw new ArgumentException($"Invalid output_level in config: '{level}'. Must be one of: standard, detailed, compact")
        };
    }
}
