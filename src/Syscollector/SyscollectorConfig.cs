using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Syscollector;

public sealed class SyscollectorConfig
{
    private const string DefaultConfigFileName = "config.yml";

    [YamlMember(Alias = "output_dir")]
    public string? OutputDir { get; set; }

    [YamlMember(Alias = "report_file")]
    public string? ReportFile { get; set; }

    [YamlMember(Alias = "log_file")]
    public string? LogFile { get; set; }

    [YamlMember(Alias = "timeout_seconds")]
    public double? TimeoutSeconds { get; set; }

    [YamlMember(Alias = "max_cache_age_days")]
    public double? MaxCacheAgeDays { get; set; }

    public static SyscollectorConfig LoadConfig(string? configPath)
    {
        string? actualPath = !string.IsNullOrEmpty(configPath)
            ? configPath
            : File.Exists(DefaultConfigFileName) ? DefaultConfigFileName : null;

        if (actualPath is null)
            return new SyscollectorConfig();

        if (!File.Exists(actualPath))
            return new SyscollectorConfig();

        try
        {
            string yaml = File.ReadAllText(actualPath);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();

            return deserializer.Deserialize<SyscollectorConfig>(yaml) ?? new SyscollectorConfig();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse config file '{actualPath}': {ex.Message}", ex);
        }
    }

    public static void WriteTemplate(string? outputPath)
    {
        string targetPath = string.IsNullOrEmpty(outputPath) ? DefaultConfigFileName : outputPath;
        const string template = """
            # Syscollector Configuration File
            # Uncomment and modify values as needed
            # All values are optional; CLI arguments always override config file settings

            # Root directory for default artifacts (default: REPORTS_DIR or ./results)
            # output_dir: results

            # Report and Log File Outputs
            # report_file: patches.json
            # log_file: patches.log

            # Collection Settings
            # timeout_seconds: 300
            # max_cache_age_days: 7
            """;

        try
        {
            File.WriteAllText(targetPath, template + Environment.NewLine);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to write config template to '{targetPath}': {ex.Message}", ex);
        }
    }
}
