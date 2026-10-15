using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Sftp_Uploader;

public sealed class SftpConfig
{
    private const string DefaultConfigFileName = "sftp-config.yml";

    [YamlMember(Alias = "host")]
    public string? Host { get; set; }

    [YamlMember(Alias = "port")]
    public int Port { get; set; } = 22;

    [YamlMember(Alias = "user")]
    public string? User { get; set; }

    [YamlMember(Alias = "key_path")]
    public string? KeyPath { get; set; }

    [YamlMember(Alias = "remote_path")]
    public string RemotePath { get; set; } = "/";

    [YamlMember(Alias = "host_key_sha256")]
    public string? HostKeySha256 { get; set; }

    [YamlMember(Alias = "log_file")]
    public string? LogFile { get; set; }

    [YamlIgnore]
    public string? Password { get; set; }

    [YamlIgnore]
    public bool Enabled => !string.IsNullOrWhiteSpace(Host);

    public static SftpConfig LoadFromFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Config file not found: {path}");

        try
        {
            string yaml = File.ReadAllText(path);
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();

            return deserializer.Deserialize<SftpConfig>(yaml) ?? new SftpConfig();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse YAML config file '{path}': {ex.Message}", ex);
        }
    }

    public static void WriteTemplate(string? outputPath)
    {
        string targetPath = string.IsNullOrEmpty(outputPath) ? DefaultConfigFileName : outputPath;
        const string template = """
            # Sftp_Uploader Configuration File
            # Uncomment and modify values as needed
            # CLI arguments and environment variables override config file settings

            host: sftp.example.com
            port: 22
            user: report-uploader
            key_path: /path/to/private/key
            host_key_sha256: SHA256:replace-with-server-fingerprint
            remote_path: /reports
            # log_file: results/sftp-upload.log
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

    public void Validate()
    {
        if (!Enabled) throw new ArgumentException("Specify --host or host in the YAML config file.");
        if (Port is < 1 or > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(User)) throw new ArgumentException("Specify --user or SFTP_USER.");
        if (string.IsNullOrWhiteSpace(Password) && string.IsNullOrWhiteSpace(KeyPath))
            throw new ArgumentException("Specify --key or set SFTP_PASS.");
        if (KeyPath is not null && !File.Exists(KeyPath))
            throw new ArgumentException($"Private key not found: {KeyPath}");
        if (string.IsNullOrWhiteSpace(RemotePath) || !RemotePath.StartsWith('/'))
            throw new ArgumentException("Remote path must be an absolute SFTP directory path.");
        if (HostKeySha256 is null || !HostKeySha256.StartsWith("SHA256:", StringComparison.Ordinal))
            throw new ArgumentException("Specify --host-key SHA256:<fingerprint> or SFTP_HOST_KEY.");
        try
        {
            byte[] fingerprint = Convert.FromBase64String(HostKeySha256[7..].PadRight(44, '='));
            if (fingerprint.Length != 32)
                throw new FormatException();
            HostKeySha256 = "SHA256:" + Convert.ToBase64String(fingerprint).TrimEnd('=');
        }
        catch (FormatException)
        {
            throw new ArgumentException("Host key must contain a valid SHA256 fingerprint.");
        }
    }
}
