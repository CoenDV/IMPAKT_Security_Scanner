using System.Globalization;
using System.Text;
using Sftp_Uploader;

if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
{
    Console.Error.WriteLine("""
        Sftp_Uploader — upload report files independently of the scanners
        Usage: Sftp_Uploader [options] --file <path> [--file <path> ...]
               Sftp_Uploader [options] --directory <path>
          -c, --config <path>       YAML connection configuration
          --write-config [path]     Generate a template YAML config file (default: sftp-config.yml)
          --host <host>             SFTP hostname (env: SFTP_HOST)
          --port <number>           SFTP port (default: 22)
          --user <name>             Username (env: SFTP_USER)
          --key <path>              SSH private key; password alternative: env SFTP_PASS
          --host-key <SHA256:…>     Expected server key fingerprint (env: SFTP_HOST_KEY)
          --remote-path <path>      Absolute remote directory (env: SFTP_PATH; default: /)
          -l, --log <path>          Write operational log output to a text file
          --file <path>             Repeat for individual files
          --directory <path>        All files directly inside a directory; no recursion
          --dry-run                 Validate and list files without connecting
        Existing remote files with the same name are overwritten. Partial failures return 1.
        """);
    return 0;
}

var logLines = new List<string>();
string? logFile = null;

try
{
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--write-config")
        {
            string writePath = (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                ? args[++i]
                : "sftp-config.yml";
            SftpConfig.WriteTemplate(writePath);
            Console.Error.WriteLine($"Info: Template config file created: {Path.GetFullPath(writePath)}");
            return 0;
        }
    }

    var config = new SftpConfig();
    // Load YAML config first so CLI values always override it, regardless of option order.
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config")
        {
            string path = Value(args, ref i);
            config = SftpConfig.LoadFromFile(path);
        }
    }

    logFile = config.LogFile;
    config.Host ??= Environment.GetEnvironmentVariable("SFTP_HOST");
    config.User ??= Environment.GetEnvironmentVariable("SFTP_USER");
    config.Password = Environment.GetEnvironmentVariable("SFTP_PASS");
    config.HostKeySha256 ??= Environment.GetEnvironmentVariable("SFTP_HOST_KEY");
    config.RemotePath = Environment.GetEnvironmentVariable("SFTP_PATH") ?? config.RemotePath;
    bool dryRun = false;
    var files = new List<string>();

    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-c":
            case "--config": Value(args, ref i); break;
            case "--host": config.Host = Value(args, ref i); break;
            case "--port": config.Port = int.Parse(Value(args, ref i), CultureInfo.InvariantCulture); break;
            case "--user": config.User = Value(args, ref i); break;
            case "--key": config.KeyPath = Value(args, ref i); break;
            case "--host-key": config.HostKeySha256 = Value(args, ref i); break;
            case "--remote-path": config.RemotePath = Value(args, ref i); break;
            case "-l":
            case "--log": logFile = Value(args, ref i); break;
            case "--dry-run": dryRun = true; break;
            case "--file": files.Add(Path.GetFullPath(Value(args, ref i))); break;
            case "--directory":
                files.AddRange(Directory.GetFiles(Path.GetFullPath(Value(args, ref i))).Order(StringComparer.Ordinal));
                break;
            default: throw new ArgumentException($"Unknown option: {args[i]}");
        }
    }

    config.Validate();
    files = files.Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal).ToList();
    if (files.Count == 0) throw new ArgumentException("Select at least one file to upload.");
    foreach (string file in files)
        if (!File.Exists(file)) throw new FileNotFoundException($"Local file not found: {file}");
    if (files.GroupBy(Path.GetFileName, StringComparer.Ordinal).Any(group => group.Count() > 1))
        throw new ArgumentException("Files have duplicate remote names; select files with unique filenames.");

    void Log(string message)
    {
        logLines.Add(message);
        Console.Error.WriteLine(message);
    }

    if (dryRun)
    {
        foreach (string file in files)
            Log($"{file} -> {config.Host}:{config.RemotePath.TrimEnd('/')}/{Path.GetFileName(file)}");
        return 0;
    }

    new SftpUploader().UploadFiles(config, files, Log);
    return 0;
}
catch (Exception ex)
{
    string errorMessage = $"Upload failed: {ex.Message}";
    logLines.Add(errorMessage);
    Console.Error.WriteLine(errorMessage);
    return 1;
}
finally
{
    if (!string.IsNullOrWhiteSpace(logFile))
    {
        try
        {
            string fullLogPath = Path.GetFullPath(logFile);
            string? dir = Path.GetDirectoryName(fullLogPath);
            if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
            File.WriteAllLines(fullLogPath, logLines, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to write log file '{logFile}': {ex.Message}");
        }
    }
}

static string Value(string[] arguments, ref int index)
{
    string option = arguments[index];
    if (++index >= arguments.Length || arguments[index].StartsWith('-'))
        throw new ArgumentException($"{option} requires a value.");
    return arguments[index];
}
