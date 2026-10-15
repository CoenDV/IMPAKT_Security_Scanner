using System.Diagnostics;
using System.Text;

namespace Syscollector;

public sealed record CommandResult(int ExitCode, string Output, string Error);

public interface ICommandRunner
{
    bool Exists(string executable);
    Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout);
    DateTimeOffset? GetMetadataTimestampUtc(string packageManager) => null;
}

public sealed class CommandRunner : ICommandRunner
{
    public bool Exists(string executable)
    {
        if (Path.IsPathRooted(executable)) return File.Exists(executable);
        return (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
            .Any(directory => File.Exists(Path.Combine(directory, executable)));
    }

    public DateTimeOffset? GetMetadataTimestampUtc(string packageManager)
    {
        string[] candidateDirs = packageManager switch
        {
            "apt" => ["/var/lib/apt/lists", "/var/cache/apt"],
            "dnf" => ["/var/cache/dnf", "/var/lib/dnf"],
            _ => []
        };

        DateTimeOffset? latest = null;
        foreach (string dir in candidateDirs)
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    string name = Path.GetFileName(file);
                    if (name == "lock" || name.StartsWith("partial", StringComparison.Ordinal)) continue;
                    DateTimeOffset writeTime = File.GetLastWriteTimeUtc(file);
                    if (latest is null || writeTime > latest)
                        latest = writeTime;
                }
            }
            catch
            {
                // Best effort: ignore inaccessible cache subdirectories.
            }
        }
        return latest;
    }

    public async Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        var start = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        start.Environment["LC_ALL"] = "C";
        start.Environment["LANG"] = "C";
        using var process = new Process { StartInfo = start };
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(stdout, stderr);
            throw new TimeoutException($"{executable} exceeded the {timeout.TotalSeconds:0}s timeout.");
        }
        return new CommandResult(process.ExitCode, await stdout, await stderr);
    }
}
