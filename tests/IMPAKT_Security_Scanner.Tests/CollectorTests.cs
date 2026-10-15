using System.Text;
using Syscollector;

namespace IMPAKT_Security_Scanner.Tests;

public class CollectorTests
{
    [Fact]
    public async Task AptSeparatesInstalledPackagesFromAvailableVersions()
    {
        var runner = new FakeRunner(["dpkg-query", "apt"],
            new(0, "installed\topenssl\t3.0.1\tamd64\nconfig-files\tremoved-package\t1.0\tall\nnot-installed\tunknown-package\t\t\n", ""),
            new(0, "Listing...\nopenssl/stable-security 3.0.2 amd64 [upgradable from: 3.0.1]\n", "CLI warning"));
        var report = await Collector(runner).CollectAsync("linux");
        Assert.Equal("3.0.1", Assert.Single(report.Installed.Items).Version);
        Assert.Equal("3.0.2", Assert.Single(report.Available.Items).Version);
        Assert.Equal("CLI warning", report.Available.Diagnostics);
        Assert.All(runner.Calls, call => Assert.DoesNotContain("update", call.Arguments));
    }

    [Theory]
    [InlineData(0, "", 0)]
    [InlineData(100, "openssl-libs.x86_64 1:3.2.4-1.el9 updates\n", 1)]
    public async Task DnfTreatsExit100AsUpdatesAvailable(int code, string output, int count)
    {
        var runner = new FakeRunner(["rpm", "dnf"],
            new(0, "openssl-libs\t1:3.2.3-1.el9\tx86_64\n", ""), new(code, output, ""));
        var report = await Collector(runner).CollectAsync("linux");
        Assert.Equal("success", report.Available.Status);
        Assert.Equal(count, report.Available.Items.Count);
        Assert.Contains("--cacheonly", runner.Calls[1].Arguments);
    }

    [Fact]
    public async Task DnfHandlesObsoletingPackagesSectionWithoutCrashing()
    {
        string dnfOutput = """
            openssl-libs.x86_64                  1:3.2.4-1.el9                   updates
            Obsoleting Packages
            grub2-tools.x86_64                   1:2.06-70.el9                   baseos
                grub2-tools.x86_64               1:2.06-61.el9                   @anaconda
            """;
        var runner = new FakeRunner(["rpm", "dnf"],
            new(0, "openssl-libs\t1:3.2.3-1.el9\tx86_64\n", ""),
            new(100, dnfOutput, ""));
        var report = await Collector(runner).CollectAsync("linux");
        Assert.Equal("success", report.Available.Status);
        Assert.Equal(2, report.Available.Items.Count);
        Assert.Contains(report.Available.Items, item => item.Name == "openssl-libs" && item.Version == "1:3.2.4-1.el9");
        Assert.Contains(report.Available.Items, item => item.Name == "grub2-tools" && item.Version == "1:2.06-70.el9");
    }

    [Fact]
    public async Task DnfExit100WithoutPackagesIsAnError()
    {
        var runner = new FakeRunner(["rpm", "dnf"], new(0, "", ""), new(100, "", ""));
        var report = await Collector(runner).CollectAsync("linux");
        Assert.Equal("error", report.Available.Status);
    }

    [Fact]
    public async Task LinuxReportsStaleMetadataCacheWhenOlderThanThreshold()
    {
        DateTimeOffset staleTimestamp = DateTimeOffset.UtcNow.AddDays(-14);
        var runner = new FakeRunner(["dpkg-query", "apt"],
            new(0, "installed\topenssl\t3.0.1\tamd64\n", ""),
            new(0, "Listing...\n", ""))
        {
            MetadataTimestampUtc = staleTimestamp
        };
        var report = await new UpdateCollector(runner, TimeSpan.FromSeconds(1), TimeSpan.FromDays(7)).CollectAsync("linux");
        Assert.Equal("success", report.Available.Status);
        Assert.True(report.Available.IsMetadataStale);
        Assert.Equal(staleTimestamp, report.Available.MetadataTimestampUtc);
        Assert.Contains("Local package metadata is", report.Available.Diagnostics);
    }

    [Fact]
    public async Task AvailableFailurePreservesInstalledEvidence()
    {
        var runner = new FakeRunner(["dpkg-query", "apt"],
            new(0, "installed\topenssl\t3.0.1\tamd64\n", ""), new(100, "", "Repository inaccessible"));
        var report = await Collector(runner).CollectAsync("linux");
        Assert.Equal("success", report.Installed.Status);
        Assert.Single(report.Installed.Items);
        Assert.Equal("error", report.Available.Status);
        Assert.Contains("Repository inaccessible", report.Available.Error);
    }

    [Fact]
    public async Task UnsupportedLinuxDoesNotReportSuccessWithZeroUpdates()
    {
        var report = await Collector(new FakeRunner([])).CollectAsync("linux");
        Assert.Equal("error", report.Installed.Status);
        Assert.Equal("error", report.Available.Status);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("Finding available software", "Service unavailable")]
    [InlineData("Software Update found the following updates:\n* Unrecognized format", "")]
    public async Task MacDoesNotTreatEmptyOrUnexpectedOutputAsNoUpdates(string output, string error)
    {
        var runner = new FakeRunner([], new(0, "{\"SPInstallHistoryDataType\":[]}", ""), new(0, output, error));
        var report = await Collector(runner).CollectAsync("macos");
        Assert.Equal("error", report.Available.Status);
    }

    [Fact]
    public async Task MacSupportsHistoricalVersionsAndOptionalUpdates()
    {
        var runner = new FakeRunner([], new(0, """
            {"SPInstallHistoryDataType":[
              {"_name":"Security Update", "install_version":"1.0", "install_date":"2026-10-01T00:00:00Z"},
              {"_name":"Security Update", "install_version":"2.0", "install_date":"2026-10-02T00:00:00Z"}
            ]}
            """, ""), new(0, """
            Software Update Tool
            Software Update found the following new or updated software:
            * Label: Safari26.0-26.0
                Title: Safari, Version: 26.0, Size: 100KiB, Recommended: YES,
            - Label: Command Line Tools-26.0
                Title: Command Line Tools, Version: 26.0, Size: 200KiB,
            """, ""));
        var report = await Collector(runner).CollectAsync("macos");
        Assert.Equal(2, report.Installed.Items.Count);
        Assert.Equal("1.0", report.Installed.Items[0].Version);
        Assert.Equal("2.0", report.Installed.Items[1].Version);
        Assert.Equal(2, report.Available.Items.Count);
        Assert.Equal("Safari", report.Available.Items[0].Name);
    }

    [Fact]
    public async Task MacAcceptsExplicitNoUpdatesResultOnStderr()
    {
        var runner = new FakeRunner([], new(0, "{\"SPInstallHistoryDataType\":[]}", ""), new(0, "", "No new software available."));
        var report = await Collector(runner).CollectAsync("macos");
        Assert.Equal("success", report.Available.Status);
        Assert.Empty(report.Available.Items);
    }

    [Fact]
    public async Task WindowsUsesOfflineStoreForInstalledAndUpdateServiceForAvailable()
    {
        var runner = new FakeRunner([], new(0, "[]", ""), new(0,
            "[{\"Id\":\"update-id\",\"Name\":\"Security Update\",\"Version\":\"3\",\"KnowledgeBaseIds\":[\"KB123\"]}]", ""));
        var report = await Collector(runner).CollectAsync("windows");
        Assert.Equal("success", report.Installed.Status);
        Assert.Equal("KB123", Assert.Single(Assert.Single(report.Available.Items).KnowledgeBaseIds!));
        string installedScript = Decode(runner.Calls[0]);
        string availableScript = Decode(runner.Calls[1]);
        Assert.Contains("$searcher.Online = $false", installedScript);
        Assert.Contains("IsInstalled=1", installedScript);
        Assert.DoesNotContain("$searcher.Online = $false", availableScript);
        Assert.Contains("IsInstalled=0 and IsHidden=0", availableScript);
        Assert.Contains("ResultCode -ne 2", availableScript);
        Assert.DoesNotContain("ServerSelection =", availableScript);
        Assert.DoesNotContain(".Install(", availableScript);
    }

    [Fact]
    public async Task TimeoutInOneSourceDoesNotStopTheOtherSource()
    {
        var runner = new FakeRunner([], new(0, "", ""), new(0, "No new software available.", ""))
        { FailFirstWithTimeout = true };
        var report = await Collector(runner).CollectAsync("macos");
        Assert.Equal("error", report.Installed.Status);
        Assert.Contains("timeout", report.Installed.Error);
        Assert.Equal("success", report.Available.Status);
    }

    [Fact]
    public void AptRejectsChangedOutputInsteadOfReturningZeroUpdates() =>
        Assert.Throws<FormatException>(() => UpdateCollector.ParseApt("Unable to fetch package list"));

    [Fact]
    public void SyscollectorYamlConfigLoadsAndWritesTemplate()
    {
        string path = Path.GetTempFileName();
        try
        {
            SyscollectorConfig.WriteTemplate(path);
            string template = File.ReadAllText(path);
            Assert.Contains("timeout_seconds", template);
            Assert.Contains("max_cache_age_days", template);

            File.WriteAllText(path, "output_dir: custom-out\ntimeout_seconds: 120\nmax_cache_age_days: 3\n");
            SyscollectorConfig loaded = SyscollectorConfig.LoadConfig(path);
            Assert.Equal("custom-out", loaded.OutputDir);
            Assert.Equal(120, loaded.TimeoutSeconds);
            Assert.Equal(3, loaded.MaxCacheAgeDays);
        }
        finally { File.Delete(path); }
    }

    private static UpdateCollector Collector(ICommandRunner runner) => new(runner, TimeSpan.FromSeconds(1));
    private static string Decode(Call call) => Encoding.Unicode.GetString(Convert.FromBase64String(call.Arguments[^1]));

    private sealed record Call(string Executable, IReadOnlyList<string> Arguments);
    private sealed class FakeRunner(string[] executables, params CommandResult[] results) : ICommandRunner
    {
        public List<Call> Calls { get; } = [];
        public bool FailFirstWithTimeout { get; init; }
        public DateTimeOffset? MetadataTimestampUtc { get; init; }
        public bool Exists(string executable) => executables.Contains(executable);
        public DateTimeOffset? GetMetadataTimestampUtc(string packageManager) => MetadataTimestampUtc;
        public Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout)
        {
            Calls.Add(new(executable, arguments));
            if (FailFirstWithTimeout && Calls.Count == 1) throw new TimeoutException("Command timeout");
            return Task.FromResult(results[Calls.Count - 1]);
        }
    }
}
