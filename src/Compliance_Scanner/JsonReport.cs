using System.Text.Json;
using System.Text.Json.Serialization;

namespace Compliance_Scanner;

public sealed class ComplianceReport
{
    public string SchemaVersion { get; } = "1.0";
    public string Scanner { get; } = "Compliance_Scanner";
    public string ComputerName { get; } = Environment.MachineName;
    public string OperatingSystem { get; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public required string Target { get; init; }
    public DateTimeOffset StartedAtUtc { get; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAtUtc { get; set; }
    public int ExitCode { get; set; }
    public List<PolicyDiscovery> Discovery { get; } = [];
    public List<PolicyReport> Policies { get; } = [];
    public List<string> Errors { get; } = [];
    public CheckSummary Summary => CheckSummary.From(Policies.SelectMany(policy => policy.Checks));

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    });
}

public sealed record PolicyDiscovery(string Path, bool Applicable, string Reason, string? Error = null);

public sealed class PolicyReport
{
    public required string Path { get; init; }
    public PolicyMetadata? Policy { get; set; }
    public string Status { get; set; } = "error";
    public string? Error { get; set; }
    public CheckEvidence? Requirements { get; set; }
    public List<CheckEvidence> Checks { get; } = [];
    public CheckSummary Summary => CheckSummary.From(Checks);
}

public sealed record CheckSummary(int Passed, int Failed, int Invalid, int Total)
{
    public static CheckSummary From(IEnumerable<CheckEvidence> checks)
    {
        var items = checks.ToList();
        return new(items.Count(check => check.Status == CheckStatus.Passed),
            items.Count(check => check.Status == CheckStatus.Failed),
            items.Count(check => check.Status == CheckStatus.Invalid), items.Count);
    }
}

public sealed record RuleEvidence(string Rule, bool Passed, bool Invalid, string Detail);

public sealed record CheckEvidence(int Id, string Title, string Description, string Rationale,
    string Remediation, string Condition, CheckStatus Status, string Reason, IReadOnlyList<RuleEvidence> Rules)
{
    public static CheckEvidence From(Check check, CheckResult result) =>
        new(check.Id, check.DisplayTitle, check.Description, check.Rationale, check.Remediation,
            check.Condition, result.Status, result.Reason,
            result.RuleResults.Select((rule, index) =>
                new RuleEvidence(check.Rules[index], rule.Passed, rule.Invalid, rule.Detail)).ToArray());
}
