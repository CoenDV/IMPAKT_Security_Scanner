namespace Syscollector;

public sealed record UpdateItem(string Id, string Name, string? Version = null,
    string? Architecture = null, string? InstalledOn = null, string[]? KnowledgeBaseIds = null);

public sealed record CollectionSection(string Source, string Scope, string Status,
    IReadOnlyList<UpdateItem> Items, string? Error = null, string? Diagnostics = null,
    DateTimeOffset? MetadataTimestampUtc = null, bool? IsMetadataStale = null);

public sealed record SystemReport(string SchemaVersion, string ComputerName, string OperatingSystem,
    DateTimeOffset CollectedAtUtc, CollectionSection Installed, CollectionSection Available);
