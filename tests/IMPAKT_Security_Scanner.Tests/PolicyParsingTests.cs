using Compliance_Scanner;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace IMPAKT_Security_Scanner.Tests;

/// <summary>
/// Policy model parsing. Wazuh 4.x policies name a check with <c>title:</c>, Wazuh 5.x
/// policies with <c>name:</c>; both must end up as the reported title.
/// </summary>
public class PolicyParsingTests
{
    [Fact]
    public void CheckNameFromWazuh5IsUsedAsTitle()
    {
        const string yaml = """
            policy:
              id: test
              file: test.yml
              name: Test policy
            checks:
              - id: 1
                name: "Ensure something is configured"
                condition: all
                rules:
                  - "f:/etc/hosts"
            """;

        Check check = Parse(yaml).Checks[0];

        Assert.Equal(string.Empty, check.Title);
        Assert.Equal("Ensure something is configured", check.DisplayTitle);
    }

    [Fact]
    public void CheckTitleFromWazuh4IsUsedAsTitle()
    {
        const string yaml = """
            policy:
              id: test
              file: test.yml
              name: Test policy
            checks:
              - id: 1
                title: "Ensure something is configured"
                condition: all
                rules:
                  - "f:/etc/hosts"
            """;

        Assert.Equal("Ensure something is configured", Parse(yaml).Checks[0].DisplayTitle);
    }

    [Fact]
    public void TitleWinsWhenBothFieldsArePresent()
    {
        const string yaml = """
            policy:
              id: test
              file: test.yml
              name: Test policy
            checks:
              - id: 1
                title: "Title value"
                name: "Name value"
                condition: all
                rules:
                  - "f:/etc/hosts"
            """;

        Assert.Equal("Title value", Parse(yaml).Checks[0].DisplayTitle);
    }

    private static SCAPolicy Parse(string yaml) =>
        new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build()
            .Deserialize<SCAPolicy>(yaml);
}
