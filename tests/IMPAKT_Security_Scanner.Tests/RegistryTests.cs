using Compliance_Scanner;
using Microsoft.Win32;

namespace IMPAKT_Security_Scanner.Tests;

/// <summary>
/// Registry rule behaviour. The value formatting test runs everywhere; the registry
/// lookups only run on Windows (CI covers that runner).
/// </summary>
public class RegistryTests
{
    [Fact]
    public void MultiStringValueIsRenderedAsSeparateLines()
    {
        string formatted = RuleChecker.FormatRegistryValue(new[] { "first", "second" });

        Assert.Equal($"first{Environment.NewLine}second", formatted);
    }

    [Fact]
    public void BinaryValueIsRenderedAsHex()
    {
        Assert.Equal("DEADBEEF", RuleChecker.FormatRegistryValue(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));
    }

    [Fact]
    public void OtherValueTypesUseTheirInvariantText()
    {
        Assert.Equal("4", RuleChecker.FormatRegistryValue(4));
        Assert.Equal(string.Empty, RuleChecker.FormatRegistryValue(null));
    }

    [Fact]
    public void MissingRegistryKeyFailsInsteadOfBecomingInvalid()
    {
        if (!OperatingSystem.IsWindows())
            return; // registry checks are unsupported off Windows

        var check = new Check
        {
            Id = 1,
            Condition = "all",
            Rules = [@"r:HKEY_LOCAL_MACHINE\SOFTWARE\IMPAKT-UnitTest-DoesNotExist -> Value -> r:anything"]
        };

        CheckResult result = RuleChecker.EvaluateCheck(check, null);

        Assert.Equal(CheckStatus.Failed, result.Status);
        Assert.False(result.RuleResults[0].Invalid);
        Assert.Contains("not found", result.RuleResults[0].Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ContentCheckMatchesInsideMultiStringValue()
    {
        if (!OperatingSystem.IsWindows())
            return; // registry checks are unsupported off Windows

        const string subKey = @"Software\IMPAKT_Security_Scanner_Tests\MultiString";
        try
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(subKey)!)
            {
                key.SetValue("Paths",
                    new[] { @"System\CurrentControlSet\Control\Print\Printers", @"Software\Microsoft\OLAP Server" },
                    RegistryValueKind.MultiString);
            }

            var check = new Check
            {
                Id = 2,
                Condition = "all",
                Rules = [@"r:HKEY_CURRENT_USER\Software\IMPAKT_Security_Scanner_Tests\MultiString -> Paths -> r:OLAP Server"]
            };

            CheckResult result = RuleChecker.EvaluateCheck(check, null);

            Assert.Equal(CheckStatus.Passed, result.Status);
            Assert.Contains("OLAP Server", result.RuleResults[0].Detail);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\IMPAKT_Security_Scanner_Tests", throwOnMissingSubKey: false);
        }
    }
}
