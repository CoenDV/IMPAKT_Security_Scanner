using Compliance_Scanner;

namespace IMPAKT_Security_Scanner.Tests;

/// <summary>
/// Translation of Wazuh command rules (cmd.exe syntax) into the PowerShell script the
/// scanner executes on Windows. These are pure string transformations, so they run on
/// every platform.
/// </summary>
public class WindowsCommandTests
{
    [Fact]
    public void PowershellWithNoProfileAndCommandIsReducedToItsScript()
    {
        const string rule = """
            powershell -NoProfile -Command "[bool](Get-CimInstance -Query 'SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE ''S-1-5-21-%-501''' | Where-Object -Property Disabled)"
            """;

        Assert.Equal(
            "[bool](Get-CimInstance -Query 'SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE ''S-1-5-21-%-501''' | Where-Object -Property Disabled)",
            RuleCheckerTranslation(rule));
    }

    [Fact]
    public void CmdWrapperIsUnwrapped()
    {
        Assert.Equal(
            "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1)",
            RuleCheckerTranslation("cmd /c powershell \"(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1)\""));
    }

    [Fact]
    public void NestedCmdWrapperAndSwitchesAreUnwrapped()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("cmd.exe /d /c powershell.exe -NoProfile -Command \"Get-Date\""));
    }

    [Fact]
    public void QuotedPowershellPathWithSpacesIsRecognised()
    {
        Assert.Equal(
            "Get-Date",
            RuleCheckerTranslation("\"C:\\Program Files\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -Command \"Get-Date\""));
    }

    [Fact]
    public void SwitchWithValueIsSkipped()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("powershell -ExecutionPolicy Bypass -NoProfile -Command \"Get-Date\""));
    }

    [Fact]
    public void PositionalArgumentIsTreatedAsCommand()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("powershell \"Get-Date\""));
    }

    [Fact]
    public void SwitchesAreCaseInsensitive()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("PowerShell -NOPROFILE -COMMAND \"Get-Date\""));
    }

    [Fact]
    public void PwshIsRecognised()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("pwsh -c \"Get-Date\""));
    }

    [Fact]
    public void EncodedCommandIsDecoded()
    {
        Assert.Equal("Get-Date", RuleCheckerTranslation("powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA=="));
        Assert.Equal("Write-Output 42", RuleCheckerTranslation("powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAA0ADIA"));
    }

    [Fact]
    public void FileArgumentBecomesCallOperator()
    {
        Assert.Equal("& 'C:\\Temp\\check.ps1'", RuleCheckerTranslation("powershell -NoProfile -File C:\\Temp\\check.ps1"));
    }

    [Fact]
    public void UnquotedCommandValueKeepsWholeRemainder()
    {
        Assert.Equal("Get-HotFix | Select-Object -First 1",
            RuleCheckerTranslation("powershell -Command Get-HotFix | Select-Object -First 1"));
    }

    [Theory]
    [InlineData("secedit /export /cfg secpol.cfg")]
    [InlineData("net user Guest")]
    [InlineData("Get-Service powershell")]
    public void BareCommandsArePassedThrough(string command)
    {
        Assert.Equal(command, RuleCheckerTranslation(command));
    }

    [Fact]
    public void FullPowershellPathKeepsItsArguments()
    {
        Assert.Equal(
            "secedit /export /cfg secpol.cfg",
            RuleCheckerTranslation("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe secedit /export /cfg secpol.cfg"));
    }

    [Fact]
    public void PowershellRuleWithSwitchesExecutesOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return; // covered by CI on windows-2022

        var check = new Check
        {
            Id = 1,
            Condition = "all",
            Rules = ["c:powershell -NoProfile -Command \"'translated-ok'\" -> r:translated-ok"]
        };

        CheckResult result = RuleChecker.EvaluateCheck(check, null);
        Assert.True(result.Status == CheckStatus.Passed,
            string.Join(Environment.NewLine, result.RuleResults.Select(rule => rule.Detail)));
    }

    [Fact]
    public void CisGuestAccountRuleRunsWithoutCliXmlError()
    {
        if (!OperatingSystem.IsWindows())
            return; // covered by CI on windows-2022

        // Wazuh CIS rule as published; both True and False are accepted, the point is that
        // the command runs instead of failing on a "-NoProfile -Command" parse error.
        var check = new Check
        {
            Id = 2,
            Condition = "all",
            Rules =
            [
                "c:powershell -NoProfile -Command \"[bool](Get-CimInstance -Query 'SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE ''S-1-5-21-%-501''' | Where-Object -Property Disabled)\" -> r:(True|False)"
            ]
        };

        CheckResult result = RuleChecker.EvaluateCheck(check, null);
        Assert.True(result.Status == CheckStatus.Passed,
            string.Join(Environment.NewLine, result.RuleResults.Select(rule => rule.Detail)));
    }

    [Fact]
    public void EscapedDoubleQuotesInsideQuotedArgumentAreUnescaped()
    {
        Assert.Equal(
            "(Get-HotFix | Select-Object -First 1).InstalledOn.ToString(\"MM-dd-yyyy\")",
            RuleCheckerTranslation(
                "cmd /c powershell \"(Get-HotFix | Select-Object -First 1).InstalledOn.ToString(\\\"MM-dd-yyyy\\\")\""));
    }

    [Fact]
    public void CmdWithFullyQuotedPayloadIsUnwrapped()
    {
        Assert.Equal("echo hi", RuleCheckerTranslation("cmd /c \"echo hi\""));
    }

    private static string RuleCheckerTranslation(string command) => WindowsCommand.ToPowerShellScript(command);
}
