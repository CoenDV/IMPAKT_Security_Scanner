using Sftp_Uploader;

namespace IMPAKT_Security_Scanner.Tests;

public class SftpConfigTests
{
    [Fact]
    public void RequiresTrustedServerFingerprint()
    {
        var config = Valid();
        config.HostKeySha256 = null;
        Assert.Throws<ArgumentException>(config.Validate);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void RejectsInvalidPort(int port)
    {
        var config = Valid();
        config.Port = port;
        Assert.Throws<ArgumentException>(config.Validate);
    }

    [Fact]
    public void RequiresAuthentication()
    {
        var config = Valid();
        config.Password = null;
        Assert.Throws<ArgumentException>(config.Validate);
    }

    [Fact]
    public void NormalizesPaddedFingerprint()
    {
        var config = Valid();
        config.HostKeySha256 = "SHA256:" + Convert.ToBase64String(new byte[32]);
        config.Validate();
        Assert.DoesNotContain("=", config.HostKeySha256);
    }

    [Fact]
    public void LoadsYamlConfigurationAndWritesTemplate()
    {
        string path = Path.GetTempFileName();
        try
        {
            SftpConfig.WriteTemplate(path);
            SftpConfig templateConfig = SftpConfig.LoadFromFile(path);
            Assert.Equal("sftp.example.com", templateConfig.Host);
            Assert.Equal(22, templateConfig.Port);
            Assert.Equal("/reports", templateConfig.RemotePath);
        }
        finally { File.Delete(path); }
    }

    private static SftpConfig Valid() => new()
    {
        Host = "localhost", User = "test", Password = "test-password",
        HostKeySha256 = "SHA256:" + Convert.ToBase64String(new byte[32]).TrimEnd('=')
    };
}
