using Microsoft.Extensions.Configuration;
using static Activout.Extensions.Configuration.Kdbx.Tests.TestData;

namespace Activout.Extensions.Configuration.Kdbx.Tests;

public class FormatTests
{
    [Fact]
    public void Kdbx4_Argon2d_Aes256()
    {
        var config = Load("SimplePasswordV4.kdbx", o => o.Password = "password123");

        Assert.Equal(new Dictionary<string, string?>
        {
            ["test"] = "Password",
            ["test:UserName"] = "Username",
            ["test:Url"] = "https://example.com",
        }, Flatten(config));
    }

    [Fact]
    public void Kdbx4_Argon2id_ChaCha20()
    {
        var config = Load("Argon2id-ChaCha20.kdbx", o => o.Password = "password123");

        Assert.Equal(new Dictionary<string, string?> { ["Secret"] = "SomeSecretValue" }, Flatten(config));
    }

    [Fact]
    public void Kdbx4_Argon2d_Twofish()
    {
        var config = Load("Argon2d-Twofish.kdbx", o => o.Password = "password123");

        Assert.Equal(new Dictionary<string, string?> { ["Secret"] = "SomeSecretValue" }, Flatten(config));
    }

    [Fact]
    public void Kdbx31_AesKdf_ChaCha20()
    {
        var config = Load("SimplePasswordV3_ChaCha20.kdbx", o => o.Password = "password123");

        Assert.Equal(new Dictionary<string, string?>
        {
            ["Group1:Entry1"] = "password",
            ["Group1:Entry1:UserName"] = "username",
        }, Flatten(config));
    }

    [Fact]
    public void KeyFileOnly()
    {
        var config = Load("keyfile-only.kdbx", o => o.KeyFilePath = PathOf("keyfile.keyx"));

        Assert.Equal("kf-secret", config["Service"]);
    }

    [Fact]
    public void PasswordAndKeyFile()
    {
        var config = Load("password-and-keyfile.kdbx", o =>
        {
            o.Password = "combo-pw";
            o.KeyFilePath = PathOf("keyfile.keyx");
        });

        Assert.Equal("combo-secret", config["Service"]);
    }

    [Fact]
    public void PasswordWithoutKeyFile_IsWrongKey()
    {
        var ex = Assert.Throws<InvalidDataException>(() => Load("password-and-keyfile.kdbx", o => o.Password = "combo-pw"));
        Assert.IsType<KdbxAuthenticationException>(ex.InnerException);
    }

    [Theory]
    [InlineData("SimplePasswordV4.kdbx")]
    [InlineData("mapping.kdbx")]
    public void WrongPassword_ThrowsAuthenticationException(string file)
    {
        var ex = Assert.Throws<InvalidDataException>(() => Load(file, o => o.Password = "wrong"));
        Assert.IsType<KdbxAuthenticationException>(ex.InnerException);
    }

    [Fact]
    public void Stream()
    {
        using var stream = File.OpenRead(PathOf("mapping.kdbx"));
        var config = new ConfigurationBuilder().AddKdbxStream(stream, o => o.Password = "mapping-pw").Build();

        Assert.Equal("top-secret", config["TopLevel"]);
    }

    [Fact]
    public void Stream_WrongPassword_ThrowsAuthenticationException()
    {
        using var stream = File.OpenRead(PathOf("mapping.kdbx"));
        var builder = new ConfigurationBuilder().AddKdbxStream(stream, o => o.Password = "wrong");

        Assert.Throws<KdbxAuthenticationException>(() => builder.Build());
    }

    [Fact]
    public void PasswordProvider_TakesPrecedence_AndIsCalledOnEveryLoad()
    {
        int calls = 0;
        var config = Load("mapping.kdbx", o =>
        {
            o.Password = "wrong";
            o.PasswordProvider = () => { calls++; return "mapping-pw"; };
        });
        config.Reload();

        Assert.Equal("top-secret", config["TopLevel"]);
        Assert.Equal(2, calls);
    }

    [Fact]
    public void NoMasterKey_ThrowsWhenBuilt()
    {
        var builder = new ConfigurationBuilder().AddKdbxFile(PathOf("mapping.kdbx"), _ => { });

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void MissingFile_Optional_IsEmpty()
    {
        var config = new ConfigurationBuilder()
            .AddKdbxFile(PathOf("missing.kdbx"), optional: true, reloadOnChange: false, o => o.Password = "x")
            .Build();

        Assert.Empty(Flatten(config));
    }

    [Fact]
    public void MissingFile_Required_Throws()
    {
        Assert.Throws<FileNotFoundException>(() => Load("missing.kdbx", o => o.Password = "x"));
    }
}
