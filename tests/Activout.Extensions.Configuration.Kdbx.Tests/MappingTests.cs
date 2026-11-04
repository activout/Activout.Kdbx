using Activout.Extensions.Configuration.Kdbx.Internal;
using static Activout.Extensions.Configuration.Kdbx.Tests.TestData;

namespace Activout.Extensions.Configuration.Kdbx.Tests;

public class MappingTests
{
    // Decrypt once; each test maps the same document with different options.
    private static readonly Lazy<KdbxDocument> Mapping = new(() => Read("mapping.kdbx", "mapping-pw"));
    private static readonly Lazy<KdbxDocument> Duplicates = new(() => Read("duplicates.kdbx", "duplicates-pw"));

    private static KdbxDocument Read(string file, string password)
    {
        using var stream = File.OpenRead(PathOf(file));
        return KdbxConfigurationMapper.Read(stream, new KdbxConfigurationOptions { Password = password });
    }

    private static Dictionary<string, string?> Map(Action<KdbxConfigurationOptions>? configure = null)
    {
        var options = new KdbxConfigurationOptions();
        configure?.Invoke(options);
        return KdbxConfigurationMapper.Map(Mapping.Value, options);
    }

    [Fact]
    public void Defaults()
    {
        Assert.Equal(new Dictionary<string, string?>
        {
            ["TopLevel"] = "top-secret",
            ["Database:Main"] = "Server=db;Password=x",
            ["Database:Main:UserName"] = "app",
            ["Api:Stripe:SecretKey"] = "sk_test_123",
            ["Api:Stripe:SecretKey:Endpoint"] = "https://api.example.com",
            ["Api:Stripe:SecretKey:Token"] = "tok-protected",
            ["Empty:NoPassword:UserName"] = "only-user",
            ["Tagged:Prod"] = "p1",
            ["Tagged:Dev"] = "d1",
            ["Expiry:Expired"] = "old",
            ["Expiry:Future"] = "new",
            ["Special:A:B"] = "colon",
            ["Special:Räksmörgås & <ok>"] = "å\"ä'ö",
            ["Special:Räksmörgås & <ok>:Url"] = "https://example.com/x?y=1&z=2",
        }, Map());
    }

    [Fact]
    public void KeysAreCaseInsensitive()
    {
        Assert.Equal("app", Map()["database:main:username"]);
    }

    [Fact]
    public void KeyPrefix_And_RootGroupName()
    {
        var data = Map(o =>
        {
            o.KeyPrefix = "Secrets";
            o.IncludeRootGroupName = true;
        });

        Assert.Equal("top-secret", data["Secrets:Root:TopLevel"]);
        Assert.Equal("Server=db;Password=x", data["Secrets:Root:Database:Main"]);
    }

    [Fact]
    public void IncludeRecycleBin()
    {
        Assert.DoesNotContain("Recycle Bin:Old", Map().Keys);
        Assert.Equal("deleted", Map(o => o.IncludeRecycleBin = true)["Recycle Bin:Old"]);
    }

    [Fact]
    public void Fields()
    {
        var data = Map(o => o.Fields = KdbxFieldMapping.Notes);

        Assert.Equal(new Dictionary<string, string?>
        {
            ["Special:Räksmörgås & <ok>:Notes"] = "line1\nline2",
        }, data);
    }

    [Fact]
    public void RequiredTag()
    {
        Assert.Equal(["Tagged:Prod"], Map(o => o.RequiredTag = "WEB").Keys);
    }

    [Fact]
    public void EntryFilter_And_RequiredTag_MustBothAccept()
    {
        var seen = new List<KdbxEntryInfo>();
        var data = Map(o =>
        {
            o.RequiredTag = "prod";
            o.EntryFilter = e =>
            {
                seen.Add(e);
                return e.Title != "Prod";
            };
        });

        Assert.Empty(data);
        var prod = Assert.Single(seen);
        Assert.Equal(["Tagged"], prod.GroupPath);
        Assert.Equal(["prod", "web"], prod.Tags);
    }

    [Fact]
    public void EntryFilter_SeesExpiryTime()
    {
        var infos = new Dictionary<string, KdbxEntryInfo>();
        Map(o => o.EntryFilter = e => infos.TryAdd(e.Title, e));

        Assert.Equal(new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc), infos["Expired"].ExpiryTime);
        Assert.Null(infos["TopLevel"].ExpiryTime);
    }

    [Fact]
    public void ExcludeExpired()
    {
        var data = Map(o => o.ExcludeExpired = true);

        Assert.DoesNotContain("Expiry:Expired", data.Keys);
        Assert.Equal("new", data["Expiry:Future"]);
    }

    [Fact]
    public void DuplicateKeys_Throw_NamingBothEntries()
    {
        var ex = Assert.Throws<FormatException>(() =>
            KdbxConfigurationMapper.Map(Duplicates.Value, new KdbxConfigurationOptions()));

        Assert.Contains("'Database/Main'", ex.Message);
        Assert.Contains("'database/main'", ex.Message);
        Assert.DoesNotContain("first", ex.Message);
        Assert.DoesNotContain("second", ex.Message);
    }

    [Fact]
    public void DuplicateKeys_Allowed_LastWins()
    {
        var data = KdbxConfigurationMapper.Map(Duplicates.Value, new KdbxConfigurationOptions { AllowDuplicateKeys = true });

        Assert.Equal("second", data["Database:Main"]);
    }
}
