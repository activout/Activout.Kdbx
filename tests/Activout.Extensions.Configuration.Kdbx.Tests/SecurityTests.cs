using Activout.Extensions.Configuration.Kdbx.Internal;
using static Activout.Extensions.Configuration.Kdbx.Tests.TestData;

namespace Activout.Extensions.Configuration.Kdbx.Tests;

public class SecurityTests
{
    private static Exception ReadBytes(byte[] bytes, string password, KdbxLimits? limits = null)
    {
        using var key = new CompositeKey();
        key.AddPassword(password);
        return Assert.ThrowsAny<Exception>(() => KdbxReader.Read(new MemoryStream(bytes), key, limits ?? new KdbxLimits()));
    }

    private static byte[] Flip(string file, int offsetFromEnd)
    {
        var bytes = File.ReadAllBytes(PathOf(file));
        bytes[^offsetFromEnd] ^= 0x01;
        return bytes;
    }

    [Theory]
    [InlineData("SimplePasswordV4.kdbx", "password123")]
    [InlineData("mapping.kdbx", "mapping-pw")]
    public void ChangedPayloadByte_IsCorrupt_NotWrongKey(string file, string password)
    {
        var ex = ReadBytes(Flip(file, 100), password);

        Assert.IsType<InvalidDataException>(ex);
    }

    [Fact]
    public void ChangedHeaderByte_Kdbx4_IsCorrupt()
    {
        var bytes = File.ReadAllBytes(PathOf("SimplePasswordV4.kdbx"));
        bytes[20] ^= 0x01; // inside the cipher id

        Assert.IsType<InvalidDataException>(ReadBytes(bytes, "password123"));
    }

    [Fact]
    public void NotAKeePassFile()
    {
        Assert.IsType<InvalidDataException>(ReadBytes("not a database at all"u8.ToArray(), "x"));
    }

    [Fact]
    public void Kdbx1_IsNotSupported()
    {
        byte[] kdb = [0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5, 0, 0, 0, 0];

        Assert.IsType<NotSupportedException>(ReadBytes(kdb, "x"));
    }

    [Fact]
    public void Truncated_IsCorrupt()
    {
        var bytes = File.ReadAllBytes(PathOf("SimplePasswordV4.kdbx"))[..300];

        Assert.IsType<InvalidDataException>(ReadBytes(bytes, "password123"));
    }

    [Fact]
    public void Argon2MemoryLimit()
    {
        // SimplePasswordV4.kdbx uses 64 MiB and 135 iterations
        var ex = ReadBytes(File.ReadAllBytes(PathOf("SimplePasswordV4.kdbx")), "password123",
            new KdbxLimits { MaxArgon2MemoryBytes = 32 << 20 });

        Assert.IsType<InvalidDataException>(ex);
        Assert.Contains("Argon2 memory", ex.Message);
    }

    [Fact]
    public void Argon2IterationLimit()
    {
        var ex = ReadBytes(File.ReadAllBytes(PathOf("SimplePasswordV4.kdbx")), "password123",
            new KdbxLimits { MaxArgon2Iterations = 100 });

        Assert.Contains("Argon2 iteration", ex.Message);
    }

    [Fact]
    public void AesKdfRoundLimit()
    {
        var ex = ReadBytes(File.ReadAllBytes(PathOf("mapping.kdbx")), "mapping-pw",
            new KdbxLimits { MaxAesKdfRounds = 1000 });

        Assert.IsType<InvalidDataException>(ex);
        Assert.Contains("AES-KDF", ex.Message);
    }

    [Fact]
    public void DecompressedSizeLimit()
    {
        var ex = ReadBytes(File.ReadAllBytes(PathOf("mapping.kdbx")), "mapping-pw",
            new KdbxLimits { MaxDecompressedBytes = 1000 });

        Assert.IsType<InvalidDataException>(ex);
        Assert.Contains("decompressed", ex.Message);
    }

    [Fact]
    public void ErrorMessages_ContainNoSecrets()
    {
        var secrets = new[] { "mapping-pw", "wrong-password", "top-secret", "sk_test_123", "first", "second" };
        var messages = new List<string>
        {
            Assert.ThrowsAny<Exception>(() => Load("mapping.kdbx", o => o.Password = "wrong-password")).ToString(),
            Assert.ThrowsAny<Exception>(() => Load("duplicates.kdbx", o => o.Password = "duplicates-pw")).ToString(),
            ReadBytes(Flip("mapping.kdbx", 100), "mapping-pw").ToString(),
        };

        foreach (var message in messages)
            foreach (var secret in secrets)
                Assert.DoesNotContain(secret, message);
    }

    [Fact]
    public void XmlKeyFile_WithDtd_IsNotParsedAsXml()
    {
        // A DTD makes the XML reader fail, so the file is hashed as an opaque key file instead of expanded.
        var keyFile = """
            <?xml version="1.0"?>
            <!DOCTYPE KeyFile [<!ENTITY x SYSTEM "file:///etc/passwd">]>
            <KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>&x;</Data></Key></KeyFile>
            """u8.ToArray();
        using var key = new CompositeKey();

        key.AddKeyFile(keyFile);

        Assert.Equal(32, key.GetRawKey().Length);
    }
}
