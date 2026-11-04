// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

// The composite key used to unlock a KDBX database: SHA256 of the concatenated component hashes.
internal sealed class CompositeKey : IDisposable
{
    private readonly List<byte[]> _components = [];

    public void AddPassword(string password)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        _components.Add(SHA256.HashData(bytes));
        CryptographicOperations.ZeroMemory(bytes);
    }

    public void AddKeyFile(byte[] data) => _components.Add(ReadKeyFile(data));

    public byte[] GetRawKey()
    {
        if (_components.Count == 0)
            throw new InvalidOperationException("No master key was given.");

        var buffer = new byte[_components.Count * 32];
        try
        {
            for (int i = 0; i < _components.Count; i++)
                _components[i].CopyTo(buffer, i * 32);
            return SHA256.HashData(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public void Dispose()
    {
        foreach (var c in _components)
            CryptographicOperations.ZeroMemory(c);
        _components.Clear();
    }

    private static byte[] ReadKeyFile(byte[] data)
    {
        if (TryParseXmlKeyFile(data, out var xmlKey))
            return xmlKey;

        // 64 ASCII hex chars → 32 bytes
        if (data.Length == 64 && TryParseHex(data, out var hexKey))
            return hexKey;

        // Raw 32-byte binary key
        if (data.Length == 32)
            return (byte[])data.Clone();

        return SHA256.HashData(data);
    }

    private static bool TryParseXmlKeyFile(byte[] data, out byte[] key)
    {
        key = [];

        XDocument doc;
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(data), KdbxXmlReader.SafeSettings);
            doc = XDocument.Load(reader);
        }
        catch (XmlException)
        {
            return false;
        }

        if (doc.Root?.Name.LocalName != "KeyFile")
            return false;

        var dataElement = doc.Root.Element("Key")?.Element("Data")
            ?? throw new InvalidDataException("The XML key file does not contain key data.");
        bool v2 = doc.Root.Element("Meta")?.Element("Version")?.Value.Trim().StartsWith("2.", StringComparison.Ordinal) == true;

        try
        {
            key = v2
                ? Convert.FromHexString(string.Concat(dataElement.Value.Where(c => !char.IsWhiteSpace(c))))
                : Convert.FromBase64String(dataElement.Value.Trim());
        }
        catch (FormatException)
        {
            throw new InvalidDataException("The XML key file contains invalid key data.");
        }

        if (key.Length != 32)
            throw new InvalidDataException("An XML key file must contain a 32-byte key.");

        if (v2)
        {
            var actualHash = dataElement.Attribute("Hash")?.Value.Trim()
                ?? throw new InvalidDataException("A version 2 XML key file must contain a key hash.");
            var expectedHash = Convert.ToHexString(SHA256.HashData(key).AsSpan(0, 4));
            if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The XML key file hash is invalid.");
        }

        return true;
    }

    private static bool TryParseHex(byte[] data, out byte[] key)
    {
        try
        {
            key = Convert.FromHexString(Encoding.ASCII.GetString(data));
            return true;
        }
        catch (FormatException)
        {
            key = [];
            return false;
        }
    }
}
