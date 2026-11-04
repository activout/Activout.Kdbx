// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Security.Cryptography;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

// Payload and HMAC keys derived from the master seed and the transformed (KDF) key.
internal sealed class EncryptionKey : IDisposable
{
    public EncryptionKey(byte[] masterSeed, byte[] derivedKey)
    {
        // SHA256(masterSeed ∥ derivedKey) is the cipher key;
        // SHA512(masterSeed ∥ derivedKey ∥ 0x01) is the KDBX 4 HMAC base key.
        var buf = new byte[masterSeed.Length + derivedKey.Length + 1];
        masterSeed.CopyTo(buf, 0);
        derivedKey.CopyTo(buf, masterSeed.Length);
        Key = SHA256.HashData(buf.AsSpan(0, buf.Length - 1));
        buf[^1] = 0x01;
        HmacKey = SHA512.HashData(buf);
        CryptographicOperations.ZeroMemory(buf);
    }

    // 32-byte payload key (AES-CBC, ChaCha20, Twofish)
    public byte[] Key { get; }

    // 64-byte key for HMAC block integrity (KDBX 4 only)
    public byte[] HmacKey { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Key);
        CryptographicOperations.ZeroMemory(HmacKey);
    }
}
