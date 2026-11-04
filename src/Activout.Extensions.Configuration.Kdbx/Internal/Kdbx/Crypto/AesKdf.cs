// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Security.Cryptography;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal sealed class AesKdf(byte[] seed, ulong rounds) : IKdf
{
    // UUID used in KDBX 3.x KdfParameters (and by some KDBX 4.x writers for compatibility)
    public static readonly Guid UuidKdbx3 = new("c9d9f39a-628a-4460-bf74-0d08c18a4fea");
    // UUID used in KDBX 4.x KdfParameters
    public static readonly Guid UuidKdbx4 = new("7c02bb82-79a7-4ac0-927d-114a00648238");

    // DerivedKey = SHA256(ECB(left, seed, rounds) ∥ ECB(right, seed, rounds))
    // where left = rawKey[0..16], right = rawKey[16..32]
    public byte[] Transform(byte[] rawKey)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = seed;

        var left = rawKey[..16];
        var right = rawKey[16..];
        var leftBuf = new byte[16];
        var rightBuf = new byte[16];
        var combined = new byte[32];

        try
        {
            using var encryptor = aes.CreateEncryptor();
            for (ulong i = 0; i < rounds; i++)
            {
                encryptor.TransformBlock(left, 0, 16, leftBuf, 0);
                encryptor.TransformBlock(right, 0, 16, rightBuf, 0);
                (left, leftBuf) = (leftBuf, left);
                (right, rightBuf) = (rightBuf, right);
            }

            left.CopyTo(combined, 0);
            right.CopyTo(combined, 16);
            return SHA256.HashData(combined);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(left);
            CryptographicOperations.ZeroMemory(right);
            CryptographicOperations.ZeroMemory(leftBuf);
            CryptographicOperations.ZeroMemory(rightBuf);
            CryptographicOperations.ZeroMemory(combined);
        }
    }
}
