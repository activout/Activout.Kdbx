// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal static class SymmetricCipher
{
    // CipherID UUIDs from the KDBX header.
    // Reference: https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp
    private static readonly Guid Aes128Uuid = new("61ab05a1-9464-41c3-8d74-3a563df8dd35");
    private static readonly Guid Aes256Uuid = new("31c1f2e6-bf71-4350-be58-05216afc5aff");
    private static readonly Guid ChaCha20Uuid = new("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");
    private static readonly Guid TwofishUuid = new("ad68f29f-576f-4bb9-a36a-d47af965346c");

    public static int IvSize(Guid cipherId) => cipherId == ChaCha20Uuid ? 12 : 16;

    public static void Validate(Guid cipherId)
    {
        if (cipherId != Aes128Uuid && cipherId != Aes256Uuid && cipherId != ChaCha20Uuid && cipherId != TwofishUuid)
            throw new NotSupportedException($"Unsupported cipher: {cipherId}.");
    }

    // Decrypts the payload. CBC padding is left in place and removed by RemovePadding, so that a
    // wrong key (detected by the caller) can be told apart from a corrupt file (bad padding).
    public static byte[] Decrypt(Guid cipherId, byte[] key, byte[] iv, byte[] ciphertext)
    {
        if (cipherId == ChaCha20Uuid)
        {
            var engine = new ChaCha7539Engine();
            engine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
            var plain = new byte[ciphertext.Length];
            engine.ProcessBytes(ciphertext, 0, ciphertext.Length, plain, 0);
            return plain;
        }

        if (ciphertext.Length == 0 || ciphertext.Length % 16 != 0)
            throw new InvalidDataException("The encrypted payload has an invalid length.");

        if (cipherId == TwofishUuid)
        {
            var cbc = new CbcBlockCipher(new TwofishEngine());
            cbc.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
            var plain = new byte[ciphertext.Length];
            for (int i = 0; i < ciphertext.Length; i += 16)
                cbc.ProcessBlock(ciphertext, i, plain, i);
            return plain;
        }

        using var aes = Aes.Create();
        aes.Key = cipherId == Aes128Uuid ? key[..16] : key;
        return aes.DecryptCbc(ciphertext, iv, PaddingMode.None);
    }

    public static bool IsBlockCipher(Guid cipherId) => cipherId != ChaCha20Uuid;

    public static int UnpaddedLength(byte[] plain)
    {
        int pad = plain.Length == 0 ? 0 : plain[^1];
        if (pad is < 1 or > 16 || pad > plain.Length)
            throw new InvalidDataException("The encrypted payload has invalid padding.");
        for (int i = plain.Length - pad; i < plain.Length; i++)
        {
            if (plain[i] != pad)
                throw new InvalidDataException("The encrypted payload has invalid padding.");
        }
        return plain.Length - pad;
    }
}
