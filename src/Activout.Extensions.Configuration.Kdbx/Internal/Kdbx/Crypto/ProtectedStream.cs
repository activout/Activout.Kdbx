// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal enum ProtectedStreamAlgorithm
{
    Salsa20 = 2,
    ChaCha20 = 3,
}

// Stateful XOR stream used to decrypt Protected="True" XML values.
// The keystream advances with each call to Process(), so values must be processed in document order.
internal sealed class ProtectedStream
{
    private readonly IStreamCipher _cipher;

    public ProtectedStream(ProtectedStreamAlgorithm algorithm, byte[] key)
    {
        _cipher = algorithm switch
        {
            ProtectedStreamAlgorithm.Salsa20 => InitSalsa20(key),
            ProtectedStreamAlgorithm.ChaCha20 => InitChaCha20(key),
            _ => throw new NotSupportedException($"Unsupported inner random stream: {(int)algorithm}."),
        };
    }

    public byte[] Process(byte[] data)
    {
        var output = new byte[data.Length];
        _cipher.ProcessBytes(data, 0, data.Length, output, 0);
        return output;
    }

    private static Salsa20Engine InitSalsa20(byte[] key)
    {
        var engine = new Salsa20Engine();
        engine.Init(true, new ParametersWithIV(
            new KeyParameter(SHA256.HashData(key)),
            [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]));
        return engine;
    }

    private static ChaCha7539Engine InitChaCha20(byte[] key)
    {
        var hash = SHA512.HashData(key);
        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(hash[..32]), hash[32..44]));
        CryptographicOperations.ZeroMemory(hash);
        return engine;
    }
}
