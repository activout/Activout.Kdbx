// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal sealed class Argon2Kdf(byte[] salt, int parallelism, int memoryKib, int iterations, int version, bool isArgon2id)
    : IKdf
{
    public static readonly Guid Argon2dUuid = new("ef636ddf-8c29-444b-91f7-a9a403e30a0c");
    public static readonly Guid Argon2idUuid = new("9e298b19-56db-4773-b23d-fc3ec6f0a1e6");

    public byte[] Transform(byte[] rawKey)
    {
        var parameters = new Argon2Parameters.Builder(isArgon2id ? Argon2Parameters.Argon2id : Argon2Parameters.Argon2d)
            .WithSalt(salt)
            .WithParallelism(parallelism)
            .WithMemoryAsKB(memoryKib)
            .WithIterations(iterations)
            .WithVersion(version)
            .Build();

        var gen = new Argon2BytesGenerator();
        gen.Init(parameters);

        byte[] result = new byte[32];
        gen.GenerateBytes(rawKey, result);
        return result;
    }
}
