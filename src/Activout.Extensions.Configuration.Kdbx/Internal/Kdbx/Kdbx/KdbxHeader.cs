// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Buffers.Binary;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal sealed class KdbxHeader
{
    private const uint Signature1 = 0x9AA2D903;
    private const uint Signature2Kdbx = 0xB54BFB67;
    private const uint Signature2Kdb = 0xB54BFB65;       // KDBX 1.x (.kdb)
    private const uint Signature2PreRelease = 0xB54BFB66; // KDBX 2.x pre-release

    private enum FieldId : byte
    {
        EndOfHeader = 0x00,
        CipherId = 0x02,
        CompressionFlags = 0x03,
        MasterSeed = 0x04,
        TransformSeed = 0x05,
        TransformRounds = 0x06,
        EncryptionIV = 0x07,
        ProtectedStreamKey = 0x08,
        StreamStartBytes = 0x09,
        InnerRandomStreamId = 0x0A,
        KdfParameters = 0x0B,
    }

    public ushort MajorVersion { get; private set; }
    public bool IsVersion4 => MajorVersion == 4;

    public Guid CipherId { get; private set; }
    public bool IsCompressed { get; private set; }
    public byte[] MasterSeed { get; private set; } = [];
    public byte[] EncryptionIV { get; private set; } = [];

    // KDBX 3.x
    public byte[]? TransformSeed { get; private set; }
    public ulong TransformRounds { get; private set; }
    public byte[]? ProtectedStreamKey { get; private set; }
    public byte[]? StreamStartBytes { get; private set; }
    public ProtectedStreamAlgorithm InnerRandomStreamId { get; private set; }

    // KDBX 4.x
    public Dictionary<string, object>? KdfParameters { get; private set; }

    private KdbxHeader() { }

    public static KdbxHeader Read(BinaryReader reader)
    {
        var h = new KdbxHeader();

        uint sig1 = reader.ReadUInt32();
        uint sig2 = reader.ReadUInt32();
        if (sig1 != Signature1)
            throw new InvalidDataException("The file is not a KeePass database.");
        if (sig2 is Signature2Kdb or Signature2PreRelease)
            throw new NotSupportedException("KDBX 1.x and 2.x databases are not supported.");
        if (sig2 != Signature2Kdbx)
            throw new InvalidDataException("The file is not a KeePass database.");

        reader.ReadUInt16(); // minor version
        h.MajorVersion = reader.ReadUInt16();
        if (h.MajorVersion is not (3 or 4))
            throw new NotSupportedException($"KDBX version {h.MajorVersion}.x is not supported.");

        bool v4 = h.IsVersion4;

        while (true)
        {
            var fieldId = (FieldId)reader.ReadByte();
            int length = v4 ? checked((int)reader.ReadUInt32()) : reader.ReadUInt16();
            byte[] data = reader.ReadBytes(length);
            if (data.Length != length)
                throw new EndOfStreamException();

            switch (fieldId)
            {
                case FieldId.EndOfHeader: return h;
                case FieldId.CipherId: h.CipherId = GuidRfc4122.FromBytes(data); break;
                case FieldId.CompressionFlags: h.IsCompressed = BinaryPrimitives.ReadUInt32LittleEndian(data) != 0; break;
                case FieldId.MasterSeed: h.MasterSeed = data; break;
                case FieldId.TransformSeed: h.TransformSeed = data; break;
                case FieldId.TransformRounds: h.TransformRounds = BinaryPrimitives.ReadUInt64LittleEndian(data); break;
                case FieldId.EncryptionIV: h.EncryptionIV = data; break;
                case FieldId.ProtectedStreamKey: h.ProtectedStreamKey = data; break;
                case FieldId.StreamStartBytes: h.StreamStartBytes = data; break;
                case FieldId.InnerRandomStreamId: h.InnerRandomStreamId = (ProtectedStreamAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case FieldId.KdfParameters: h.KdfParameters = VariantMap.Read(data); break;
                    // Comment, PublicCustomData and unknown fields are ignored
            }
        }
    }

    // Called after the KDBX 4 header hash check, so that a corrupt header is not reported as unsupported
    public void Validate()
    {
        SymmetricCipher.Validate(CipherId);
        if (MasterSeed.Length != 32 || EncryptionIV.Length != SymmetricCipher.IvSize(CipherId))
            throw new InvalidDataException("The database header is invalid.");
        if (!IsVersion4 && (TransformSeed?.Length != 32 || StreamStartBytes?.Length != 32 || ProtectedStreamKey == null))
            throw new InvalidDataException("The database header is invalid.");
    }

    public IKdf CreateKdf(KdbxLimits limits)
    {
        if (!IsVersion4)
            return CreateAesKdf(TransformSeed!, TransformRounds, limits);

        if (KdfParameters == null || !KdfParameters.TryGetValue("$UUID", out var uuidBytes) || uuidBytes is not byte[] { Length: 16 } uuid)
            throw new InvalidDataException("The database header has no KDF parameters.");

        var kdfId = GuidRfc4122.FromBytes(uuid);

        if (kdfId == Argon2Kdf.Argon2dUuid || kdfId == Argon2Kdf.Argon2idUuid)
        {
            var salt = Get<byte[]>("S");
            uint parallelism = Get<uint>("P");
            ulong memoryBytes = Get<ulong>("M");
            ulong iterations = Get<ulong>("I");
            uint version = Get<uint>("V");

            if (memoryBytes > (ulong)limits.MaxArgon2MemoryBytes)
                throw new InvalidDataException($"The Argon2 memory size ({memoryBytes} bytes) exceeds the limit ({limits.MaxArgon2MemoryBytes} bytes).");
            if (iterations > limits.MaxArgon2Iterations)
                throw new InvalidDataException($"The Argon2 iteration count ({iterations}) exceeds the limit ({limits.MaxArgon2Iterations}).");
            if (parallelism > limits.MaxArgon2Parallelism)
                throw new InvalidDataException($"The Argon2 parallelism ({parallelism}) exceeds the limit ({limits.MaxArgon2Parallelism}).");
            if (version is not (0x10 or 0x13) || parallelism == 0 || iterations == 0 || memoryBytes < 8 * 1024 * parallelism)
                throw new InvalidDataException("The Argon2 parameters are invalid.");

            // M is stored in bytes, BouncyCastle wants KiB
            return new Argon2Kdf(salt, (int)parallelism, (int)(memoryBytes / 1024), (int)iterations, (int)version,
                isArgon2id: kdfId == Argon2Kdf.Argon2idUuid);
        }

        if (kdfId == AesKdf.UuidKdbx3 || kdfId == AesKdf.UuidKdbx4)
            return CreateAesKdf(Get<byte[]>("S"), Get<ulong>("R"), limits);

        throw new NotSupportedException($"Unsupported KDF: {kdfId}.");

        T Get<T>(string key) => KdfParameters.TryGetValue(key, out var v) && v is T t
            ? t
            : throw new InvalidDataException($"The KDF parameter '{key}' is missing or invalid.");
    }

    private static AesKdf CreateAesKdf(byte[] seed, ulong rounds, KdbxLimits limits)
    {
        if (rounds > limits.MaxAesKdfRounds)
            throw new InvalidDataException($"The AES-KDF round count ({rounds}) exceeds the limit ({limits.MaxAesKdfRounds}).");
        if (seed.Length != 32)
            throw new InvalidDataException("The AES-KDF seed is invalid.");
        return new AesKdf(seed, rounds);
    }
}
