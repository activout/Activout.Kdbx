// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal static class KdbxReader
{
    public static KdbxDocument Read(Stream stream, CompositeKey key, KdbxLimits limits)
    {
        try
        {
            return ReadCore(stream, key, limits);
        }
        catch (Exception ex) when (ex is not KdbxAuthenticationException and (EndOfStreamException or FormatException or XmlException
                                       or CryptographicException or ArgumentException or OverflowException
                                       or IndexOutOfRangeException))
        {
            // The inner exception is dropped on purpose: XML errors can quote decrypted content.
            throw new InvalidDataException($"The database is corrupt ({ex.GetType().Name}).");
        }
    }

    private static KdbxDocument ReadCore(Stream stream, CompositeKey key, KdbxLimits limits)
    {
        // RecordingStream captures the header bytes needed for KDBX 4 verification
        var recording = new RecordingStream(stream);
        var header = KdbxHeader.Read(new BinaryReader(recording));
        byte[] headerBytes = recording.GetRecordedBytes();
        var reader = new BinaryReader(stream);

        // KDBX 4: the SHA256 of the outer header detects corruption; checked before the expensive KDF
        byte[] headerHmac = [];
        if (header.IsVersion4)
        {
            if (!CryptographicOperations.FixedTimeEquals(ReadExactly(reader, 32), SHA256.HashData(headerBytes)))
                throw new InvalidDataException("Header SHA-256 verification failed.");
            headerHmac = ReadExactly(reader, 32);
        }
        header.Validate();

        var kdf = header.CreateKdf(limits);
        byte[] rawKey = key.GetRawKey();
        byte[] derived = kdf.Transform(rawKey);
        using var encKey = new EncryptionKey(header.MasterSeed, derived);
        CryptographicOperations.ZeroMemory(rawKey);
        CryptographicOperations.ZeroMemory(derived);

        return header.IsVersion4
            ? ReadV4(header, encKey, headerBytes, headerHmac, reader, limits)
            : ReadV3(header, encKey, reader, limits);
    }

    // ── KDBX 3.x ────────────────────────────────────────────────────────────────
    // File: [Header][Cipher([StreamStartBytes(32)][HashedBlockStream([GZip]([XML]))])]

    private static KdbxDocument ReadV3(KdbxHeader header, EncryptionKey encKey, BinaryReader reader, KdbxLimits limits)
    {
        byte[] plain = SymmetricCipher.Decrypt(header.CipherId, encKey.Key, header.EncryptionIV, ReadToEnd(reader.BaseStream));
        try
        {
            // The first 32 decrypted bytes must match StreamStartBytes; if not, the key is wrong
            if (plain.Length < 32 || !CryptographicOperations.FixedTimeEquals(plain.AsSpan(0, 32), header.StreamStartBytes))
                throw new KdbxAuthenticationException();

            int length = SymmetricCipher.IsBlockCipher(header.CipherId) ? SymmetricCipher.UnpaddedLength(plain) : plain.Length;
            using var blocks = new BinaryReader(new MemoryStream(plain, 32, length - 32));
            byte[] payload = ReadHashedBlocks(blocks);

            using var xml = Decompress(payload, header.IsCompressed, limits);
            var ps = new ProtectedStream(header.InnerRandomStreamId, header.ProtectedStreamKey!);
            return KdbxXmlReader.Read(xml, ps, isV4: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // ── KDBX 4.x ────────────────────────────────────────────────────────────────
    // File: [Header][SHA256(32)][HMAC(32)][HmacBlockStream(Cipher([GZip]([InnerHeader][XML])))]

    private static KdbxDocument ReadV4(KdbxHeader header, EncryptionKey encKey, byte[] headerBytes, byte[] headerHmac,
        BinaryReader reader, KdbxLimits limits)
    {
        // HMAC-SHA256 of the outer header (block index UInt64.MaxValue) detects a wrong key
        byte[] headerHmacKey = BlockKey(ulong.MaxValue, encKey.HmacKey);
        bool keyOk = CryptographicOperations.FixedTimeEquals(headerHmac, HMACSHA256.HashData(headerHmacKey, headerBytes));
        CryptographicOperations.ZeroMemory(headerHmacKey);
        if (!keyOk)
            throw new KdbxAuthenticationException();

        byte[] ciphertext = ReadHmacBlocks(reader, encKey.HmacKey);
        byte[] plain = SymmetricCipher.Decrypt(header.CipherId, encKey.Key, header.EncryptionIV, ciphertext);
        try
        {
            int length = SymmetricCipher.IsBlockCipher(header.CipherId) ? SymmetricCipher.UnpaddedLength(plain) : plain.Length;
            using var payload = Decompress(plain.AsSpan(0, length).ToArray(), header.IsCompressed, limits);

            var inner = new BinaryReader(payload);
            var (algorithm, innerKey) = ReadInnerHeader(inner);
            var ps = new ProtectedStream(algorithm, innerKey);
            CryptographicOperations.ZeroMemory(innerKey);

            // payload is now positioned at the XML
            return KdbxXmlReader.Read(payload, ps, isV4: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // ── HashedBlockStream (KDBX 3.x) ────────────────────────────────────────────
    // Block: [Index (4 LE)][SHA256 (32)][Size (4 LE)][Data]. Terminates when Size == 0.

    private static byte[] ReadHashedBlocks(BinaryReader reader)
    {
        using var result = new MemoryStream();
        for (uint index = 0; ; index++)
        {
            if (reader.ReadUInt32() != index)
                throw new InvalidDataException("Block index verification failed.");
            byte[] hash = ReadExactly(reader, 32);
            byte[] data = ReadExactly(reader, ReadLength(reader));

            if (data.Length == 0) break;

            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(data), hash))
                throw new InvalidDataException($"Block {index} hash verification failed.");

            result.Write(data);
        }
        return result.ToArray();
    }

    // ── HmacBlockStream (KDBX 4.x) ──────────────────────────────────────────────
    // Block: [HMAC-SHA256 (32)][Size (4 LE)][Data]. Terminates when Size == 0 (also HMAC-verified).

    private static byte[] ReadHmacBlocks(BinaryReader reader, byte[] hmacKey64)
    {
        using var result = new MemoryStream();
        for (ulong index = 0; ; index++)
        {
            byte[] hmac = ReadExactly(reader, 32);
            int size = ReadLength(reader);
            byte[] data = ReadExactly(reader, size);

            // HMAC-SHA256(blockIndex_LE64 ∥ blockSize_LE32 ∥ data, SHA512(blockIndex_LE64 ∥ hmacKey64))
            var msg = new byte[12 + data.Length];
            BinaryPrimitives.WriteUInt64LittleEndian(msg, index);
            BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(8), size);
            data.CopyTo(msg, 12);
            byte[] blockKey = BlockKey(index, hmacKey64);
            bool ok = CryptographicOperations.FixedTimeEquals(hmac, HMACSHA256.HashData(blockKey, msg));
            CryptographicOperations.ZeroMemory(blockKey);
            if (!ok)
                throw new InvalidDataException($"Block {index} HMAC verification failed.");

            if (size == 0) break;
            result.Write(data);
        }
        return result.ToArray();
    }

    // SHA512(blockIndex_LE64 ∥ hmacKey64)
    private static byte[] BlockKey(ulong blockIndex, byte[] hmacKey64)
    {
        var buf = new byte[8 + hmacKey64.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, blockIndex);
        hmacKey64.CopyTo(buf, 8);
        byte[] key = SHA512.HashData(buf);
        CryptographicOperations.ZeroMemory(buf);
        return key;
    }

    // ── Inner header (KDBX 4.x) ─────────────────────────────────────────────────
    // Field: [ID (1)][Length (4 LE)][Data]. 0x00 = end, 0x01 = stream id, 0x02 = stream key, 0x03 = binary (ignored).

    private static (ProtectedStreamAlgorithm Algorithm, byte[] Key) ReadInnerHeader(BinaryReader reader)
    {
        var algorithm = ProtectedStreamAlgorithm.ChaCha20;
        byte[]? key = null;

        while (true)
        {
            byte id = reader.ReadByte();
            byte[] data = ReadExactly(reader, ReadLength(reader));

            switch (id)
            {
                case 0x00: return (algorithm, key ?? throw new InvalidDataException("The inner header has no stream key."));
                case 0x01: algorithm = (ProtectedStreamAlgorithm)BinaryPrimitives.ReadUInt32LittleEndian(data); break;
                case 0x02: key = data; break;
            }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private static int ReadLength(BinaryReader reader)
    {
        int length = reader.ReadInt32();
        if (length < 0)
            throw new InvalidDataException("A block has an invalid length.");
        return length;
    }

    private static byte[] ReadExactly(BinaryReader reader, int count)
    {
        byte[] data = reader.ReadBytes(count);
        if (data.Length != count)
            throw new EndOfStreamException();
        return data;
    }

    private static byte[] ReadToEnd(Stream stream)
    {
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    // Returns a seekable stream with the (decompressed) payload, capped at MaxDecompressedBytes (GZip bomb).
    private static MemoryStream Decompress(byte[] data, bool compressed, KdbxLimits limits)
    {
        if (!compressed) return new MemoryStream(data, writable: false);

        using var gzip = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
        var output = new MemoryStream();
        var buffer = new byte[81920];
        int n;
        while ((n = gzip.Read(buffer)) > 0)
        {
            if (output.Length + n > limits.MaxDecompressedBytes)
                throw new InvalidDataException($"The decompressed database exceeds the limit ({limits.MaxDecompressedBytes} bytes).");
            output.Write(buffer, 0, n);
        }
        output.Position = 0;
        return output;
    }

    // Wraps a stream and records every byte read through it. Does not dispose the inner stream.
    private sealed class RecordingStream(Stream inner) : Stream
    {
        private readonly MemoryStream _buffer = new();

        public byte[] GetRecordedBytes() => _buffer.ToArray();

        public override bool CanRead => true;
        public override bool CanWrite => false;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = inner.Read(buffer, offset, count);
            _buffer.Write(buffer, offset, n);
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
