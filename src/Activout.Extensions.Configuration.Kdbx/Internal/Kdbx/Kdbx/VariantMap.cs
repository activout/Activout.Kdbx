// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Buffers.Binary;
using System.Text;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

// Binary key-value map used by KDBX 4.x to store KDF parameters.
// Format: [version (2)] { [type (1)][keyLen (4 LE)][key UTF8][valLen (4 LE)][val] }* [0x00]
internal static class VariantMap
{
    public static Dictionary<string, object> Read(byte[] data)
    {
        var map = new Dictionary<string, object>();
        using var reader = new BinaryReader(new MemoryStream(data), Encoding.UTF8);

        ushort version = reader.ReadUInt16();
        if ((version & 0xFF00) != 0x0100)
            throw new NotSupportedException($"Unsupported KDF parameter version: 0x{version:X4}.");

        while (true)
        {
            byte type = reader.ReadByte();
            if (type == 0x00) break;

            string key = Encoding.UTF8.GetString(ReadBlock(reader));
            byte[] val = ReadBlock(reader);

            map[key] = type switch
            {
                0x04 => BinaryPrimitives.ReadUInt32LittleEndian(val),  // UInt32
                0x05 => BinaryPrimitives.ReadUInt64LittleEndian(val),  // UInt64
                0x08 => val[0] != 0,                                   // Bool
                0x0C => BinaryPrimitives.ReadInt32LittleEndian(val),   // Int32
                0x0D => BinaryPrimitives.ReadInt64LittleEndian(val),   // Int64
                0x18 => Encoding.UTF8.GetString(val),                  // String
                0x42 => val,                                           // ByteArray
                _ => throw new InvalidDataException($"Unknown KDF parameter type: 0x{type:X2}."),
            };
        }

        return map;
    }

    private static byte[] ReadBlock(BinaryReader reader)
    {
        uint length = reader.ReadUInt32();
        if (length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("A KDF parameter has an invalid length.");
        return reader.ReadBytes((int)length);
    }
}
