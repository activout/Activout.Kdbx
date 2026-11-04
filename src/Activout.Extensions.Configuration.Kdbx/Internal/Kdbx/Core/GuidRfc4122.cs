// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

namespace Activout.Extensions.Configuration.Kdbx.Internal;

// KDBX stores UUIDs in RFC 4122 big-endian byte order; .NET's Guid(byte[]) is mixed-endian.
internal static class GuidRfc4122
{
    public static Guid FromBytes(byte[] b) => new(b, bigEndian: true);
}
