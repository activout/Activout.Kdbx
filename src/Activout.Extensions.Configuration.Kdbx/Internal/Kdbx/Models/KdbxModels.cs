// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

namespace Activout.Extensions.Configuration.Kdbx.Internal;

// Read-only views of the parts of a database that the configuration provider uses.

internal sealed record KdbxDocument(Guid RecycleBinUuid, KdbxGroup Root);

internal sealed record KdbxGroup(Guid Uuid, string Name, IReadOnlyList<KdbxGroup> Groups, IReadOnlyList<KdbxEntry> Entries);

internal sealed record KdbxEntry(
    IReadOnlyDictionary<string, string> Strings,
    string Tags,
    bool Expires,
    DateTime ExpiryTime);
