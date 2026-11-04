// Derived from pidamg/keepass-dotnet (Pidamg.KeePass.Kdbx), commit 7fa3f9a,
// https://github.com/pidamg/keepass-dotnet. Copyright (c) 2026 pidamg. MIT License.
// Modified by Activout AB; changes are listed in Internal/Kdbx/README.md.

using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Activout.Extensions.Configuration.Kdbx.Internal;

internal static class KdbxXmlReader
{
    // No DTDs and no external resolution (XXE).
    public static readonly XmlReaderSettings SafeSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
    };

    private static readonly DateTime KdbxV4Epoch = new(1, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static KdbxDocument Read(Stream stream, ProtectedStream protectedStream, bool isV4)
    {
        XDocument xml;
        using (var reader = XmlReader.Create(stream, SafeSettings))
            xml = XDocument.Load(reader);

        var keePassFile = xml.Root ?? throw new InvalidDataException("The database has no XML root element.");

        // Protected values share one keystream, consumed in document order. This includes entry
        // history and inline binaries, which are not otherwise read.
        foreach (var el in keePassFile.Descendants())
        {
            if (!ParseBool(el.Attribute("Protected")?.Value)) continue;
            el.Value = Encoding.UTF8.GetString(protectedStream.Process(Convert.FromBase64String(el.Value)));
        }

        var rootGroup = keePassFile.Element("Root")?.Element("Group")
            ?? throw new InvalidDataException("The database has no root group.");

        var recycleBin = ParseUuid(keePassFile.Element("Meta")?.Element("RecycleBinUUID")?.Value);
        return new KdbxDocument(recycleBin, ParseGroup(rootGroup, isV4));
    }

    private static KdbxGroup ParseGroup(XElement el, bool isV4) => new(
        ParseUuid(el.Element("UUID")?.Value),
        el.Element("Name")?.Value ?? "",
        [.. el.Elements("Group").Select(g => ParseGroup(g, isV4))],
        [.. el.Elements("Entry").Select(e => ParseEntry(e, isV4))]);

    // <History> is skipped: only direct <String> children are read.
    private static KdbxEntry ParseEntry(XElement el, bool isV4)
    {
        var strings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var s in el.Elements("String"))
            strings[s.Element("Key")?.Value ?? ""] = s.Element("Value")?.Value ?? "";

        var times = el.Element("Times");
        return new KdbxEntry(
            strings,
            el.Element("Tags")?.Value ?? "",
            ParseBool(times?.Element("Expires")?.Value),
            ParseDate(times?.Element("ExpiryTime")?.Value, isV4));
    }

    private static DateTime ParseDate(string? value, bool isV4)
    {
        if (string.IsNullOrEmpty(value)) return DateTime.MaxValue;

        // KDBX 4 stores seconds since 0001-01-01 as base64 Int64; KDBX 3 (and some 4 writers) use ISO 8601.
        if (isV4 && !value.Contains('-'))
        {
            long seconds = BinaryPrimitives.ReadInt64LittleEndian(Convert.FromBase64String(value));
            return KdbxV4Epoch.AddSeconds(seconds);
        }

        return DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
    }

    private static Guid ParseUuid(string? value)
    {
        if (string.IsNullOrEmpty(value)) return Guid.Empty;
        Span<byte> bytes = stackalloc byte[16];
        return Convert.TryFromBase64String(value, bytes, out int n) && n == 16 ? new Guid(bytes) : Guid.Empty;
    }

    private static bool ParseBool(string? value) => string.Equals(value, "True", StringComparison.OrdinalIgnoreCase);
}
