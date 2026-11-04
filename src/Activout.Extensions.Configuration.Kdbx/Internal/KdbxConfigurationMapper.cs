using Activout.Extensions.Configuration.Kdbx.Internal;
using Microsoft.Extensions.Configuration;

namespace Activout.Extensions.Configuration.Kdbx;

// Reads a database and maps groups and entries to configuration keys.
internal static class KdbxConfigurationMapper
{
    private static readonly HashSet<string> StandardFields = ["Title", "UserName", "Password", "URL", "Notes"];

    public static Dictionary<string, string?> Load(Stream stream, KdbxConfigurationOptions options) =>
        Map(Read(stream, options), options);

    public static Dictionary<string, string?> Map(KdbxDocument document, KdbxConfigurationOptions options)
    {
        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var origins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var rootPath = options.IncludeRootGroupName ? new List<string> { document.Root.Name } : [];
        MapGroup(document.Root, rootPath);
        return data;

        void MapGroup(KdbxGroup group, List<string> path)
        {
            foreach (var entry in group.Entries)
                MapEntry(entry, path);

            foreach (var child in group.Groups)
            {
                if (!options.IncludeRecycleBin && child.Uuid != Guid.Empty && child.Uuid == document.RecycleBinUuid)
                    continue;
                MapGroup(child, [.. path, child.Name]);
            }
        }

        void MapEntry(KdbxEntry entry, List<string> path)
        {
            string Field(string name) => entry.Strings.GetValueOrDefault(name, "");

            var title = Field("Title");
            var tags = entry.Tags.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var info = new KdbxEntryInfo(path.AsReadOnly(), title, Field("UserName"), Field("URL"), tags,
                entry.Expires ? entry.ExpiryTime : null);

            if (options.ExcludeExpired && entry.Expires && entry.ExpiryTime <= DateTime.UtcNow) return;
            if (options.RequiredTag != null && !tags.Contains(options.RequiredTag, StringComparer.OrdinalIgnoreCase)) return;
            if (options.EntryFilter != null && !options.EntryFilter(info)) return;

            var key = ConfigurationPath.Combine([.. Prefix(), .. path, title]);
            var origin = string.Join('/', [.. path, title]);
            var fields = options.Fields;

            if (fields.HasFlag(KdbxFieldMapping.Password)) Set(key, Field("Password"));
            if (fields.HasFlag(KdbxFieldMapping.UserName)) Set(ConfigurationPath.Combine(key, "UserName"), Field("UserName"));
            if (fields.HasFlag(KdbxFieldMapping.Url)) Set(ConfigurationPath.Combine(key, "Url"), Field("URL"));
            if (fields.HasFlag(KdbxFieldMapping.Notes)) Set(ConfigurationPath.Combine(key, "Notes"), Field("Notes"));
            if (fields.HasFlag(KdbxFieldMapping.CustomFields))
            {
                foreach (var (name, value) in entry.Strings)
                {
                    if (!StandardFields.Contains(name))
                        Set(ConfigurationPath.Combine(key, name), value);
                }
            }

            void Set(string k, string value)
            {
                if (value.Length == 0) return;
                if (!options.AllowDuplicateKeys && origins.TryGetValue(k, out var previous))
                    throw new FormatException($"The key '{k}' is produced by both '{previous}' and '{origin}'.");
                origins[k] = origin;
                data[k] = value;
            }
        }

        IEnumerable<string> Prefix() => string.IsNullOrEmpty(options.KeyPrefix) ? [] : [options.KeyPrefix];
    }

    public static KdbxDocument Read(Stream stream, KdbxConfigurationOptions options)
    {
        using var key = new CompositeKey();
        var password = options.PasswordProvider != null ? options.PasswordProvider() : options.Password;
        if (password != null) key.AddPassword(password);
        if (options.KeyFilePath != null) key.AddKeyFile(File.ReadAllBytes(options.KeyFilePath));
        return KdbxReader.Read(stream, key, options.Limits);
    }

    public static void Validate(KdbxConfigurationOptions options)
    {
        if (options.Password == null && options.PasswordProvider == null && options.KeyFilePath == null)
            throw new InvalidOperationException("A KDBX source needs a Password, PasswordProvider or KeyFilePath.");
    }
}
