using System.Security.Cryptography;

namespace Activout.Extensions.Configuration.Kdbx;

/// <summary>
/// Options for reading a KDBX database into configuration.
/// </summary>
public sealed class KdbxConfigurationOptions
{
    /// <summary>The master password. Ignored when <see cref="PasswordProvider"/> is set.</summary>
    public string? Password { get; set; }

    /// <summary>Returns the master password. Called on every load; takes precedence over <see cref="Password"/>.</summary>
    public Func<string?>? PasswordProvider { get; set; }

    /// <summary>Path to a key file. Combined with the password if both are given.</summary>
    public string? KeyFilePath { get; set; }

    /// <summary>A prefix for all keys, for example <c>Secrets</c> gives <c>Secrets:Database:Main</c>.</summary>
    public string? KeyPrefix { get; set; }

    /// <summary>Whether the root group's name is the first key segment. Default <see langword="false"/>.</summary>
    public bool IncludeRootGroupName { get; set; }

    /// <summary>Whether entries in the recycle bin are loaded. Default <see langword="false"/>.</summary>
    public bool IncludeRecycleBin { get; set; }

    /// <summary>Whether entries whose expiry time has passed are skipped. Default <see langword="false"/>.</summary>
    public bool ExcludeExpired { get; set; }

    /// <summary>Which entry fields are mapped to configuration keys.</summary>
    public KdbxFieldMapping Fields { get; set; } = KdbxFieldMapping.Default;

    /// <summary>Returns <see langword="true"/> for entries to load. Applied together with <see cref="RequiredTag"/>.</summary>
    public Func<KdbxEntryInfo, bool>? EntryFilter { get; set; }

    /// <summary>Only load entries with this tag (case-insensitive).</summary>
    public string? RequiredTag { get; set; }

    /// <summary>
    /// When <see langword="false"/> (the default), two entries that produce the same key cause a
    /// <see cref="FormatException"/>. When <see langword="true"/>, the entry that comes last in tree order wins.
    /// </summary>
    public bool AllowDuplicateKeys { get; set; }

    /// <summary>Upper limits that protect against hostile files.</summary>
    public KdbxLimits Limits { get; set; } = new();
}

/// <summary>
/// Which entry fields become configuration keys.
/// </summary>
[Flags]
public enum KdbxFieldMapping
{
    /// <summary>No fields.</summary>
    None = 0,

    /// <summary>The password, as the value of the entry's key itself.</summary>
    Password = 1,

    /// <summary>The user name, as the subkey <c>UserName</c>.</summary>
    UserName = 2,

    /// <summary>The URL, as the subkey <c>Url</c>.</summary>
    Url = 4,

    /// <summary>The notes, as the subkey <c>Notes</c>.</summary>
    Notes = 8,

    /// <summary>Custom fields, as subkeys with their own names.</summary>
    CustomFields = 16,

    /// <summary>Everything except <see cref="Notes"/>.</summary>
    Default = Password | UserName | Url | CustomFields,
}

/// <summary>
/// A read-only view of an entry, passed to <see cref="KdbxConfigurationOptions.EntryFilter"/>. Does not include the password.
/// </summary>
/// <param name="GroupPath">The group names from the root down, as used in the key. The root group is included only with <see cref="KdbxConfigurationOptions.IncludeRootGroupName"/>.</param>
/// <param name="Title">The entry's title.</param>
/// <param name="UserName">The entry's user name.</param>
/// <param name="Url">The entry's URL.</param>
/// <param name="Tags">The entry's tags.</param>
/// <param name="ExpiryTime">The expiry time in UTC, or <see langword="null"/> if the entry does not expire.</param>
public sealed record KdbxEntryInfo(
    IReadOnlyList<string> GroupPath,
    string Title,
    string UserName,
    string Url,
    IReadOnlyList<string> Tags,
    DateTime? ExpiryTime);

/// <summary>
/// Upper limits on KDF parameters and content size, so that a hostile file cannot exhaust memory or CPU.
/// </summary>
public sealed class KdbxLimits
{
    /// <summary>Maximum Argon2 memory, in bytes. Default 1 GiB.</summary>
    public long MaxArgon2MemoryBytes { get; set; } = 1L << 30;

    /// <summary>Maximum Argon2 iterations. Default 200.</summary>
    public ulong MaxArgon2Iterations { get; set; } = 200;

    /// <summary>Maximum Argon2 parallelism. Default 64.</summary>
    public uint MaxArgon2Parallelism { get; set; } = 64;

    /// <summary>Maximum AES-KDF rounds. Default 100,000,000.</summary>
    public ulong MaxAesKdfRounds { get; set; } = 100_000_000;

    /// <summary>Maximum size of the decompressed content, in bytes. Default 256 MiB.</summary>
    public long MaxDecompressedBytes { get; set; } = 256L << 20;
}

/// <summary>
/// The password or key file is wrong.
/// </summary>
public sealed class KdbxAuthenticationException : CryptographicException
{
    /// <summary>Creates the exception with the default message.</summary>
    public KdbxAuthenticationException() : base("The password or key file is wrong.") { }
}
