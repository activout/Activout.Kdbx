# Activout.Extensions.Configuration.Kdbx

A configuration source for `Microsoft.Extensions.Configuration` that reads secrets from a KeePass
database (`.kdbx`). Passwords, connection strings and API keys come from an encrypted file, the same
way `AddJsonFile` reads a JSON file.

> This project is not affiliated with or endorsed by the KeePass project. "KeePass" is a trademark of
> Dominik Reichl and is used here only to describe the file format.

## Quick start

```sh
dotnet add package Activout.Extensions.Configuration.Kdbx
```

```csharp
builder.Configuration.AddKdbxFile("secrets.kdbx", options =>
{
    options.Password = Environment.GetEnvironmentVariable("KDBX_PASSWORD");
});

var connectionString = builder.Configuration["Database:Main"];
```

Other overloads:

```csharp
// Optional file, reloaded when it changes
builder.Configuration.AddKdbxFile("secrets.kdbx", optional: true, reloadOnChange: true, options =>
{
    options.PasswordProvider = () => Environment.GetEnvironmentVariable("KDBX_PASSWORD");
    options.KeyFilePath = "/run/secrets/app.keyx";
});

// Full control over the source (file provider, OnLoadException, ReloadDelay, ...)
builder.Configuration.AddKdbxFile(source =>
{
    source.Path = "secrets.kdbx";
    source.Options.Password = "...";
});

// From a stream
builder.Configuration.AddKdbxStream(stream, options => options.Password = "...");
```

KDBX 3.1, 4.0 and 4.1 are supported: AES-256, ChaCha20 and Twofish; AES-KDF, Argon2d and Argon2id;
password, key file (XML v1/v2, 32-byte binary, 64-character hex, or any other file) or both.
Requires .NET 10.

## Key mapping

Given this database:

```
Root
├── Database
│   └── Main          (Password = "Server=...;Password=x", UserName = "app")
├── Api
│   └── Stripe
│       └── SecretKey (Password = "sk_live_...", custom field "Endpoint" = "https://...")
└── Recycle Bin
    └── Old           (ignored)
```

the default settings give:

| Configuration key | Value |
|---|---|
| `Database:Main` | `Server=...;Password=x` |
| `Database:Main:UserName` | `app` |
| `Api:Stripe:SecretKey` | `sk_live_...` |
| `Api:Stripe:SecretKey:Endpoint` | `https://...` |

Rules:

- A key is `[KeyPrefix:][RootName:]Group:Subgroup:...:EntryTitle`. The root group's name is left out
  unless `IncludeRootGroupName` is set.
- The key itself gets the entry's password. `UserName`, `Url`, `Notes` and custom fields become
  subkeys, as chosen by `Fields` (default: everything except `Notes`).
- Empty fields are left out.
- The recycle bin and everything in it is left out unless `IncludeRecycleBin` is set.
- Entry history and attachments are never read.
- **A `:` in a group or entry name is a key delimiter**, so `Title = "A:B"` gives the key `A:B`, two levels.
- Keys are case-insensitive, like in the other configuration providers.
- If two entries give the same key (also if they differ only in case), a `FormatException` names both
  entries. With `AllowDuplicateKeys = true` the entry that comes last in the tree wins.
- Field references (`{REF:...}`) are not resolved; the value is used as is.

Filtering:

```csharp
options.RequiredTag = "prod";                            // only entries with this tag
options.EntryFilter = e => e.GroupPath[0] != "Personal"; // your own rule; never sees the password
options.ExcludeExpired = true;                           // skip entries whose expiry time has passed
```

All filters must accept an entry for it to be loaded.

## Master key

- `PasswordProvider` is called on every load and takes precedence over `Password`. `KeyFilePath` is
  combined with the password if both are given. A relative `KeyFilePath` is relative to the current
  directory.
- Without a password, password provider or key file, building the configuration throws an
  `InvalidOperationException`.

**Do not put the master password in an earlier configuration source that is checked in, such as
`appsettings.json`.** Use one of these instead:

- an environment variable,
- [user secrets](https://learn.microsoft.com/aspnet/core/security/app-secrets) during development,
- a key file with restricted file permissions (`chmod 400`), or
- a platform secret, such as a Kubernetes secret mounted as a file.

## Loading and reloading

- A missing file with `optional: true` gives an empty configuration; without it, a
  `FileNotFoundException`.
- **Every load runs the key derivation function**, by design: the key cannot be cached because the salt
  changes on every save. The KDF is computed by BouncyCastle in managed code, which is slower than
  KeePassXC's native code: a database that takes one second to open in KeePassXC can take several
  seconds here. If start-up time matters, lower the KDF setting in KeePassXC (Database settings →
  Security → Decryption time). With `reloadOnChange`, keep `ReloadDelay` at its default or higher.
- If a reload fails, for example because the file is half-written, **the previous data is kept** and
  the error goes to `OnLoadException` if you set one. (`FileConfigurationProvider` itself would clear
  the data instead.)

## Errors

Load errors from a file are wrapped in an `InvalidDataException` by `FileConfigurationProvider`; the
`InnerException` is one of these:

| Situation | Exception |
|---|---|
| Wrong password or key file | `KdbxAuthenticationException` (a `CryptographicException`) |
| Corrupt or tampered file (hash or HMAC mismatch) | `InvalidDataException` |
| KDF parameters or content over a limit in `options.Limits` | `InvalidDataException` |
| Unsupported format (KDBX 1/2, unknown cipher or KDF) | `NotSupportedException` |
| Duplicate key | `FormatException` |

Error messages never contain passwords, field values or key material. Group and entry names can appear.

## Security

- The file's integrity is verified: the header SHA-256 and HMAC and the per-block HMACs in KDBX 4, and
  the block hashes and StreamStartBytes in KDBX 3. Comparisons are constant-time.
- `options.Limits` caps Argon2 memory (1 GiB), Argon2 iterations (200), Argon2 parallelism (64), AES-KDF
  rounds (100 million) and decompressed size (256 MiB), so a hostile file cannot exhaust memory or CPU.
- XML is read with DTDs prohibited and no resolver (no XXE).
- The master key and derived key material are zeroed after each load, as far as .NET allows.
- **Residual risk:** the secrets end up as ordinary `string` values in the configuration, like with any
  other `IConfiguration` provider. They stay in memory for the life of the process and can show up in
  memory dumps.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). The KDBX reader is derived from
[pidamg/keepass-dotnet](https://github.com/pidamg/keepass-dotnet) (MIT); see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
