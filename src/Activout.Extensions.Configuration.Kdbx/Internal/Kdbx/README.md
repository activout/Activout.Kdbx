# Vendored KDBX reader

Derived from [pidamg/keepass-dotnet](https://github.com/pidamg/keepass-dotnet) at commit `7fa3f9a`
(v0.1.1), MIT License. See [THIRD-PARTY-NOTICES.md](../../../../THIRD-PARTY-NOTICES.md).

## Changes from the original

- All types are `internal`, in the namespace `Activout.Extensions.Configuration.Kdbx.Internal`.
- Read-only: `KdbxWriter`, `KdbxXmlWriter`, `KdbxSettings`, `KdbxDatabase`, `KeyFile.Generate`, header
  writing and `VariantMap.Serialize` are removed.
- `Models/*` is replaced by three small read-only records (`KdbxDocument`, `KdbxGroup`, `KdbxEntry`).
  Icons, Auto-Type, binaries, history, custom data and most times are not read.
- `Core/Signature`, `KdbxVersion`, `IHeader`, `KdbxFormat` and `FieldReference` are removed; the
  header reads the signature and version directly. `DerivedKey` is folded into `KdbxReader`.
- Hash and HMAC comparisons use `CryptographicOperations.FixedTimeEquals` instead of `SequenceEqual`.
- KDBX 4: the header SHA-256 is checked before the KDF runs, and before the cipher and KDF are
  validated, so a corrupt header is not reported as unsupported.
- A wrong key throws `KdbxAuthenticationException` (KDBX 4 header HMAC, KDBX 3 StreamStartBytes).
  Other verification failures and malformed data throw `InvalidDataException`; unsupported formats,
  ciphers and KDFs throw `NotSupportedException`. KDBX 1.x/2.x signatures are recognised.
- CBC padding is removed after the key check, so bad padding means corruption, not a wrong key.
  The cipher layer decrypts byte arrays instead of wrapping streams.
- KDBX 3: the block index of the hashed block stream is verified.
- Limits from `KdbxLimits` on Argon2 memory, iterations and parallelism, AES-KDF rounds and
  decompressed size. Lengths in the header, blocks and KDF parameters are checked.
- The Argon2 version comes from the KDF parameters (0x10 or 0x13) instead of always 0x13.
- The Argon2id KDF UUID is corrected to `9e298b19-56db-4773-b23d-fc3ec6f0a1e6`.
- XML is read with `DtdProcessing.Prohibit` and no `XmlResolver`, including XML key files.
- Protected values are decrypted in document order over the whole XML, so the keystream stays in
  step through history entries and inline binaries without parsing them.
- KDBX 4 times may also be ISO 8601 strings.
- Key material (password hash, composite key, derived key, cipher and HMAC keys, decrypted payload)
  is zeroed after use, as far as .NET allows.
- Error messages for corrupt XML do not include the inner exception, which can quote decrypted content.
