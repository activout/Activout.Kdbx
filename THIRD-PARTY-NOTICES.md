# Third-party notices

## pidamg/keepass-dotnet

The code in `src/Activout.Extensions.Configuration.Kdbx/Internal/Kdbx/` that reads KDBX files is
derived from [pidamg/keepass-dotnet](https://github.com/pidamg/keepass-dotnet) (`Pidamg.KeePass.Kdbx`),
commit `7fa3f9a2d4434df037545c5cd10e0a6d5876205e` (v0.1.1). The test files
`SimplePasswordV4.kdbx` and `SimplePasswordV3_ChaCha20.kdbx` come from the same commit.
The changes are listed in
[`Internal/Kdbx/README.md`](src/Activout.Extensions.Configuration.Kdbx/Internal/Kdbx/README.md).

```
MIT License

Copyright (c) 2026 pidamg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BouncyCastle.Cryptography

A NuGet dependency, not vendored. MIT License, Copyright (c) 2000-2024 The Legion of the Bouncy Castle
Inc. (https://www.bouncycastle.org).
