<p align="center">
  <img src=".github/hero.png" alt="symmetry — seal your .env files" width="720">
</p>

Seal the `.env` files in your repo. Symmetry encrypts them to `.enc` siblings,
keeps the encryption key in your OS keychain, and injects variables straight
into process memory at runtime — plaintext never has to touch disk.

One binary. No server, no account, no daemon.

**Docs:** https://symmetry.jackh.sh

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/jackh-sh/symmetry-cli/main/scripts/install.sh | sh
```

Prebuilt binaries for macOS and Linux (arm64 and x86_64), verified by
checksum and release signature.
As always, [read the script](scripts/install.sh) before piping it to your
shell. To build from source instead, clone this repo and run
`./scripts/dev-install.sh` (needs Rust).

## Quickstart

```sh
symmetry init             # scan for .env files, set up a key, encrypt
symmetry run -- npm start # run with decrypted vars injected into memory
symmetry status           # encryption state of each managed file
```

Edit sealed files without ever writing plaintext to disk:

```sh
symmetry show                     # list variables (values masked)
symmetry set DATABASE_URL foo     # set or add, re-encrypts in place
symmetry unset DATABASE_URL       # remove, re-encrypts in place
```

`symmetry encrypt` / `symmetry decrypt` (aliases: `lock` / `unlock`) round out
the loop when you need the plaintext files back.

See the [quickstart](https://symmetry.jackh.sh/docs/quickstart) and
[CLI reference](https://symmetry.jackh.sh/docs/cli) for the rest — key
sharing, password mode for CI, and strict mode (Touch ID / Windows Hello on
every key use).
