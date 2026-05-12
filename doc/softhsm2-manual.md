# SoftHSM2 — Operator Manual

A concise reference for the day-to-day operations against the SoftHSM2 software
PKCS#11 token used by pyPKI for HSM development. SoftHSM2 stores keys
unencrypted on disk — it is a development fixture, not a security boundary.
Real-HSM portability concerns are tracked in
[hsm-support-specs.md](hsm-support-specs.md).

All commands below assume `softhsm2` (token + utilities) and `opensc`
(`pkcs11-tool`) are installed.

---

## 1. Install

**macOS (Homebrew):**

```bash
brew install softhsm opensc
```

**Debian / Ubuntu:**

```bash
sudo apt-get install softhsm2 opensc
```

**RHEL / Rocky / Alma:**

```bash
sudo dnf install softhsm opensc
```

The PKCS#11 module path differs by platform — set it once in your shell so the
later commands are portable:

| Platform | `PKCS11_MODULE` |
|---|---|
| macOS (Homebrew) | `$(brew --prefix)/lib/softhsm/libsofthsm2.so` |
| Debian / Ubuntu | `/usr/lib/softhsm/libsofthsm2.so` |
| RHEL / Rocky / Alma | `/usr/lib64/pkcs11/libsofthsm2.so` |

```bash
export PKCS11_MODULE=$(brew --prefix)/lib/softhsm/libsofthsm2.so   # macOS example
```

**Inside the pyPKI Docker container** the module is already at the Debian path
and `PKCS11_MODULE` is set in `docker-compose.yml`. Prefix the commands below
with `docker compose exec app` to run them against the container's token:

```bash
docker compose exec app pkcs11-tool --module "$PKCS11_MODULE" --list-slots
```

---

## 2. Initialise a token

A SoftHSM2 "slot" must be initialised once before keys can be created on it.
The pyPKI Docker container does this automatically on first boot (label
`pypki-dev`, user PIN `1234`, SO PIN `5678`); on a manual setup, run:

```bash
softhsm2-util --init-token --free \
    --label pypki-dev \
    --pin 1234 \
    --so-pin 5678
```

`--free` selects the first uninitialised slot. To target a specific slot,
replace it with `--slot N`. List initialised tokens with:

```bash
softhsm2-util --show-slots
```

---

## 3. Create keys

Key creation is done with `pkcs11-tool` (from `opensc`). `softhsm2-util` itself
only handles import/export — it cannot generate keys on the token.

**RSA-3072:**

```bash
pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --login --pin 1234 \
    --keypairgen --key-type rsa:3072 \
    --label "my-rsa-key" --id 01
```

**ECDSA P-256:**

```bash
pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --login --pin 1234 \
    --keypairgen --key-type EC:secp256r1 \
    --label "my-ec-key" --id 02
```

For other curves replace `secp256r1` with `secp384r1` (P-384) or
`secp521r1` (P-521). For RSA, common sizes are `rsa:2048`, `rsa:3072`,
`rsa:4096`. The `--id` value (CKA_ID) is hex; pick a value that is unique
within the token. The `--label` (CKA_LABEL) is free-form text.

---

## 4. List keys

Public objects (no login required):

```bash
pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --list-objects
```

Private objects too (requires login):

```bash
pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --login --pin 1234 \
    --list-objects
```

Filter to a specific class with `--type pubkey | privkey | cert | data`.

---

## 5. Delete a key

A keypair is two PKCS#11 objects (public + private). Delete both, identified by
their shared `--id`:

```bash
pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --login --pin 1234 \
    --delete-object --type privkey --id 01

pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label pypki-dev --login --pin 1234 \
    --delete-object --type pubkey --id 01
```

To wipe an entire token rather than individual objects, re-initialise the slot
with `softhsm2-util --init-token --slot N …` — this discards all of its
contents.

---

## 6. Backup and restore a slot

SoftHSM2 keeps each token's state as a directory under the configured
`tokendir`. Locating it:

| Environment | Default `tokendir` |
|---|---|
| pyPKI Docker container | `/var/lib/softhsm/tokens/` (bind-mounted to `data/softhsm/tokens/` on the host) |
| Linux system install | `/var/lib/softhsm/tokens/` |
| macOS (Homebrew, per-user) | `~/.config/softhsm2/tokens/` |

The actual subdirectory name inside `tokendir` is a generated UUID, not the
label — there is one such subdirectory per initialised token.

### Backup

Stop any process holding the token open (gunicorn, scripts, …), then archive
the whole `tokendir`:

```bash
# Linux example — adjust the path on macOS
tar -czf pypki-softhsm-$(date +%Y%m%d).tar.gz \
    -C /var/lib/softhsm tokens
```

This captures every initialised token plus all keys, certificates, and
attribute metadata. Treat the archive as sensitive: SoftHSM2 keys are at rest
in a form that is functionally equivalent to plaintext.

To back up a single token rather than all of them, identify its directory by
grepping for the label:

```bash
grep -lr "pypki-dev" /var/lib/softhsm/tokens/*/token.object \
    | xargs dirname
```

…then `tar` only that directory.

### Restore

Stop any process using the token and replace the `tokendir` contents with the
archive:

```bash
# Wipe the current tokens (or move them aside first if you want a rollback)
rm -rf /var/lib/softhsm/tokens/*

tar -xzf pypki-softhsm-YYYYMMDD.tar.gz -C /var/lib/softhsm/
```

Verify with `softhsm2-util --show-slots`.

### Per-key export / import

For migrating a single key between tokens (or off SoftHSM2 entirely),
`softhsm2-util` exports an asymmetric key pair to a PKCS#8 file:

```bash
softhsm2-util --export private-key.pem \
    --token pypki-dev --pin 1234 --id 01

softhsm2-util --import private-key.pem \
    --token pypki-dev --pin 1234 \
    --label "my-rsa-key" --id 01
```

Export only works on keys whose `CKA_EXTRACTABLE=TRUE` — pyPKI generates CA
keys with `CKA_EXTRACTABLE=FALSE` (see the "Mandatory private-key attributes"
section in [hsm-support-specs.md](hsm-support-specs.md)), so production-grade keys
created through pyPKI cannot be exported. This is intentional and matches how
real HSMs behave.

---

## Tips

- **Wrong `tokendir`?** SoftHSM2 reads `softhsm2.conf` from the path in
  `$SOFTHSM2_CONF`, then falls back to per-user (`~/.config/softhsm2/softhsm2.conf`)
  and finally system (`/etc/softhsm/softhsm2.conf`). `softhsm2-util --show-slots`
  prints which file is in effect at the top of its output.
- **`CKR_PIN_INCORRECT` after a restore.** The archived token's PIN travels
  with it — restoring on top of a token initialised with a different PIN does
  *not* migrate the new PIN. Use the PIN that was set when the backup was
  taken.
- **Avoid concurrent writers.** SoftHSM2 does not coordinate writes between
  processes. Take backups, run `--init-token`, and import keys with the
  application stopped.
