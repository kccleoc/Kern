# Kern

Kern is an air-gapped Bitcoin hardware wallet firmware for the ESP32-P4. This
context covers the wallet's key model: how a BIP39 mnemonic and passphrase are
turned into an active wallet, and how the user supplies and verifies them.

## Language

**Passphrase**:
A secret string supplied alongside the BIP39 mnemonic when deriving the seed.
Arbitrary text (up to 256 chars), session-only — never persisted. When absent
the wallet derives from the mnemonic alone.
_Avoid_: extension word, 25th word

**Word-list Passphrase**:
A passphrase that is a sequence of 1-24 lowercase BIP39 words separated by
single spaces. The words *are* the passphrase — there is no encoding or
checksum. Validated word-by-word against the English wordlist; a word-list
passphrase is never a mnemonic.
_Avoid_: mnemonic, seed phrase

**Base Fingerprint**:
The BIP32 master-key fingerprint of the wallet derived from the mnemonic with
no passphrase.

**Passphrase Fingerprint**:
The BIP32 master-key fingerprint derived with a given passphrase. Differs from
the base fingerprint whenever the passphrase is non-empty.

**Fingerprint Transition**:
The `[base] -> [passphrase]` fingerprint pair shown to the user so they can
verify that a passphrase produces the expected keys before it is applied.

**Verify Passphrase screen**:
The confirmation step for the scanned passphrase path (keyboard entry
confirms by fingerprint transition dialog instead). Shows the candidate
passphrase, the fingerprint transition, and Confirm / Back / Rescan actions.

**Scan input**:
Supplying a value (passphrase, KEF encryption key, mnemonic, descriptor) by
scanning a QR code with the camera instead of typing it. A scanned
passphrase bypasses the keyboard entry and goes straight to verification.

**KEF Encryption Key**:
The password that protects a KEF envelope — used when backing up the
mnemonic (or a descriptor, or displaying an encrypted SeedQR). Typed twice
for confirmation, or scanned once from a QR code and confirmed on the
Verify Key screen. Not wallet-derived, so it has no fingerprint transition.

**Verify Key screen**:
The confirmation step for a scanned KEF encryption key. Shows the key
masked with an eye toggle and Confirm / Back / Rescan actions.

**Derivation**:
Turning the mnemonic (and optional passphrase) into the wallet's master key
via BIP39 seed derivation and BIP32.
