# Word-list passphrases are validated per-word, never via bip39_mnemonic_validate

A "word-list passphrase" (1-24 lowercase BIP39 words separated by single
spaces) is a passphrase, not a mnemonic: it has no checksum and no
multiple-of-3 word count, so `bip39_mnemonic_validate` would reject almost
every valid word-list passphrase. We therefore validate word-by-word against
the English wordlist (`bip39_filter_get_word_index`) instead. Reaching for
mnemonic validation here would silently break existing word-list passphrases,
which is why the per-word path is enforced in `passphrase_validate_word_list`.
