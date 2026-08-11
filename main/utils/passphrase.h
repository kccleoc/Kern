/*
 * Passphrase validation utilities.
 *
 * A BIP39 passphrase is an arbitrary string fed to seed derivation. This
 * module adds one optional constraint: a "word-list passphrase" — a sequence
 * of 1..24 lowercase BIP39 words separated by single spaces. It is NOT a
 * mnemonic: there is no checksum and no multiple-of-3 word count, so
 * bip39_mnemonic_validate() must never be used on it.
 */

#ifndef KERN_UTILS_PASSPHRASE_H
#define KERN_UTILS_PASSPHRASE_H

#include <stdbool.h>
#include <stddef.h>

/* Max passphrase length in chars (NUL terminator stored separately).
 * Covers the worst-case word-list passphrase (24 x 8 + 23 spaces = 215)
 * with headroom for arbitrary passphrases. */
#define PASSPHRASE_MAX_LEN 256
#define PASSPHRASE_WORD_MIN 1
#define PASSPHRASE_WORD_MAX 24

/* Longest BIP39 English word is 8 letters. */
#define PASSPHRASE_WORD_MAX_LEN 8

/**
 * Validate a word-list passphrase: split on single spaces, every token must
 * be an exact lowercase BIP39 word, 1..24 words total, no leading/trailing
 * or doubled spaces.
 *
 * @param passphrase NUL-terminated candidate string
 * @param err_out    Optional buffer for a human-readable reason
 * @param err_len    Size of err_out
 * @return true if the passphrase satisfies the word-list constraint
 */
bool passphrase_validate_word_list(const char *passphrase, char *err_out,
                                   size_t err_len);

#endif // KERN_UTILS_PASSPHRASE_H
