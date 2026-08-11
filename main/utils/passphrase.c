#include "passphrase.h"

#include "bip39_filter.h"

#include <stdio.h>
#include <string.h>

bool passphrase_validate_word_list(const char *passphrase, char *err_out,
                                   size_t err_len) {
  const char *msg = NULL;

  if (!passphrase || passphrase[0] == '\0') {
    msg = "Passphrase is empty";
    goto fail;
  }

  if (strlen(passphrase) > PASSPHRASE_MAX_LEN) {
    msg = "Passphrase is too long";
    goto fail;
  }

  /* The wordlist must be resident to look words up. */
  if (!bip39_filter_init()) {
    msg = "BIP39 wordlist unavailable";
    goto fail;
  }

  const char *p = passphrase;
  int words = 0;

  /* Leading space is not single-space separation. */
  if (*p == ' ') {
    msg = "Must not start with a space";
    goto fail;
  }

  while (*p) {
    const char *start = p;
    while (*p && *p != ' ')
      p++;
    size_t token_len = (size_t)(p - start);

    if (token_len == 0) {
      msg = "Must use single spaces only";
      goto fail;
    }

    char token[PASSPHRASE_WORD_MAX_LEN + 2];
    if (token_len >= sizeof(token)) {
      msg = "Not a BIP39 word";
      goto fail;
    }
    memcpy(token, start, token_len);
    token[token_len] = '\0';

    if (bip39_filter_get_word_index(token) < 0) {
      if (err_out && err_len > 0)
        snprintf(err_out, err_len, "Not a BIP39 word: \"%s\"", token);
      return false;
    }

    words++;
    if (words > PASSPHRASE_WORD_MAX) {
      msg = "More than 24 words";
      goto fail;
    }

    /* Must be followed by nothing (end) or exactly one more word. */
    if (*p == ' ') {
      if (*(p + 1) == '\0') {
        msg = "Must not end with a space";
        goto fail;
      }
      if (*(p + 1) == ' ') {
        msg = "Must use single spaces only";
        goto fail;
      }
      p++;
    }
  }

  if (words < PASSPHRASE_WORD_MIN) {
    msg = "Passphrase is empty";
    goto fail;
  }

  return true;

fail:
  if (err_out && err_len > 0 && msg) {
    strncpy(err_out, msg, err_len - 1);
    err_out[err_len - 1] = '\0';
  }
  return false;
}
