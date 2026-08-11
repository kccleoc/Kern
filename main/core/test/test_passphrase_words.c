#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "utils/passphrase.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

static void expect_valid(const char *name, const char *passphrase) {
  TEST(name);
  if (passphrase_validate_word_list(passphrase, NULL, 0))
    PASS();
  else
    FAIL("expected valid but rejected");
}

static void expect_invalid(const char *name, const char *passphrase) {
  TEST(name);
  char err[128];
  if (!passphrase_validate_word_list(passphrase, err, sizeof(err)))
    PASS();
  else
    FAIL("expected rejected but accepted");
}

int main(void) {
  /* Valid: single word. */
  expect_valid("single word", "abandon");
  /* Valid: two words. */
  expect_valid("two words", "abandon about");
  /* Valid: 24 words (first 24 of the BIP39 English list). */
  expect_valid("24 words", "abandon ability able about above absent absorb "
                           "abstract absurd abuse access accident account "
                           "achieve acid acoustic acquire across act action "
                           "actor actress adapt add");
  /* Valid: word count that a mnemonic could never have — a word-list
   * passphrase is NOT a mnemonic. */
  expect_valid("4 words (not a mnemonic)", "abandon ability able about");
  /* Valid: max word length in the list. */
  expect_valid("long words", "sentence squirrel");

  /* Invalid: empty. */
  expect_invalid("empty", "");
  /* Invalid: NULL. */
  TEST("NULL");
  if (!passphrase_validate_word_list(NULL, NULL, 0))
    PASS();
  else
    FAIL("NULL accepted");
  /* Invalid: leading space. */
  expect_invalid("leading space", " abandon");
  /* Invalid: trailing space. */
  expect_invalid("trailing space", "abandon ");
  /* Invalid: double space. */
  expect_invalid("double space", "abandon  about");
  /* Invalid: not a BIP39 word. */
  expect_invalid("unknown word", "abandon notaword");
  /* Invalid: uppercase (strict, no normalization). */
  expect_invalid("uppercase word", "Abandon about");
  /* Invalid: mixed case token. */
  expect_invalid("mixed case", "abandon About");
  /* Invalid: punctuation. */
  expect_invalid("punctuation", "abandon,about");
  /* Invalid: newline separator. */
  expect_invalid("newline", "abandon\nabout");
  /* Invalid: 25 words. */
  expect_invalid("25 words", "abandon ability able about above absent absorb "
                             "abstract absurd abuse access accident account "
                             "achieve acid acoustic acquire across act action "
                             "actor actress adapt add abandon");

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
