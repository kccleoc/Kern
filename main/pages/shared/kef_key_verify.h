/*
 * KEF Key Verify Page
 *
 * Shows a candidate KEF encryption key masked, with an eye toggle, and
 * Confirm / Rescan / Back actions. Mirrors the passphrase_verify pattern
 * for values scanned from a QR code (there is no fingerprint transition:
 * a KEF key is not wallet-derived).
 */

#ifndef KEF_KEY_VERIFY_H
#define KEF_KEY_VERIFY_H

#include <lvgl.h>
#include <stdbool.h>

/**
 * Success callback — the key pointer is only valid during the call; copy it.
 */
typedef void (*kef_key_verify_accept_cb_t)(const char *key);

/**
 * Takes ownership of `key` (heap-allocated, NUL-terminated) and zeroizes it
 * on destroy; the caller never frees it. `rescan_cb` is only wired when
 * `allow_rescan` is true.
 */
void kef_key_verify_page_create(const char *key, bool allow_rescan,
                                void (*back_cb)(void), void (*rescan_cb)(void),
                                kef_key_verify_accept_cb_t accept_cb);
void kef_key_verify_page_show(void);
void kef_key_verify_page_destroy(void);

#endif /* KEF_KEY_VERIFY_H */
