/*
 * Passphrase Verify Page
 * Shared review step for BIP39 passphrase entry, reached from both the
 * keyboard path and the QR-scan path of the passphrase page.
 *
 * Shows the candidate passphrase and the master-key fingerprint transition
 *  [base] -> [passphrase]
 * so the user can confirm the passphrase yields the expected keys. Confirm
 * hands the passphrase to the success callback; Back discards it and returns
 * to the entry page; Rescan (scan path only) discards it and re-opens the
 * camera.
 */

#ifndef PASSPHRASE_VERIFY_H
#define PASSPHRASE_VERIFY_H

#include <lvgl.h>

/* Signature-compatible with passphrase_success_callback_t (pages/passphrase.h).
 * The passphrase pointer is only valid for the duration of the call — the
 * caller must copy it if it needs to keep it. */
typedef void (*passphrase_verify_success_cb_t)(const char *passphrase);

/**
 * @brief Create the Verify Passphrase page
 *
 * @param parent        Parent LVGL object (lv_screen_active())
 * @param passphrase    Candidate passphrase. The page TAKES OWNERSHIP: it must
 *                      be heap-allocated and NUL-terminated, and is zeroized
 *                      and freed on destroy.
 * @param allow_rescan  Show a Rescan button (scan path only)
 * @param back_cb       Called when the user cancels (Back / corner back)
 * @param rescan_cb     Called when the user taps Rescan (may be NULL)
 * @param success_cb    Called with the confirmed passphrase on Confirm
 */
void passphrase_verify_page_create(lv_obj_t *parent, const char *passphrase,
                                   bool allow_rescan, void (*back_cb)(void),
                                   void (*rescan_cb)(void),
                                   passphrase_verify_success_cb_t success_cb);

void passphrase_verify_page_show(void);
void passphrase_verify_page_hide(void);
void passphrase_verify_page_destroy(void);

#endif // PASSPHRASE_VERIFY_H
