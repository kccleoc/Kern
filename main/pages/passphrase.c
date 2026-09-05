#include "passphrase.h"
#include "../core/key.h"
#include "../ui/assets/icons.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/settings_row.h"
#include "../ui/theme_widgets.h"
#include "../utils/passphrase.h"
#include "../utils/secure_mem.h"
#include "shared/passphrase_verify.h"
#include "shared/text_input_scan.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lv_obj_t *passphrase_screen = NULL;
static ui_text_input_t text_input = {0};
static lv_obj_t *wordlist_row = NULL;
static void (*return_callback)(void) = NULL;
static passphrase_success_callback_t success_callback = NULL;

/* Help-modal text for the word-list toggle (stored by reference, literal). */
static const char *WORDLIST_HELP =
    "Restrict the passphrase to 1-24 lowercase BIP39 words separated by "
    "single spaces. The words are the passphrase itself (no checksum, no "
    "encoding) and are validated before confirmation.";

static void back_confirm_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure you want to go back?", back_confirm_cb,
                      NULL, DIALOG_STYLE_OVERLAY);
}

static void confirm_passphrase_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && success_callback)
    success_callback(lv_textarea_get_text(text_input.textarea));
}

static bool passphrase_word_list_enabled(void) {
  if (!wordlist_row)
    return false;
  lv_obj_t *sw = settings_row_get_widget(wordlist_row);
  return sw && lv_obj_has_state(sw, LV_STATE_CHECKED);
}

/* Overwrite the textarea contents with spaces before clearing so the typed
 * passphrase doesn't linger in freed heap memory. Same trick as pin_page. */
static void secure_clear_textarea(void) {
  if (!text_input.textarea)
    return;
  const char *text = lv_textarea_get_text(text_input.textarea);
  size_t len = text ? strlen(text) : 0;
  if (len > 0) {
    char dummy[PASSPHRASE_MAX_LEN + 1];
    if (len > PASSPHRASE_MAX_LEN)
      len = PASSPHRASE_MAX_LEN;
    memset(dummy, ' ', len);
    dummy[len] = '\0';
    lv_textarea_set_text(text_input.textarea, dummy);
    secure_memzero(dummy, sizeof(dummy));
  }
  lv_textarea_set_text(text_input.textarea, "");
}

/* Forward: the keyboard scan key captures via the shared text-input scan
 * helper, then scan_loaded_cb routes the result to the Verify page. */
static void start_passphrase_scan(void);
static void scan_loaded_cb(void);

/* Returns the passphrase to the entry page. The verify page has already been
 * destroyed by the time this runs. */
static void verify_return_cb(void) { passphrase_page_show(); }

/* Re-opens the camera via text_input_scan (scan path only). The verify page
 * has already destroyed itself by the time this runs. */
static void verify_rescan_cb(void) { start_passphrase_scan(); }

/* text_input_scan loaded callback: the scanned text is already in the
 * textarea (validated as text/UTF-8 with any trailing newline stripped).
 * Enforce the length + word-list constraints, then hand off to the Verify
 * Passphrase page instead of leaving the secret in the entry field. */
static void scan_loaded_cb(void) {
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;
  if (strlen(text) > PASSPHRASE_MAX_LEN) {
    dialog_show_error_timeout("Passphrase too long", NULL, 0);
    secure_clear_textarea();
    return;
  }
  if (passphrase_word_list_enabled()) {
    char err[128];
    if (!passphrase_validate_word_list(text, err, sizeof(err))) {
      dialog_show_error_timeout(err, NULL, 0);
      secure_clear_textarea();
      return;
    }
  }

  char *copy = strdup(text);
  secure_clear_textarea();
  if (!copy) {
    dialog_show_error_timeout("Out of memory", NULL, 0);
    return;
  }

  passphrase_verify_page_create(lv_screen_active(), copy, true,
                                verify_return_cb, verify_rescan_cb,
                                success_callback);
  passphrase_verify_page_show();
}

static void start_passphrase_scan(void) {
  text_input_scan_cfg_t cfg = {&text_input, passphrase_page_hide,
                               passphrase_page_show, scan_loaded_cb};
  text_input_scan_start(&cfg);
}

static void scan_key_cb(void *user_data) {
  (void)user_data;
  start_passphrase_scan();
}

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;

  const char *text = lv_textarea_get_text(text_input.textarea);
  if (text && strlen(text) > PASSPHRASE_MAX_LEN) {
    dialog_show_error_timeout("Passphrase too long", NULL, 0);
    return;
  }
  const char *passphrase = (text && text[0] != '\0') ? text : NULL;

  if (passphrase && passphrase_word_list_enabled()) {
    char err[128];
    if (!passphrase_validate_word_list(passphrase, err, sizeof(err))) {
      dialog_show_error_timeout(err, NULL, 0);
      return;
    }
  }

  // A typo looks like plausible dots either way; only the fingerprint it
  // derives makes it visible, without putting the secret on screen.
  char before_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char after_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char *mnemonic = NULL;
  if (!key_get_fingerprint_hex(before_hex) || !key_get_mnemonic(&mnemonic))
    return;
  bool ok =
      key_mnemonic_passphrase_fingerprint_hex(mnemonic, passphrase, after_hex);
  SECURE_FREE_STRING(mnemonic);
  if (!ok)
    return;

  lv_color32_t c = lv_color_to_32(highlight_color(), LV_OPA_COVER);
  uint32_t highlight = (c.red << 16) | (c.green << 8) | c.blue;

  char prompt[128];
  snprintf(prompt, sizeof(prompt),
           "Confirm passphrase?\n\n" ICON_FINGERPRINT " %s\n" LV_SYMBOL_DOWN
           "\n#%06X " ICON_FINGERPRINT " %s#",
           before_hex, (unsigned)highlight, after_hex);
  dialog_show_confirm(prompt, confirm_passphrase_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

void passphrase_page_create(lv_obj_t *parent, void (*return_cb)(void),
                            passphrase_success_callback_t success_cb) {
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  // Screen
  passphrase_screen = theme_create_page_container(lv_screen_active());

  // Create title label
  theme_create_page_title(passphrase_screen, "Enter Passphrase");

  // Back button
  ui_create_back_button(passphrase_screen, back_btn_cb);

  // Text input (textarea + keyboard), masked with an eye toggle to reveal
  ui_text_input_create(&text_input, passphrase_screen, "passphrase", true,
                       keyboard_ready_cb);
  ui_text_input_enable_scan(&text_input, scan_key_cb, NULL);

  // Word-list toggle row between the textarea and the keyboard. Scanned
  // input arrives via the keyboard's scan key and is routed to the Verify
  // Passphrase page (see scan_loaded_cb).
  int32_t ta_bottom = lv_obj_get_y(text_input.textarea) +
                      lv_obj_get_height(text_input.textarea);

  lv_obj_t *rows = theme_create_flex_column(passphrase_screen);
  lv_obj_set_width(rows, LV_PCT(90));
  lv_obj_set_style_pad_gap(rows, theme_small_padding(), 0);
  lv_obj_align(rows, LV_ALIGN_TOP_MID, 0, ta_bottom + theme_small_padding());

  wordlist_row = settings_row_toggle(rows, "BIP39 words", false, NULL,
                                     "BIP39 words", WORDLIST_HELP);

  // Shrink the keyboard to clear the new row.
  lv_obj_update_layout(rows);
  int32_t rows_bottom =
      lv_obj_get_y(rows) + lv_obj_get_height(rows) + theme_default_padding();
  int32_t kb_h = LV_VER_RES - rows_bottom;
  if (kb_h < theme_min_touch_size())
    kb_h = theme_min_touch_size();
  lv_obj_set_height(text_input.keyboard, kb_h);
}

void passphrase_page_show(void) {
  if (passphrase_screen)
    lv_obj_clear_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_hide(void) {
  if (passphrase_screen)
    lv_obj_add_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_destroy(void) {
  secure_clear_textarea();
  ui_text_input_destroy(&text_input);
  if (passphrase_screen) {
    lv_obj_del(passphrase_screen);
    passphrase_screen = NULL;
  }
  wordlist_row = NULL;
  return_callback = NULL;
  success_callback = NULL;
}
