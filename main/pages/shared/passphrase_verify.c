#include "passphrase_verify.h"

#include "../../core/key.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/passphrase.h"
#include "../../utils/secure_mem.h"

#include <lvgl.h>
#include <string.h>

#define PREVIEW_MAX_LEN 48

static lv_obj_t *verify_screen = NULL;
static char *passphrase_copy = NULL;
static void (*back_callback)(void) = NULL;
static void (*rescan_callback)(void) = NULL;
static passphrase_verify_success_cb_t success_callback = NULL;

/* Compute the master fingerprint a passphrase would produce via the core key
 * module (seed512(mnemonic, passphrase) -> master key -> fingerprint).
 * Returns false on derivation failure. */
static bool
derive_passphrase_fingerprint(const char *passphrase,
                              char fp_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1]) {
  char *mnemonic = NULL;
  if (!key_get_mnemonic(&mnemonic))
    return false;
  bool ok =
      key_mnemonic_passphrase_fingerprint_hex(mnemonic, passphrase, fp_hex);
  SECURE_FREE_STRING(mnemonic);
  return ok;
}

static void confirm_btn_cb(lv_event_t *e) {
  (void)e;
  passphrase_verify_success_cb_t cb = success_callback;
  /* Hand off first: the success handler copies the string and tears down the
   * entry page. The verify page is destroyed after, releasing our copy. */
  if (cb && passphrase_copy)
    cb(passphrase_copy);
  passphrase_verify_page_destroy();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  void (*cb)(void) = back_callback;
  passphrase_verify_page_destroy();
  if (cb)
    cb();
}

static void rescan_btn_cb(lv_event_t *e) {
  (void)e;
  void (*cb)(void) = rescan_callback;
  passphrase_verify_page_destroy();
  if (cb)
    cb();
}

void passphrase_verify_page_create(lv_obj_t *parent, const char *passphrase,
                                   bool allow_rescan, void (*back_cb)(void),
                                   void (*rescan_cb)(void),
                                   passphrase_verify_success_cb_t success_cb) {
  (void)parent;
  /* The page takes ownership of `passphrase` (heap-allocated, NUL-terminated)
   * and zeroizes it on destroy. Free it on any early-exit path so the caller
   * never has to. */
  char *owned = (char *)passphrase;
  if (!passphrase || !success_cb) {
    SECURE_FREE_STRING(owned);
    return;
  }
  if (strlen(passphrase) > PASSPHRASE_MAX_LEN) {
    SECURE_FREE_STRING(owned);
    return;
  }

  back_callback = back_cb;
  rescan_callback = allow_rescan ? rescan_cb : NULL;
  success_callback = success_cb;

  passphrase_copy = owned;

  verify_screen = theme_create_page_container(lv_screen_active());

  theme_create_page_title(verify_screen, "Verify Passphrase");

  ui_create_back_button(verify_screen, back_btn_cb);

  /* Passphrase preview — full string when short, truncated with ellipsis
   * otherwise. The fingerprint transition below is the real verification. */
  char preview[PREVIEW_MAX_LEN + 1];
  size_t len = strlen(passphrase);
  if (len <= PREVIEW_MAX_LEN) {
    strcpy(preview, passphrase);
  } else {
    memcpy(preview, passphrase, PREVIEW_MAX_LEN - 3);
    preview[PREVIEW_MAX_LEN - 3] = '.';
    preview[PREVIEW_MAX_LEN - 2] = '.';
    preview[PREVIEW_MAX_LEN - 1] = '.';
    preview[PREVIEW_MAX_LEN] = '\0';
  }
  lv_obj_t *preview_label = theme_create_label(verify_screen, preview, false);
  lv_obj_set_width(preview_label, LV_PCT(90));
  lv_obj_set_style_text_align(preview_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(preview_label, LV_ALIGN_TOP_MID, 0,
               theme_corner_button_height() + theme_default_padding());

  /* Fingerprint transition: [base] -> [passphrase]. */
  char base_fp[BIP32_KEY_FINGERPRINT_LEN * 2 + 1] = "????????";
  if (!key_get_fingerprint_hex(base_fp))
    strcpy(base_fp, "--------");

  char derived_fp[BIP32_KEY_FINGERPRINT_LEN * 2 + 1] = "????????";
  if (!derive_passphrase_fingerprint(passphrase, derived_fp))
    strcpy(derived_fp, "--------");

  lv_obj_t *fp_row = theme_create_flex_row(verify_screen);
  lv_obj_set_style_pad_column(fp_row, 8, 0);
  lv_obj_align(fp_row, LV_ALIGN_TOP_MID, 0,
               theme_corner_button_height() + theme_default_padding() * 3 +
                   theme_min_touch_size());

  theme_create_label(fp_row, base_fp, true);
  lv_obj_t *arrow = theme_create_label(fp_row, ">", true);
  lv_obj_set_style_text_color(arrow, secondary_color(), 0);
  theme_create_label(fp_row, derived_fp, false);

  /* Buttons. */
  lv_obj_t *btn_row =
      theme_create_button_row(verify_screen, theme_button_spacing());
  lv_obj_align(btn_row, LV_ALIGN_BOTTOM_MID, 0, -theme_default_padding());

  theme_create_button(btn_row, "Confirm", true);

  if (rescan_callback) {
    theme_create_button(btn_row, "Rescan", false);
  }
  theme_create_button(btn_row, "Back", false);

  /* Wire button clicks: the row's children are created in order, Confirm is
   * first. */
  lv_obj_t *confirm_btn = lv_obj_get_child(btn_row, 0);
  lv_obj_add_event_cb(confirm_btn, confirm_btn_cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *back_btn =
      lv_obj_get_child(btn_row, lv_obj_get_child_cnt(btn_row) - 1);
  lv_obj_add_event_cb(back_btn, back_btn_cb, LV_EVENT_CLICKED, NULL);

  if (rescan_callback) {
    lv_obj_t *rescan_btn = lv_obj_get_child(btn_row, 1);
    lv_obj_add_event_cb(rescan_btn, rescan_btn_cb, LV_EVENT_CLICKED, NULL);
  }
}

void passphrase_verify_page_show(void) {
  if (verify_screen)
    lv_obj_clear_flag(verify_screen, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_verify_page_hide(void) {
  if (verify_screen)
    lv_obj_add_flag(verify_screen, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_verify_page_destroy(void) {
  if (verify_screen) {
    lv_obj_del(verify_screen);
    verify_screen = NULL;
  }
  SECURE_FREE_STRING(passphrase_copy);
  back_callback = NULL;
  rescan_callback = NULL;
  success_callback = NULL;
}
