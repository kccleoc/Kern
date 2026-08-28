#include "kef_key_verify.h"

#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"

#include <lvgl.h>
#include <string.h>

static lv_obj_t *verify_screen = NULL;
static char *key_copy = NULL;
static void (*back_callback)(void) = NULL;
static void (*rescan_callback)(void) = NULL;
static kef_key_verify_accept_cb_t accept_callback = NULL;

static void eye_btn_cb(lv_event_t *e) {
  lv_obj_t *preview = lv_event_get_user_data(e);
  if (!preview)
    return;
  bool hidden = lv_textarea_get_password_mode(preview);
  lv_textarea_set_password_mode(preview, !hidden);
  lv_obj_t *eye_label = lv_obj_get_child(lv_event_get_target(e), 0);
  if (eye_label)
    lv_label_set_text(eye_label,
                      hidden ? LV_SYMBOL_EYE_CLOSE : LV_SYMBOL_EYE_OPEN);
}

static void confirm_btn_cb(lv_event_t *e) {
  (void)e;
  kef_key_verify_accept_cb_t cb = accept_callback;
  /* Hand off first: the success handler copies the key and launches the
   * encryption. The verify page is destroyed after, releasing our copy. */
  if (cb && key_copy)
    cb(key_copy);
  kef_key_verify_page_destroy();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  void (*cb)(void) = back_callback;
  kef_key_verify_page_destroy();
  if (cb)
    cb();
}

static void rescan_btn_cb(lv_event_t *e) {
  (void)e;
  void (*cb)(void) = rescan_callback;
  kef_key_verify_page_destroy();
  if (cb)
    cb();
}

void kef_key_verify_page_create(const char *key, bool allow_rescan,
                                void (*back_cb)(void), void (*rescan_cb)(void),
                                kef_key_verify_accept_cb_t accept_cb) {
  /* The page takes ownership of `key` (heap-allocated, NUL-terminated) and
   * zeroizes it on destroy. Free it on any early-exit path so the caller
   * never has to. */
  char *owned = (char *)key;
  if (!key || key[0] == '\0' || !accept_cb) {
    SECURE_FREE_STRING(owned);
    return;
  }

  back_callback = back_cb;
  rescan_callback = allow_rescan ? rescan_cb : NULL;
  accept_callback = accept_cb;

  key_copy = owned;

  verify_screen = theme_create_page_container(lv_screen_active());

  theme_create_page_title(verify_screen, "Verify Key");

  ui_create_back_button(verify_screen, back_btn_cb);

  /* Masked preview with an eye toggle: the key itself is never shown at
   * rest; revealing is an explicit tap. */
  const int32_t ta_y = theme_small_padding() + theme_corner_button_height() +
                       theme_default_padding();
  lv_obj_t *preview = lv_textarea_create(verify_screen);
  lv_obj_set_size(preview, LV_PCT(80), 50);
  lv_obj_align(preview, LV_ALIGN_TOP_MID, 0, ta_y);
  lv_textarea_set_one_line(preview, true);
  lv_textarea_set_password_mode(preview, true);
  lv_textarea_set_text(preview, key);
  lv_obj_set_style_text_font(preview, theme_font_small(), 0);
  lv_obj_set_style_bg_color(preview, panel_color(), 0);
  lv_obj_set_style_text_color(preview, primary_color(), 0);
  lv_obj_set_style_border_color(preview, highlight_color(), 0);
  lv_obj_set_style_border_width(preview, 1, 0);
  lv_obj_set_style_bg_color(preview, highlight_color(), LV_PART_CURSOR);
  lv_obj_set_style_bg_opa(preview, LV_OPA_COVER, LV_PART_CURSOR);

  lv_obj_t *eye_btn = lv_btn_create(verify_screen);
  lv_obj_set_size(eye_btn, theme_min_touch_size(), theme_min_touch_size());
  lv_obj_align_to(eye_btn, preview, LV_ALIGN_OUT_RIGHT_MID, 5, 0);
  lv_obj_set_style_bg_opa(eye_btn, LV_OPA_TRANSP, 0);
  lv_obj_set_style_shadow_width(eye_btn, 0, 0);
  lv_obj_set_style_border_width(eye_btn, 0, 0);
  lv_obj_add_event_cb(eye_btn, eye_btn_cb, LV_EVENT_CLICKED, preview);

  lv_obj_t *eye_label = lv_label_create(eye_btn);
  lv_label_set_text(eye_label, LV_SYMBOL_EYE_OPEN);
  lv_obj_set_style_text_color(eye_label, secondary_color(), 0);
  lv_obj_set_style_text_font(eye_label, theme_font_small(), 0);
  lv_obj_center(eye_label);

  lv_obj_t *hint =
      theme_create_label(verify_screen, "Scanned encryption key", false);
  lv_obj_set_style_text_font(hint, theme_font_small(), 0);
  lv_obj_set_style_text_color(hint, secondary_color(), 0);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, ta_y + 50 + theme_default_padding());

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

void kef_key_verify_page_show(void) {
  if (verify_screen)
    lv_obj_clear_flag(verify_screen, LV_OBJ_FLAG_HIDDEN);
}

void kef_key_verify_page_destroy(void) {
  if (verify_screen) {
    lv_obj_del(verify_screen);
    verify_screen = NULL;
  }
  SECURE_FREE_STRING(key_copy);
  back_callback = NULL;
  rescan_callback = NULL;
  accept_callback = NULL;
}
