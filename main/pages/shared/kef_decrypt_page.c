/*
 * KEF Decrypt Page
 * Key entry (typed or scanned from QR) + decryption for KEF-encrypted data.
 * Follows the same pattern as passphrase.c.
 *
 * Decryption (PBKDF2 with 100k+ iterations) runs on a worker task (see
 * utils/worker_task.h) to avoid triggering the watchdog on the LVGL task.
 * An LVGL timer polls for completion and handles the result on the UI thread.
 */

#include "kef_decrypt_page.h"
#include "../../core/kef.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "kef_key_verify.h"
#include "../../utils/worker_task.h"
#include "text_input_scan.h"
#include <stdlib.h>
#include <string.h>

#define DECRYPT_TASK_STACK_SIZE 8192

static lv_obj_t *kef_screen = NULL;
static lv_obj_t *progress_dialog = NULL;
static ui_text_input_t text_input = {0};
static lv_timer_t *poll_timer = NULL;

static void (*return_callback)(void) = NULL;
static kef_decrypt_success_cb_t success_callback = NULL;

static uint8_t *envelope_copy = NULL;
static size_t envelope_copy_len = 0;
static uint8_t *key_copy = NULL;
static size_t key_copy_len = 0;
static uint8_t *decrypted_data = NULL;
static size_t decrypted_len = 0;

/* Shared state between the worker task and the LVGL timer */
static volatile bool decrypt_done = false;
static kef_error_t decrypt_result = KEF_OK;

static void show_input(void) {
  /* Re-shows the page too: the scanner and verify flows hide it while the
   * key entry screen stays alive underneath, and the retry path after a
   * failed decrypt must land back on a visible page either way. */
  kef_decrypt_page_show();
  ui_text_input_show(&text_input);
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

static void show_loading(void) {
  ui_text_input_hide(&text_input);
  progress_dialog =
      dialog_show_progress("KEF", "Decrypting...", DIALOG_STYLE_OVERLAY);
}

/* Runs on the worker task — does NOT touch LVGL */
static void decrypt_work(void) {
  /* Free any previous decrypted data */
  if (decrypted_data) {
    SECURE_FREE_BUFFER(decrypted_data, decrypted_len);
    decrypted_len = 0;
  }

  decrypt_result = kef_decrypt(envelope_copy, envelope_copy_len, key_copy,
                               key_copy_len, &decrypted_data, &decrypted_len);

  /* Zero key immediately after use */
  SECURE_FREE_BUFFER(key_copy, key_copy_len);
  key_copy_len = 0;
}

/* LVGL timer polls for decrypt task completion */
static void poll_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!decrypt_done)
    return;

  /* Task finished — stop polling */
  lv_timer_del(poll_timer);
  poll_timer = NULL;

  if (decrypt_result == KEF_OK) {
    if (success_callback)
      success_callback(decrypted_data, decrypted_len);
    return;
  }

  /* Show error and let user retry */
  show_input();
  if (text_input.textarea)
    lv_textarea_set_text(text_input.textarea, "");

  if (decrypt_result == KEF_ERR_AUTH) {
    dialog_show_error_timeout("Wrong key", NULL, 0);
  } else {
    dialog_show_error_timeout(kef_error_str(decrypt_result), NULL, 0);
  }
}

/* Copy key into key_copy and launch decryption on CPU 1 to keep LVGL
 * (CPU 0) responsive. Shows its own error dialogs on failure. */
static bool start_decrypt(const char *key, size_t len) {
  key_copy = malloc(len);
  if (!key_copy) {
    dialog_show_error_timeout("Out of memory", NULL, 0);
    return false;
  }
  memcpy(key_copy, key, len);
  key_copy_len = len;

  lv_textarea_set_text(text_input.textarea, "");
  show_loading();

  decrypt_done = false;
  if (!worker_task_start("kef_dec", DECRYPT_TASK_STACK_SIZE, decrypt_work,
                         &decrypt_done)) {
    /* Fallback: if task creation fails, clean up and show error */
    SECURE_FREE_BUFFER(key_copy, key_copy_len);
    key_copy_len = 0;
    show_input();
    dialog_show_error_timeout("Task creation failed", NULL, 0);
    return false;
  }

  /* Poll every 100ms for task completion */
  poll_timer = lv_timer_create(poll_timer_cb, 100, NULL);
  return true;
}

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;

  start_decrypt(text, strlen(text));
}

/* ---------- Scan key path (via text_input_scan + Verify Key page) ---------- */

/* The page stays alive (hidden) under the scanner and the verify page, so
 * the envelope survives Cancel and Back. */

/* Forward: the keyboard scan key captures via text_input_scan, then
 * scan_loaded_cb routes the result to the Verify Key page. */
static void start_key_scan(void);
static void scan_loaded_cb(void);
static void verify_back_cb(void);
static void verify_rescan_cb(void);
static void verify_accept_cb(const char *key);

/* text_input_scan loaded callback: the scanned key is already in the
 * textarea (validated as text/UTF-8 with any trailing newline stripped).
 * Enforce the length cap, then hand off to the Verify Key page instead of
 * leaving the secret in the entry field. */
static void scan_loaded_cb(void) {
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;
  if (strlen(text) > KEF_KEY_MAX_LEN) {
    dialog_show_error_timeout("Key too long", NULL, 0);
    lv_textarea_set_text(text_input.textarea, "");
    return;
  }

  char *copy = strdup(text);
  lv_textarea_set_text(text_input.textarea, "");
  if (!copy) {
    dialog_show_error_timeout("Out of memory", NULL, 0);
    return;
  }

  kef_key_verify_page_create(copy, true, verify_back_cb, verify_rescan_cb,
                             verify_accept_cb);
  kef_key_verify_page_show();
}

static void start_key_scan(void) {
  text_input_scan_cfg_t cfg = {&text_input, kef_decrypt_page_hide,
                               kef_decrypt_page_show, scan_loaded_cb};
  text_input_scan_start(&cfg);
}

/* The verify page has already been destroyed by the time these run. */
static void verify_back_cb(void) { kef_decrypt_page_show(); }

static void verify_rescan_cb(void) { start_key_scan(); }

static void verify_accept_cb(const char *key) {
  if (!start_decrypt(key, strlen(key)))
    kef_decrypt_page_show();
}

static void scan_key_cb(void *user_data) {
  (void)user_data;
  start_key_scan();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void kef_decrypt_page_create(lv_obj_t *parent, void (*return_cb)(void),
                             kef_decrypt_success_cb_t success_cb,
                             const uint8_t *envelope, size_t envelope_len) {
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  /* Copy envelope data */
  envelope_copy = malloc(envelope_len);
  if (!envelope_copy)
    return;
  memcpy(envelope_copy, envelope, envelope_len);
  envelope_copy_len = envelope_len;

  /* Parse KEF ID for the title */
  const uint8_t *id = NULL;
  size_t id_len = 0;
  uint8_t version;
  uint32_t iterations;
  const char *prefix = "Enter Key for: ";
  char title[64] = "Enter Key";
  if (kef_parse_header(envelope, envelope_len, &id, &id_len, &version,
                       &iterations) == KEF_OK &&
      id_len > 0) {
    size_t prefix_len = strlen(prefix);
    size_t copy_len = id_len < sizeof(title) - prefix_len - 1
                          ? id_len
                          : sizeof(title) - prefix_len - 1;
    memcpy(title, prefix, prefix_len);
    memcpy(title + prefix_len, id, copy_len);
    title[prefix_len + copy_len] = '\0';
  }

  /* Screen */
  kef_screen = theme_create_page_container(lv_screen_active());

  /* Title — shows KEF ID if available */
  theme_create_page_title(kef_screen, title);

  /* Back button */
  ui_create_back_button(kef_screen, back_btn_cb);

  /* Text input (textarea + eye toggle + keyboard, with scan key) */
  ui_text_input_create(&text_input, kef_screen, "key", true, keyboard_ready_cb);
  ui_text_input_enable_scan(&text_input, scan_key_cb, NULL);

  progress_dialog = NULL;
}

void kef_decrypt_page_show(void) {
  if (kef_screen)
    lv_obj_clear_flag(kef_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void kef_decrypt_page_hide(void) {
  if (kef_screen)
    lv_obj_add_flag(kef_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void kef_decrypt_page_destroy(void) {
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  decrypt_done = false;
  ui_text_input_destroy(&text_input);
  if (kef_screen) {
    lv_obj_del(kef_screen);
    kef_screen = NULL;
  }
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }

  SECURE_FREE_BUFFER(envelope_copy, envelope_copy_len);
  envelope_copy_len = 0;
  SECURE_FREE_BUFFER(key_copy, key_copy_len);
  key_copy_len = 0;
  SECURE_FREE_BUFFER(decrypted_data, decrypted_len);
  decrypted_len = 0;

  return_callback = NULL;
  success_callback = NULL;
}
