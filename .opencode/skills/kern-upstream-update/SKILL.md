---
name: kern-upstream-update
description: Update the Kern fork from upstream (odudex/Kern), resolve merge conflicts while preserving custom features, let GitHub Actions build the firmware, and flash the default wave_35 target to the ESP32-P4 board. Use when the user mentions upstream, sync, merge, odudex, conflict resolution, GitHub Actions build, firmware artifact, or flashing the board.
---

# Kern upstream update, merge, CI build, flash

Kern is a fork (`kccleoc/Kern`) of `odudex/Kern`, an ESP32-P4 Bitcoin hardware
wallet. The fork carries custom features that must survive every upstream merge.
The build/CI/flash pipeline below is the reliable path on this machine — **the
firmware is built by GitHub Actions, never locally**.

## Repo layout

- Working dir: `/Volumes/Crucial2T/Mac/leo_temp/Kern`
- `origin` = https://github.com/kccleoc/Kern.git (fork, `master` tracks `origin/master`)
- `upstream` = https://github.com/odudex/Kern.git
- `git config rerere.enabled` = `true` (conflict resolutions are remembered; re-merge cleanly)
- `gh` is authenticated as `kccleoc`. Workflows live in `.github/workflows/`.

## Custom features to preserve on every merge

The fork diverges from upstream in these areas. After any merge, confirm they
still exist and are wired onto upstream's current APIs:

1. **Passphrase QR scan + word-list passphrase validation** (login flow).
2. **KEF encryption-key QR scan** on both encrypt and decrypt paths
   (`main/pages/shared/kef_encrypt_page.c`, `kef_decrypt_page.c`,
   `kef_key_verify.h`).
3. **Custom host test** `test_passphrase_words` (in `main/core/test/`), kept
   alongside upstream's `test_kef`.

General rule when conflict-resolving: **upstream is source of truth for
infrastructure/mechanics** (task management, watchdog, IDF APIs, build
infra); the fork keeps its UI features (scan-by-QR, word-list passphrase) and
re-wires them onto upstream's new APIs.

## Golden rule: never build firmware locally

This Mac has **no usable ESP-IDF v6 toolchain**:
- No `idf.py`/`just` on PATH, no `~/esp/esp-idf`.
- `~/.espressif` only has IDF v5.1/v5.4 installs for the wrong target
  (esp32s3) plus orphaned toolchain binaries.

Do **not** retry locating/installing the toolchain (user has declined this
before). Use GitHub Actions instead. The local `.justfile` commands
(`just build <board>`, `just flash <board>`, `just test`) are only useful on a
machine with `IDF_PATH=$HOME/esp/esp-idf` set up.

## Workflow

### 1. Fetch and review upstream

```bash
git fetch upstream
git log --oneline origin/master..upstream/master        # what you will bring in
git log --oneline upstream/master..origin/master        # your custom commits
```

Upstream releases are tagged (`0.0.x`) and may add branches (e.g.
`chore/idf-6.1`, `hw-pbkdf2`) that are not yet on `master` — only merge
`upstream/master`.

### 2. Merge (merge, never rebase)

```bash
git merge upstream/master
```

Resolve conflicts. Known recurring conflicts and their resolutions:

| File | Resolution |
|---|---|
| `main/core/test/Makefile` | Keep **both** `SRCS_PP`/`TARGET_PP` (`test_passphrase_words`, custom) and `SRCS_KEF`/`TARGET_KEF` (`test_kef`, upstream). Add `TARGET_KEF` alongside `TARGET_PP` in `all:`, `run:`, `clean:`. |
| `main/core/test/.gitignore` | Union: keep both `test_passphrase_words` and `test_kef` entries. |
| `main/pages/shared/kef_encrypt_page.c` | Upstream removed the old task plumbing (`encrypt_task`, `encrypt_task_handle`, `xTaskCreatePinnedToCore`) and moved to a watchdog-safe `worker_task_start()` (`../../utils/worker_task.h`). The custom encrypt task function becomes the callback arg: `worker_task_start("kef_enc", <encrypt_fn>, <arg>);`. Union includes: `kef_key_verify.h` + `worker_task.h`. |
| `main/pages/shared/kef_decrypt_page.c` | Same: use `worker_task_start`; drop unused `<esp_task_wdt.h>`/FreeRTOS includes (they break the host simulator build). |

For unexpected conflicts: keep the custom feature, port it onto the upstream
API — never delete the fork feature to win a merge.

### 3. Verify the merge

```bash
git diff --check                     # whitespace errors
rg '^(<<<<<<<|=======|>>>>>>>)' --glob '!**/*.md' .   # leftover markers
git status                           # no unmerged paths
```

`git rerere` records resolutions automatically, so subsequent merges of the
same hunks resolve cleanly. Commit the merge (message like
`Merge remote-tracking branch 'upstream/master'`).

### 4. Push — this triggers CI

```bash
git push origin master
```

### 5. Wait for the fork's GitHub Actions builds

Pushing to `master` triggers two workflows on the fork:

- **Test All Builds** (`test-all-builds.yml`): matrix build of all 6 boards
  (`wave_4b`, `wave_35`, `wave_5`, `wave_43`, `crowpanel`, `wave_7b`) inside
  `espressif/idf:v6.0.2`; uploads one `firmware-<board>` artifact each. Then a
  `deploy-site` job follows.
- **GitHub Actions test** (`github-actions-test.yml`): `format-check`
  (`./scripts/format.sh --check`) + host tests (`./scripts/test.sh`, runs
  `test_passphrase_words` and `test_kef`).

```bash
gh run list --repo kccleoc/Kern --branch master --limit 3
```

**`deploy-site` always fails on the fork** (GitHub Pages is not enabled for
`kccleoc/Kern`) — ignore it. Judge success by the individual `build (<board>)`
and `GitHub Actions test` job conclusions, not the overall run status.

Poll the board's build job (about 6 minutes):

```bash
# NB: `status` is a read-only variable in zsh — use another name (e.g. st).
for i in $(seq 1 40); do
  st=$(gh run view <RUN_ID> --repo kccleoc/Kern --json jobs \
       --jq '.jobs[] | select(.name|startswith("build (wave_35")) | .status')
  [ "$st" = "completed" ] && break
  sleep 15
done
```

### 6. Download the artifact for the flash target

The default flash target is **wave_35** — always flash `firmware-wave_35`
unless the user explicitly names a different board. Artifacts from
`gh run download` land **directly in the current directory** (no
`firmware-<board>/` subfolder):

```bash
mkdir -p /var/folders/p5/n8z83tm96tzdcqshfp8yflyh0000gn/T/opencode/kern-fw
cd /var/folders/p5/n8z83tm96tzdcqshfp8yflyh0000gn/T/opencode/kern-fw
gh run download <RUN_ID> --repo kccleoc/Kern -n firmware-wave_35
```

Files: `bootloader.bin`, `partition-table.bin`, `ota_data_initial.bin`,
`kern.bin` (plus `kern-unsigned.bin`, `kern.elf`, `kern.map`, `flash_args`,
`flasher_args.json`).

### 7. Flash with esptool

Device port: `/dev/cu.usbmodem5AE60365571`. Use `esptool` (the `.py` suffix is
deprecated). Use the offsets from `flash_args`/`flasher_args.json`, but the
flattened download needs plain filenames (the file references
`bootloader/bootloader.bin` paths):

```bash
esptool --chip esp32p4 --port /dev/cu.usbmodem5AE60365571 --baud 460800 \
  --before default-reset --after hard-reset write_flash \
  --flash-mode dio --flash-freq 80m --flash-size keep \
  0x2000 bootloader.bin \
  0x10000 partition-table.bin \
  0x1e000 ota_data_initial.bin \
  0x20000 kern.bin
```

All images are hash-verified; a hard reset follows automatically. The CI build
is signed with the CI's per-clone throwaway dev signing key; **USB flashing is
unaffected** by the signing key (secure boot is not enabled). Only SD-card
updates must come from the same clone.

### 8. Smoke-test the custom flows on device

After flashing, verify the fork's features survived: passphrase QR scan +
word-list passphrase, and KEF key scan on both encrypt and decrypt.

## Pitfalls checklist (do not retry these)

- Do **not** hunt for/install a local ESP-IDF v6 — CI is the build path.
- Do **not** try to make `deploy-site`/GitHub Pages pass on the fork; it can't.
- Do **not** use `esptool.py` (deprecated) — use `esptool`.
- Do **not** name a shell variable `status` in zsh (read-only) — it aborts the loop.
- Do **not** expect `gh run download` to create a `firmware-<board>/` folder —
  files drop into cwd; translate `flash_args` paths to local filenames.
- Do **not** flash all six board artifacts — only the default `wave_35` target
  (unless the user names another board).
- Do **not** rebase `master` onto upstream; always merge (history stays simple,
  rerere keeps resolutions).