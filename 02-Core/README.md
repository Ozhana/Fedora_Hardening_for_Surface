# 02 — AEGIS Core

**Version:** `0.2.0-bash1`  
**Tested on:** Fedora 44, Surface Pro 9 (Intel/x86_64)  
**Arabic guide:** [README_AR.md](README_AR.md)

AEGIS Core is the basic system-hardening layer. It applies a small set of kernel/sysctl protections and can disable new `systemd-coredump` payload storage. It does **not** change your firewall, DNS, NTS, packages, bootloader, AIDE, or rkhunter.

> This layer is meant to be installed once and then left in place. You do not need to run `apply` every day.

## English

### 1. Install

Open Terminal in this folder and run:

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/core

sudo install -o root -g root -m 0755 \
  ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh

sudo restorecon -RFv /usr/local/libexec/aegis/core
```

Set a short command variable:

```bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
```

### 2. First use

For a Surface Pro 9:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9
```

Read the plan. If there are no blockers:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply \
  --profile surface-pro9
```

The script asks for confirmation before changing the system.

Then verify:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
```

Reboot once and run the same `verify` command again.

For other supported Fedora 44 systems, use:

```bash
--profile universal
```

instead of `--profile surface-pro9`.

### 3. Normal use

No daily action is required.

Useful checks after a reboot or major system update:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

A second `apply` on an already-compliant system should be a no-op.

### 4. Commands

- `audit` — read-only inspection.
- `plan` — shows what would change. Does not change the system.
- `apply` — applies the reviewed plan.
- `verify` — checks live and persistent Core settings.
- `history` — lists previous transactions.
- `rollback TX_ID` — restores the newest applicable transaction.
- `packages` — shows required tools; nothing is installed automatically.
- `--keep-coredumps` — keeps coredump handling unchanged for this plan/apply/verify.
- `--help` / `--version` — help and version information.

### 5. If something goes wrong

First, do **not** delete AEGIS files manually.

Check:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

If you need to undo the last transaction:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID
```

If the computer has already rebooted since that transaction, use:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID \
  --files-only

sudo systemctl reboot
```

---

## Türkçe

### 1. Kurulum

Terminali bu klasörde açın ve çalıştırın:

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/core

sudo install -o root -g root -m 0755 \
  ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh

sudo restorecon -RFv /usr/local/libexec/aegis/core
```

Kısa kullanım değişkenini tanımlayın:

```bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
```

### 2. İlk kullanım

Surface Pro 9 için:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9
```

Planı okuyun. Engel yoksa:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply \
  --profile surface-pro9
```

Betik sistemi değiştirmeden önce sizden onay ister.

Sonra doğrulayın:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
```

Bir kez yeniden başlatın ve aynı `verify` komutunu tekrar çalıştırın.

Diğer desteklenen Fedora 44 sistemlerde:

```bash
--profile universal
```

kullanın.

### 3. Günlük kullanım

Her gün bir şey yapmanız gerekmez.

Reboot veya büyük sistem güncellemesinden sonra kontrol etmek için:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

Sistem zaten uygunsa ikinci `apply` değişiklik yapmamalıdır.

### 4. Komutlar

- `audit` — salt okunur inceleme.
- `plan` — ne değişeceğini gösterir; sistemi değiştirmez.
- `apply` — incelenen planı uygular.
- `verify` — canlı ve kalıcı Core ayarlarını doğrular.
- `history` — eski işlemleri listeler.
- `rollback TX_ID` — uygun son işlemi geri alır.
- `packages` — gereken araçları gösterir; otomatik kurulum yapmaz.
- `--keep-coredumps` — bu işlemde coredump ayarına dokunmaz.
- `--help` / `--version` — yardım ve sürüm bilgisi.

### 5. Sorun olursa

Önce AEGIS dosyalarını elle silmeyin.

Kontrol edin:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

Son işlemi geri almak gerekirse:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID
```

İşlemden sonra bilgisayar yeniden başlatıldıysa:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID \
  --files-only

sudo systemctl reboot
```

> AEGIS seçili saldırı yüzeylerini azaltır; tek başına tüm sistemi “güvenli” ilan etmez.
