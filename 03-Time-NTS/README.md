# 03 — AEGIS Time-NTS

**Version:** `0.2.0-rc4`  
**Tested on:** Fedora 44 with chrony 4.8+  
**Arabic guide:** [README_AR.md](README_AR.md)

AEGIS Time-NTS configures `chronyd` to use authenticated Network Time Security (NTS). This helps prevent an untrusted network from silently feeding your computer unauthenticated time.

> Install once, apply once, then leave it alone. `chronyd` continues working normally in the background.

## English

### 1. Before you start

This layer expects:

- Fedora 44.
- `chronyd` already installed, enabled, and running.
- chrony 4.8+ with NTS support.
- working Internet access.

The script does not install packages automatically.

### 2. Install

Open Terminal in this folder:

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/time-nts

sudo install -o root -g root -m 0755 \
  ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh

sudo restorecon -RFv /usr/local/libexec/aegis/time-nts
```

Set a short command variable:

```bash
AEGIS_NTS=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
```

### 3. First use

Inspect the system:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" audit
```

Preview the change:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" plan
```

If the plan is clean:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" apply
```

Then verify:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

A healthy result ends with a line similar to:

```text
VERIFIED SNAPSHOT: authenticated/selectable=3 ...
```

### 4. Normal use

No daily command is required.

Use this when you want to check NTS:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

`status` only reports transaction state; it is **not** a live NTS security check.

### 5. Commands

- `audit` — read-only inspection.
- `plan` — shows the proposed NTS configuration.
- `apply` — applies the plan after confirmation.
- `verify` — checks live authenticated NTS sources.
- `status` — shows transaction status only.
- `rollback` — restores the previous chrony configuration.
- `--wait SECONDS` — changes the live verification wait time.
- `--help` — built-in help.

### 6. If something goes wrong

If `verify` does not pass immediately, wait briefly and run it again. NTS sources may need time to reconnect.

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

Check chrony:

```bash
systemctl status chronyd --no-pager
chronyc sources -v
```

To restore the previous configuration:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" rollback
```

Do not manually delete `/etc/chrony.conf` or the AEGIS transaction state while recovery is pending.

---

## Türkçe

### 1. Başlamadan önce

Bu katman şunları bekler:

- Fedora 44.
- `chronyd` önceden kurulu, enabled ve active.
- NTS destekli chrony 4.8+.
- Çalışan Internet bağlantısı.

Betik otomatik paket kurmaz.

### 2. Kurulum

Terminali bu klasörde açın:

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/time-nts

sudo install -o root -g root -m 0755 \
  ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh

sudo restorecon -RFv /usr/local/libexec/aegis/time-nts
```

Kısa kullanım değişkenini tanımlayın:

```bash
AEGIS_NTS=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
```

### 3. İlk kullanım

Önce inceleyin:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" audit
```

Planı görün:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" plan
```

Plan temizse:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" apply
```

Sonra doğrulayın:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

Sağlıklı sonuç genellikle şu satırla biter:

```text
VERIFIED SNAPSHOT: authenticated/selectable=3 ...
```

### 4. Günlük kullanım

Her gün komut çalıştırmanız gerekmez.

NTS'yi kontrol etmek istediğinizde:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

`status` yalnız transaction durumunu gösterir; canlı NTS güvenlik doğrulaması değildir.

### 5. Komutlar

- `audit` — salt okunur inceleme.
- `plan` — uygulanacak NTS yapılandırmasını gösterir.
- `apply` — onaydan sonra planı uygular.
- `verify` — canlı ve kimliği doğrulanmış NTS kaynaklarını kontrol eder.
- `status` — yalnız transaction durumunu gösterir.
- `rollback` — önceki chrony yapılandırmasını geri getirir.
- `--wait SECONDS` — canlı doğrulama bekleme süresini değiştirir.
- `--help` — yerleşik yardım.

### 6. Sorun olursa

`verify` hemen geçmezse kısa süre bekleyip tekrar deneyin. NTS kaynaklarının yeniden bağlanması zaman alabilir.

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

Chrony durumunu kontrol edin:

```bash
systemctl status chronyd --no-pager
chronyc sources -v
```

Önceki yapılandırmaya dönmek için:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" rollback
```

Recovery beklerken `/etc/chrony.conf` veya AEGIS transaction kayıtlarını elle silmeyin.
