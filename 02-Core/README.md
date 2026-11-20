# 02 — AEGIS Core

**Version:** 0.2.0-bash1  
**Validated on:** Fedora 44 — Surface Pro 9 (Intel/x86_64)  
**Arabic:** [README_AR.md](README_AR.md)

> AEGIS Core is the first hardening layer. It protects a small set of kernel/sysctl controls and can disable new systemd-coredump payload storage. It does not touch the firewall, DNS, NTS, packages, AIDE, rkhunter, or the bootloader.

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Start here

This layer is for people who want stronger defaults without blindly changing hundreds of settings.

You will learn three ideas:

1. **Plan before change**
2. **Apply only after review**
3. **Verify after reboot**

AEGIS Core is a one-time hardening layer. It is not a daemon and does not need a daily <code>apply</code>.

</td>
<td valign="top">

## Buradan başlayın

Bu katman, yüzlerce ayarı körlemesine değiştirmeden daha güvenli varsayılanlar isteyen kullanıcılar içindir.

Üç temel fikri öğreneceksiniz:

1. **Değiştirmeden önce planla**
2. **İnceledikten sonra uygula**
3. **Reboot sonrasında doğrula**

AEGIS Core bir kez uygulanıp bırakılan bir hardening katmanıdır. Daemon değildir ve her gün <code>apply</code> çalıştırılmaz.

</td>
</tr>
</table>

## How the layer works / Katman nasıl çalışır?

~~~mermaid
flowchart LR
    A["1. PLAN<br/>Ne değişecek?"] --> B["2. APPLY<br/>Kontrollü uygula"]
    B --> C["Kernel / sysctl<br/>+ coredump policy"]
    C --> D["3. VERIFY<br/>Canlı + kalıcı kontrol"]
    D --> E["REBOOT"]
    E --> F["4. VERIFY AGAIN<br/>Kalıcılığı doğrula"]
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## What does it protect?

AEGIS Core manages ten selected kernel/sysctl controls related to:

- protected links and files
- SUID core dumps
- kernel log visibility
- kernel pointer exposure
- ASLR
- unprivileged BPF
- ptrace restrictions

By default it also prevents new systemd-coredump payload storage.

It preserves stricter existing values where appropriate instead of forcing everything to one number.

</td>
<td valign="top">

## Neyi korur?

AEGIS Core şu alanlarla ilgili seçilmiş on kernel/sysctl kontrolünü yönetir:

- korumalı link ve dosyalar
- SUID core dump davranışı
- kernel log görünürlüğü
- kernel pointer görünürlüğü
- ASLR
- yetkisiz BPF
- ptrace kısıtlamaları

Varsayılan olarak yeni systemd-coredump payload saklamasını da kapatır.

Uygun yerlerde mevcut daha sıkı ayarları korur; her şeyi tek bir değere zorlamaz.

</td>
</tr>
</table>

Managed keys / Yönetilen anahtarlar:

~~~text
fs.protected_fifos
fs.protected_hardlinks
fs.protected_regular
fs.protected_symlinks
fs.suid_dumpable
kernel.dmesg_restrict
kernel.kptr_restrict
kernel.randomize_va_space
kernel.unprivileged_bpf_disabled
kernel.yama.ptrace_scope
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Before installation

Use this release on a normal, mutable Fedora 44 installation.

For the Surface Pro 9 profile:

- Intel/x86_64 Surface Pro 9
- SELinux already Enforcing
- firewalld already active
- CUPS/Avahi must not be masked

The script refuses unsupported environments rather than guessing.

</td>
<td valign="top">

## Kurulumdan önce

Bu sürümü normal, mutable Fedora 44 kurulumu üzerinde kullanın.

Surface Pro 9 profili için:

- Intel/x86_64 Surface Pro 9
- SELinux önceden Enforcing
- firewalld önceden aktif
- CUPS/Avahi maskeli olmamalı

Betik desteklenmeyen ortamda tahmin yürütmek yerine işlemi reddeder.

</td>
</tr>
</table>

## Installation / Kurulum

Open Terminal in this folder / Terminali bu klasörde açın:

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/core

sudo install -o root -g root -m 0755 \
  ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh

sudo restorecon -RFv /usr/local/libexec/aegis/core
~~~

Create a short shell variable / Kısa bir değişken tanımlayın:

~~~bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
~~~

Check the version / Sürümü kontrol edin:

~~~bash
/usr/bin/bash -p -- "$AEGIS_CORE" --version
~~~

Expected / Beklenen:

~~~text
0.2.0-bash1
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## First run — learn the workflow

### Step 1 — Plan

<code>plan</code> shows current values, target values, blockers, and the plan hash. It does not change the system.

Read the output. If you see a blocker, stop and solve that first.

</td>
<td valign="top">

## İlk çalıştırma — akışı öğrenin

### Adım 1 — Plan

<code>plan</code> mevcut değerleri, hedef değerleri, engelleri ve plan hash'ini gösterir. Sistemi değiştirmez.

Çıktıyı okuyun. Bir engel görürseniz önce onu çözün.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 2 — Apply

<code>apply</code> re-checks the plan, asks for confirmation, records rollback information, writes managed files atomically, and applies the live sysctl values.

Do not copy an old approval hash from another machine or another run.

</td>
<td valign="top">

### Adım 2 — Uygula

<code>apply</code> planı yeniden kontrol eder, onay ister, rollback bilgisini kaydeder, yönetilen dosyaları atomik yazar ve canlı sysctl değerlerini uygular.

Başka bir makineden veya eski bir çalıştırmadan plan hash'i kopyalamayın.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply \
  --profile surface-pro9
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 3 — Verify

<code>verify</code> checks both live kernel values and persistent configuration.

A successful command means **this layer** matches its intended policy. It is not a claim that the entire computer is perfectly secure.

</td>
<td valign="top">

### Adım 3 — Doğrula

<code>verify</code> hem canlı kernel değerlerini hem de kalıcı yapılandırmayı kontrol eder.

Başarılı sonuç **bu katmanın** hedef politikaya uyduğunu gösterir. Tüm bilgisayarın kusursuz güvenli olduğu anlamına gelmez.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
~~~

Reboot once, then run the same verify command again / Bir kez reboot edin ve aynı verify komutunu tekrar çalıştırın:

~~~bash
sudo systemctl reboot
~~~

After login / Oturum açtıktan sonra:

~~~bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh

sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Daily use

There is nothing to start every morning.

Recommended checks:

- after a reboot
- after a major Fedora/kernel/systemd update
- after installing another hardening tool
- when you suspect configuration drift

Running <code>apply</code> again on an already compliant system should produce no meaningful change.

</td>
<td valign="top">

## Günlük kullanım

Her sabah başlatmanız gereken bir şey yoktur.

Kontrol etmeniz yararlıdır:

- reboot sonrasında
- büyük Fedora/kernel/systemd güncellemesinden sonra
- başka bir hardening aracı kurduktan sonra
- ayarların değiştiğinden şüphelendiğinizde

Zaten uyumlu sistemde tekrar <code>apply</code> çalıştırmak anlamlı bir değişiklik üretmemelidir.

</td>
</tr>
</table>

Useful checks / Faydalı kontroller:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Command guide

- <code>audit</code> — read-only system inspection
- <code>plan</code> — preview changes
- <code>apply</code> — apply the reviewed plan
- <code>verify</code> — verify live and persistent state
- <code>history</code> — list transactions
- <code>rollback TX_ID</code> — restore a transaction
- <code>packages</code> — show required tools
- <code>--keep-coredumps</code> — do not create the coredump policy for this operation
- <code>--help</code> — built-in help

For a non-Surface Fedora 44 machine, use the <code>universal</code> profile instead of <code>surface-pro9</code>.

</td>
<td valign="top">

## Komut rehberi

- <code>audit</code> — salt okunur sistem incelemesi
- <code>plan</code> — değişiklikleri önceden gösterir
- <code>apply</code> — incelenen planı uygular
- <code>verify</code> — canlı ve kalıcı durumu doğrular
- <code>history</code> — transaction kayıtlarını listeler
- <code>rollback TX_ID</code> — bir işlemi geri alır
- <code>packages</code> — gereken araçları gösterir
- <code>--keep-coredumps</code> — bu işlemde coredump politikası oluşturmaz
- <code>--help</code> — yerleşik yardım

Surface olmayan Fedora 44 sisteminde <code>surface-pro9</code> yerine <code>universal</code> profilini kullanın.

</td>
</tr>
</table>

## Rollback / Geri alma

First list transactions / Önce işlemleri listeleyin:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
~~~

Then use the transaction ID / Sonra işlem kimliğini kullanın:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID
~~~

If the machine has rebooted since that transaction / O işlemden sonra reboot olduysa:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID \
  --files-only

sudo systemctl reboot
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Troubleshooting

**Plan reports a blocker**  
Do not force the script. Read the blocker and fix that prerequisite first.

**Existing managed file differs**  
The script is protecting you from overwriting a file that may belong to another tool or to a manual configuration.

**Verify fails after reboot**  
Run <code>plan</code> again. It will show which live or persistent value drifted.

**Partial transaction**  
Use <code>history</code> and the built-in rollback path. Do not delete the state directory as a shortcut.

</td>
<td valign="top">

## Sorun giderme

**Plan bir engel gösteriyor**  
Betiği zorlamayın. Engeli okuyun ve önce o önkoşulu düzeltin.

**Yönetilen dosya farklı**  
Betik başka bir araca veya elle yapılmış ayara ait olabilecek dosyanın üzerine yazmanızı engelliyor.

**Verify reboot sonrası geçmiyor**  
Tekrar <code>plan</code> çalıştırın. Hangi canlı veya kalıcı değerin değiştiğini gösterecektir.

**Yarım kalmış transaction**  
<code>history</code> ve yerleşik rollback yolunu kullanın. State dizinini kestirme olarak silmeyin.

</td>
</tr>
</table>

## What you learned / Ne öğrendiniz?

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

You have used a safe hardening workflow:

**observe → plan → approve → apply → verify → reboot → verify**

That pattern will appear again in later AEGIS layers.

</td>
<td valign="top">

Güvenli bir hardening iş akışı kullandınız:

**gözlemle → planla → onayla → uygula → doğrula → reboot → tekrar doğrula**

Aynı mantığı sonraki AEGIS katmanlarında da göreceksiniz.

</td>
</tr>
</table>
