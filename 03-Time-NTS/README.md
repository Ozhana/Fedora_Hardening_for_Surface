# 03 — AEGIS Time-NTS

**Version:** 0.2.0-rc4  
**Validated on:** Fedora 44 with chrony 4.8+  
**Arabic:** [README_AR.md](README_AR.md)

> AEGIS Time-NTS configures chrony to use authenticated Network Time Security (NTS). The goal is not merely “correct time”; the goal is to make the time source itself harder to spoof.

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Start here

Your computer trusts time for logs, certificates, package validation, and many security decisions.

Ordinary NTP can provide time without cryptographic authentication. NTS adds authentication between your machine and compatible time servers.

This layer configures and verifies NTS. It does not replace chrony; it hardens the chrony configuration you already use.

</td>
<td valign="top">

## Buradan başlayın

Bilgisayarınız loglar, sertifikalar, paket doğrulama ve birçok güvenlik kararı için saate güvenir.

Normal NTP zamanı kriptografik kimlik doğrulama olmadan sağlayabilir. NTS, bilgisayarınız ile uyumlu zaman sunucuları arasına kimlik doğrulama ekler.

Bu katman NTS'yi yapılandırır ve doğrular. Chrony'nin yerine geçmez; kullandığınız chrony yapılandırmasını sıkılaştırır.

</td>
</tr>
</table>

## Why NTS matters / NTS neden önemlidir?

~~~mermaid
flowchart LR
    A["Your computer<br/>Bilgisayarınız"] --> B["chronyd"]
    B -->|"NTS authenticated time"| C["Time servers<br/>Zaman sunucuları"]
    X["Untrusted network<br/>Güvenilmeyen ağ"] -. "cannot silently become a trusted NTS source" .-> B
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Before installation

This layer expects:

- Fedora 44
- chronyd already installed
- chronyd already enabled and running
- chrony 4.8 or newer in the supported 4.x series
- NTS support in chronyd
- working Internet access

The script does not install or update chrony automatically.

</td>
<td valign="top">

## Kurulumdan önce

Bu katman şunları bekler:

- Fedora 44
- chronyd önceden kurulu
- chronyd önceden enabled ve active
- desteklenen 4.x serisinde chrony 4.8 veya üzeri
- chronyd içinde NTS desteği
- çalışan Internet bağlantısı

Betik chrony'yi otomatik kurmaz veya güncellemez.

</td>
</tr>
</table>

## Installation / Kurulum

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/time-nts

sudo install -o root -g root -m 0755 \
  ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh

sudo restorecon -RFv /usr/local/libexec/aegis/time-nts
~~~

Create a short variable / Kısa değişken:

~~~bash
AEGIS_NTS=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## First run — understand the sequence

### Step 1 — Audit

<code>audit</code> inspects the current chrony service and configuration without changing them.

Use it to learn what chrony is doing before hardening.

</td>
<td valign="top">

## İlk çalıştırma — sırayı anlayın

### Adım 1 — Audit

<code>audit</code> mevcut chrony servisini ve yapılandırmasını değiştirmeden inceler.

Hardening öncesinde chrony'nin ne yaptığını görmek için kullanın.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" audit
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 2 — Plan

<code>plan</code> shows the proposed NTS configuration and its plan digest.

Read it before applying. A plan is a preview, not a security verdict.

</td>
<td valign="top">

### Adım 2 — Plan

<code>plan</code> önerilen NTS yapılandırmasını ve plan digest'ini gösterir.

Uygulamadan önce okuyun. Plan yalnızca ön izlemedir; güvenlik sonucu değildir.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" plan
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 3 — Apply

<code>apply</code> asks for confirmation, updates the managed chrony configuration, restarts chronyd, and then tries to prove that authenticated NTS traffic is actually working.

Network convergence can take a little time; do not confuse a temporary lack of selection with a configuration failure.

</td>
<td valign="top">

### Adım 3 — Uygula

<code>apply</code> onay ister, yönetilen chrony yapılandırmasını günceller, chronyd'yi yeniden başlatır ve ardından kimliği doğrulanmış NTS trafiğinin gerçekten çalıştığını kanıtlamaya çalışır.

Ağın oturması biraz zaman alabilir; geçici olarak kaynak seçilmemesini hemen yapılandırma arızası sanmayın.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" apply
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 4 — Verify

This is the most important daily command in this layer.

<code>verify</code> checks live source selection and NTS authentication evidence. <code>status</code> does not do that; status only reports transaction state.

</td>
<td valign="top">

### Adım 4 — Doğrula

Bu katmandaki en önemli kontrol komutu budur.

<code>verify</code> canlı kaynak seçimini ve NTS kimlik doğrulama kanıtını kontrol eder. <code>status</code> bunu yapmaz; status yalnız transaction durumunu gösterir.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
~~~

A healthy result looks similar to / Sağlıklı sonuç buna benzer:

~~~text
SOURCE ... NTS_key=yes authenticated_RX=yes fresh=yes ...
VERIFIED SNAPSHOT: authenticated/selectable=3, selected=..., remaining-correction<=0.1s=yes
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## How to read the result

- <code>NTS_key=yes</code> — an NTS key exists for that source
- <code>authenticated_RX=yes</code> — authenticated NTS packets were received
- <code>fresh=yes</code> — the evidence is recent enough for this verification
- <code>state=*</code> — currently selected source
- <code>state=+</code> — selectable/combined source

One selected source is normal. The others may remain available as authenticated alternatives.

</td>
<td valign="top">

## Sonuç nasıl okunur?

- <code>NTS_key=yes</code> — o kaynak için NTS anahtarı var
- <code>authenticated_RX=yes</code> — kimliği doğrulanmış NTS paketleri alındı
- <code>fresh=yes</code> — kanıt bu doğrulama için yeterince yeni
- <code>state=*</code> — şu anda seçilmiş kaynak
- <code>state=+</code> — seçilebilir/birleştirmeye katılan kaynak

Tek bir kaynağın seçili olması normaldir. Diğerleri kimliği doğrulanmış alternatif olarak hazır kalabilir.

</td>
</tr>
</table>

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Daily use

No daily <code>apply</code> is required.

Use <code>verify</code> when:

- you want to check time security
- after a reboot
- after a network change
- after a major chrony/Fedora update

</td>
<td valign="top">

## Günlük kullanım

Her gün <code>apply</code> çalıştırılmaz.

Şu durumlarda <code>verify</code> kullanın:

- zaman güvenliğini kontrol etmek istediğinizde
- reboot sonrasında
- ağ değişikliğinden sonra
- büyük chrony/Fedora güncellemesinden sonra

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Command guide

- <code>audit</code> — read-only inspection
- <code>plan</code> — preview the proposed NTS configuration
- <code>apply</code> — apply the reviewed plan
- <code>verify</code> — live NTS verification
- <code>status</code> — transaction status only
- <code>rollback</code> — restore the previous chrony configuration
- <code>--wait SECONDS</code> — change the live observation window
- <code>--help</code> — built-in help

</td>
<td valign="top">

## Komut rehberi

- <code>audit</code> — salt okunur inceleme
- <code>plan</code> — önerilen NTS yapılandırmasını gösterir
- <code>apply</code> — incelenen planı uygular
- <code>verify</code> — canlı NTS doğrulaması
- <code>status</code> — yalnız transaction durumu
- <code>rollback</code> — önceki chrony yapılandırmasını geri getirir
- <code>--wait SECONDS</code> — canlı gözlem süresini değiştirir
- <code>--help</code> — yerleşik yardım

</td>
</tr>
</table>

## Troubleshooting / Sorun giderme

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

**Verify does not pass immediately**  
Run it again after the sources have had time to reconnect.

**chronyd is not active**  
Check the service first. This module intentionally does not enable a disabled chronyd service for you.

**Unreviewed chronyd drop-in or option**  
Stop and inspect it. The script refuses unknown service modifications because they may change chrony's security meaning.

**Need to undo the change**  
Use the built-in rollback instead of manually replacing <code>chrony.conf</code>.

</td>
<td valign="top">

**Verify hemen geçmiyor**  
Kaynakların yeniden bağlanmasına fırsat verdikten sonra tekrar çalıştırın.

**chronyd aktif değil**  
Önce servisi kontrol edin. Bu modül kapalı bir chronyd servisini sizin yerinize bilinçsizce enable etmez.

**İncelenmemiş chronyd drop-in veya seçenek var**  
Durun ve inceleyin. Betik, chrony'nin güvenlik anlamını değiştirebilecek bilinmeyen servis değişikliklerini reddeder.

**Değişikliği geri almak gerekiyor**  
<code>chrony.conf</code> dosyasını elle değiştirmek yerine yerleşik rollback'i kullanın.

</td>
</tr>
</table>

Check chronyd / chronyd kontrolü:

~~~bash
systemctl status chronyd --no-pager
chronyc sources -v
~~~

Rollback / Geri alma:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" rollback
~~~

## What you learned / Ne öğrendiniz?

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

Correct time and authenticated time are not the same idea.

This layer teaches you to ask:

**“Where did this time come from, and can I verify the source?”**

</td>
<td valign="top">

Doğru saat ile kimliği doğrulanmış saat aynı şey değildir.

Bu katmanın öğrettiği temel soru şudur:

**“Bu zaman bilgisi nereden geldi ve kaynağı doğrulayabiliyor muyum?”**

</td>
</tr>
</table>
