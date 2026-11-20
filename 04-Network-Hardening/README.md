# 04 — AEGIS Network Hardening

**Version:** 0.7.0-rc4  
**Validated on:** Fedora 44 — Surface Pro 9 — firewalld + nftables  
**Arabic:** [README_AR.md](README_AR.md)

> This layer reduces unnecessary inbound network exposure while preserving normal Internet access and common printer discovery/client traffic on the reviewed local connection.

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Start here

Fedora Workstation is designed to be convenient on many kinds of networks. A security-focused laptop may prefer a narrower inbound policy.

AEGIS Network Hardening creates two clear trust levels:

- **aegis-public** — restrictive fallback
- **aegis-lan** — your reviewed physical connection, with printer discovery/client support

It removes inbound SSH, Samba/NetBIOS, and blanket high-port allowances from the selected physical profile.

</td>
<td valign="top">

## Buradan başlayın

Fedora Workstation birçok ağda kolay kullanım için tasarlanmıştır. Güvenlik odaklı bir dizüstü bilgisayarda daha dar bir inbound politika tercih edilebilir.

AEGIS Network Hardening iki açık güven seviyesi oluşturur:

- **aegis-public** — kısıtlı varsayılan/fallback bölge
- **aegis-lan** — incelenmiş fiziksel bağlantınız; yazıcı keşfi/istemci desteği korunur

Seçilen fiziksel profilden inbound SSH, Samba/NetBIOS ve geniş yüksek-port izinlerini kaldırır.

</td>
</tr>
</table>

## Mental model / Zihinsel model

~~~mermaid
flowchart TD
    N["Network connection<br/>Ağ bağlantısı"] --> Q{"Reviewed physical profile?<br/>İncelenmiş fiziksel profil mi?"}
    Q -->|"Yes / Evet"| L["aegis-lan<br/>Printer discovery/client allowed"]
    Q -->|"No / Hayır"| P["aegis-public<br/>Restrictive fallback"]
    L --> F["firewalld + nftables"]
    P --> F
    F --> H["Your host<br/>Bilgisayarınız"]
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## What changes?

The reviewed local profile keeps only a small set of client-side/discovery services needed for normal networking and printer discovery.

The policy intentionally does **not** expose:

- inbound SSH
- Samba/NetBIOS sharing
- blanket TCP/UDP 1025–65535
- forwarding or masquerading by default

It also enables a stricter DNAT gate and hardens selected redirect/source-route sysctls.

</td>
<td valign="top">

## Neler değişir?

İncelenmiş yerel profil, normal ağ ve yazıcı keşfi için gereken küçük bir istemci/keşif servis kümesini korur.

Politika bilinçli olarak şunları **açmaz**:

- inbound SSH
- Samba/NetBIOS paylaşımı
- geniş TCP/UDP 1025–65535 aralığı
- varsayılan forwarding veya masquerade

Ayrıca daha sıkı DNAT kontrolü açar ve seçilmiş redirect/source-route sysctl'lerini sıkılaştırır.

</td>
</tr>
</table>

Expected LAN services / Beklenen LAN servisleri:

~~~text
dhcpv6-client
ipp-client
mdns
ws-discovery-client
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Before installation

Use this layer only when:

- Fedora 44 is working normally
- firewalld is active
- NetworkManager is active
- you have a local desktop/TTY session for recovery
- Docker is not active during <code>apply</code>

If you depend on inbound SSH or Samba sharing, read the plan carefully. Those services are intentionally not opened by this policy.

</td>
<td valign="top">

## Kurulumdan önce

Bu katmanı şu durumda kullanın:

- Fedora 44 normal çalışıyor
- firewalld aktif
- NetworkManager aktif
- kurtarma için yerel masaüstü/TTY oturumunuz var
- <code>apply</code> sırasında Docker aktif değil

Inbound SSH veya Samba paylaşımına ihtiyacınız varsa planı dikkatle okuyun. Bu politika bu servisleri bilinçli olarak açmaz.

</td>
</tr>
</table>

## Installation / Kurulum

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening

sudo install -o root -g root -m 0755 \
  ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh

sudo restorecon -RFv \
  /usr/local/libexec/aegis/network-hardening
~~~

Create a short variable / Kısa değişken:

~~~bash
AEGIS_NET=/usr/local/libexec/aegis/network-hardening/aegis-network.sh
~~~

Verify the installed copy / Kurulu kopyayı doğrulayın:

~~~bash
/usr/bin/bash -p -- "$AEGIS_NET" verify-install
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## First run — do not skip the plan

### Step 1 — Plan

The plan shows:

- selected connection UUID
- selected device
- current and target zones
- name-resolution policy
- the exact plan hash
- what is intentionally not changed

If the selected connection is not the one you expect, stop.

</td>
<td valign="top">

## İlk çalıştırma — planı atlamayın

### Adım 1 — Plan

Plan şunları gösterir:

- seçilen bağlantı UUID'si
- seçilen cihaz
- mevcut ve hedef zone'lar
- isim çözümleme politikası
- tam plan hash'i
- bilinçli olarak değiştirilmeyenler

Seçilen bağlantı beklediğiniz bağlantı değilse durun.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 2 — Apply

<code>apply</code> creates a transaction snapshot and starts an independent rollback guard before publishing the network changes.

If verification succeeds, the transaction is committed and the guard is cancelled.

This is why you should not manually edit the AEGIS firewalld files during an active transaction.

</td>
<td valign="top">

### Adım 2 — Uygula

<code>apply</code> ağ değişikliklerini yayımlamadan önce transaction snapshot oluşturur ve bağımsız rollback guard başlatır.

Doğrulama geçerse transaction commit edilir ve guard iptal edilir.

Bu nedenle aktif transaction sırasında AEGIS firewalld dosyalarını elle değiştirmeyin.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" apply
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

### Step 3 — Verify

A successful <code>verify</code> checks:

- managed configuration files
- firewalld zones
- profile binding
- the strict DNAT gate
- managed sysctls
- connected device/default-route expectations

Then reboot once and verify again. Reboot verification is important because persistent network/sysctl behavior can differ from the first live apply.

</td>
<td valign="top">

### Adım 3 — Doğrula

Başarılı <code>verify</code> şunları kontrol eder:

- yönetilen yapılandırma dosyaları
- firewalld zone'ları
- profil bağlantısı
- sıkı DNAT kapısı
- yönetilen sysctl'ler
- bağlı cihaz/default-route beklentileri

Sonra bir kez reboot edip tekrar verify çalıştırın. Reboot doğrulaması önemlidir; kalıcı ağ/sysctl davranışı ilk canlı apply'dan farklı olabilir.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify

sudo systemctl reboot
~~~

After login / Oturum açtıktan sonra:

~~~bash
AEGIS_NET=/usr/local/libexec/aegis/network-hardening/aegis-network.sh

sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
~~~

A successful result ends with / Başarılı sonuç şununla biter:

~~~text
VERIFIED: AEGIS zones, profile binding, strict DNAT gate and managed sysctls are active/persistent.
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Daily use

No daily <code>apply</code> is required.

Useful checks:

- <code>verify</code> — full layer verification
- <code>status</code> — current managed state
- <code>history</code> — transaction history

On a compliant system, another <code>apply</code> should report <code>NO-OP</code> and should not rewrite files or reload the firewall.

</td>
<td valign="top">

## Günlük kullanım

Her gün <code>apply</code> çalıştırılmaz.

Faydalı kontroller:

- <code>verify</code> — katmanın tam doğrulaması
- <code>status</code> — mevcut yönetilen durum
- <code>history</code> — transaction geçmişi

Uyumlu sistemde yeni bir <code>apply</code>, <code>NO-OP</code> vermeli ve dosya yazmamalı veya firewall reload yapmamalıdır.

</td>
</tr>
</table>

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
sudo /usr/bin/bash -p -- "$AEGIS_NET" status
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Command guide

- <code>verify-install</code> — verify installed script integrity
- <code>audit</code> — read-only network/firewall inspection
- <code>plan</code> — preview the policy
- <code>apply</code> — apply the reviewed policy
- <code>verify</code> — verify live and persistent state
- <code>status</code> — show current managed state
- <code>history</code> — list transactions
- <code>rollback [TX_ID]</code> — restore a transaction
- <code>packages</code> — show required/optional tools
- <code>export</code> — create a private audit report

</td>
<td valign="top">

## Komut rehberi

- <code>verify-install</code> — kurulu script bütünlüğünü doğrular
- <code>audit</code> — salt okunur ağ/firewall incelemesi
- <code>plan</code> — politikayı önceden gösterir
- <code>apply</code> — incelenen politikayı uygular
- <code>verify</code> — canlı ve kalıcı durumu doğrular
- <code>status</code> — mevcut yönetilen durumu gösterir
- <code>history</code> — transaction kayıtlarını listeler
- <code>rollback [TX_ID]</code> — transaction'ı geri alır
- <code>packages</code> — gerekli/opsiyonel araçları gösterir
- <code>export</code> — özel audit raporu üretir

</td>
</tr>
</table>

## Multiple active connections / Birden fazla aktif bağlantı

If the script cannot safely choose one physical connection / Betik tek fiziksel bağlantıyı güvenle seçemiyorsa:

~~~bash
nmcli -t -f NAME,UUID,TYPE,DEVICE \
  connection show --active
~~~

Then pass the intended UUID / Sonra doğru UUID'yi verin:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan \
  --connection-uuid YOUR_UUID
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## Troubleshooting

**Plan says Docker is active**  
Stop Docker or wait for the separate Docker-isolation layer. Do not bypass the safety check.

**The wrong physical connection was selected**  
Use <code>--connection-uuid</code> with the UUID you reviewed.

**Internet works but a local service no longer accepts inbound connections**  
That may be intentional. This policy does not expose SSH/Samba or broad high ports.

**Printer discovery**  
The LAN policy keeps mDNS, IPP-client, and WS-Discovery-client. A real printer still needs a functional CUPS/printer setup.

**Verify fails after reboot**  
Run <code>status</code>, <code>history</code>, and <code>plan</code>. Do not start editing firewalld XML manually.

</td>
<td valign="top">

## Sorun giderme

**Plan Docker'ın aktif olduğunu söylüyor**  
Docker'ı durdurun veya ayrı Docker-isolation katmanını bekleyin. Güvenlik kontrolünü atlamayın.

**Yanlış fiziksel bağlantı seçildi**  
İncelediğiniz UUID ile <code>--connection-uuid</code> kullanın.

**Internet çalışıyor ama yerel bir servis inbound bağlantı kabul etmiyor**  
Bu bilinçli olabilir. Politika SSH/Samba veya geniş yüksek portları açmaz.

**Yazıcı keşfi**  
LAN politikası mDNS, IPP-client ve WS-Discovery-client servislerini korur. Gerçek yazıcı için çalışan CUPS/yazıcı kurulumu ayrıca gerekir.

**Verify reboot sonrası geçmiyor**  
<code>status</code>, <code>history</code> ve <code>plan</code> çalıştırın. firewalld XML dosyalarını elle düzenlemeye başlamayın.

</td>
</tr>
</table>

## Rollback / Geri alma

List transactions / İşlemleri listeleyin:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
~~~

Rollback a transaction / Bir transaction'ı geri alın:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" rollback TX_ID
~~~

<table>
<tr>
<th width="50%">ENGLISH</th>
<th width="50%">TÜRKÇE</th>
</tr>
<tr>
<td valign="top">

## What this layer does not do

- It does not create an outbound application allowlist.
- It does not claim DNS-over-TLS.
- It does not automatically start Docker.
- It does not disable all ICMP.
- It does not turn the laptop into a router.
- It does not replace application-level security.

</td>
<td valign="top">

## Bu katman ne yapmaz?

- Uygulama bazlı outbound allowlist oluşturmaz.
- DNS-over-TLS kullandığını iddia etmez.
- Docker'ı otomatik başlatmaz.
- Tüm ICMP'yi kapatmaz.
- Dizüstü bilgisayarı router'a dönüştürmez.
- Uygulama seviyesindeki güvenliğin yerini almaz.

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

A firewall is not simply “on” or “off”.

You learned to think in terms of:

**trust zone → allowed services → interface binding → verification → rollback**

</td>
<td valign="top">

Firewall yalnızca “açık” veya “kapalı” değildir.

Şu modelle düşünmeyi öğrendiniz:

**güven zone'u → izinli servisler → interface bağlantısı → doğrulama → rollback**

</td>
</tr>
</table>
