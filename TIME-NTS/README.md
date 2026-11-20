# AEGIS TIME-NTS

**Version:** `0.2.0-rc4`  
**Release status:** Project-host live NTS validated / Proje hostunda canlı NTS doğrulandı  
**License:** [MIT](../LICENSE)  
**Arabic:** [README_AR.md](README_AR.md)

> **Important:** Review the current `plan` before every mutating operation. Do not use old plan hashes, old scripts, or legacy service files with this release.  
> **Önemli:** Her değişiklik öncesinde güncel `plan` çıktısını inceleyin. Eski plan hash’lerini, eski betikleri veya legacy servis dosyalarını bu sürümle birlikte kullanmayın.

<table>
<thead><tr><th width="50%">ENGLISH</th><th width="50%">TÜRKÇE</th></tr></thead>
<tbody>
<tr>
<td valign="top">
<h2>Overview</h2>
<p>AEGIS TIME-NTS migrates an existing Fedora 44 Chrony client to authenticated Network Time Security (NTS) using three reviewed public hostnames. Configuration activation and proof of authenticated live synchronisation are deliberately treated as separate results.</p><pre><code>server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
authselectmode require
minsources 2
ntsdumpdir /var/lib/chrony
nocerttimecheck 0
port 0</code></pre><p>Simple existing plaintext server/pool lines and the recognised DHCP source directory are retained as comments rather than silently discarded. Non-source settings and comments are preserved when supported.</p>
</td>
<td valign="top">
<h2>Genel Bakış</h2>
<p>AEGIS TIME-NTS, mevcut Fedora 44 Chrony istemcisini üç incelenmiş public hostname kullanarak kimlik doğrulamalı Network Time Security (NTS) politikasına taşır. Yapılandırmanın aktive edilmesi ile canlı, kimlik doğrulamalı senkronizasyon kanıtı bilinçli olarak iki ayrı sonuç kabul edilir.</p><pre><code>server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
authselectmode require
minsources 2
ntsdumpdir /var/lib/chrony
nocerttimecheck 0
port 0</code></pre><p>Basit mevcut plaintext server/pool satırları ve tanınan DHCP source dizini sessizce yok edilmez; yorum olarak korunur. Desteklenen source-dışı ayarlar ve yorumlar korunur.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Security model and boundaries</h2>
<ul><li><code>authselectmode require</code> rejects unauthenticated sources for selection.</li><li><code>minsources 2</code> requires at least two selectable sources; this improves agreement requirements but can reduce availability.</li><li><code>port 0</code> keeps Chrony in client-only mode for NTP service exposure.</li><li>Existing <code>makestep</code> and <code>rtcsync</code> policy is preserved; this module does not directly run clock-step commands.</li><li>No package installation, firewall mutation, DNS/IPv6 change, NTS cookie deletion, bootloader edit or unauthenticated fallback is performed.</li><li>Rollback restores configuration, not historical clock state, timestamps already written, or elapsed time.</li></ul>
</td>
<td valign="top">
<h2>Güvenlik modeli ve sınırlar</h2>
<ul><li><code>authselectmode require</code> kimlik doğrulanmamış source’ların seçilmesini engeller.</li><li><code>minsources 2</code> en az iki selectable source ister; uzlaşma şartını güçlendirir fakat kullanılabilirliği azaltabilir.</li><li><code>port 0</code> Chrony’nin NTP server olarak port açmasını engelleyip client-only davranışı korur.</li><li>Mevcut <code>makestep</code> ve <code>rtcsync</code> politikası korunur; bu modül doğrudan clock-step komutu çalıştırmaz.</li><li>Paket kurulumu, firewall değişikliği, DNS/IPv6 değişikliği, NTS cookie silme, bootloader düzenleme veya unauthenticated fallback yapmaz.</li><li>Rollback yapılandırmayı geri getirir; geçmiş saat durumunu, yazılmış timestamp’leri veya geçen zamanı geri alamaz.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Supported target and prerequisites</h2>
<ul><li>Native, non-virtualised, mutable Fedora 44.</li><li>Chrony 4.8+ within the 4.x series and <code>chronyd -v</code> reporting <code>+NTS</code>.</li><li>Vendor <code>chronyd.service</code> already active and persistently enabled.</li><li>No competing active/enabled time daemon.</li><li>The standard Fedora drop-in <code>/usr/lib/systemd/system/service.d/10-timeout-abort.conf</code> is accepted only with the reviewed active setting; unexpected drop-ins/config trees require manual review.</li><li>WSL, VMs, containers and Atomic/OSTree are audit-only mutation targets.</li></ul>
</td>
<td valign="top">
<h2>Desteklenen hedef ve önkoşullar</h2>
<ul><li>Native, sanallaştırılmamış, mutable Fedora 44.</li><li>4.x serisi içinde Chrony 4.8+ ve <code>chronyd -v</code> çıktısında <code>+NTS</code>.</li><li>Vendor <code>chronyd.service</code> önceden active ve kalıcı olarak enabled.</li><li>Rakip active/enabled time daemon olmamalı.</li><li>Standart Fedora drop-in’i <code>/usr/lib/systemd/system/service.d/10-timeout-abort.conf</code> yalnız incelenmiş aktif ayarla kabul edilir; beklenmeyen drop-in/config ağaçları manuel inceleme ister.</li><li>WSL, VM, container ve Atomic/OSTree mutasyon için audit-only kabul edilir.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Installation</h2>
<p>Verify the public package before root execution, then place both runtime files in a root-owned libexec directory. No persistent AEGIS daemon/timer is installed.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-time-nts.sh --help

sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/time-nts
sudo install -o root -g root -m 0755 ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
sudo install -o root -g root -m 0755 ./export-audit.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts-export.sh
sudo restorecon -RFv /usr/local/libexec/aegis/time-nts

AEGIS_TIME=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh</code></pre><p>The runtime has no <code>--version</code> action; <code>audit</code>/<code>plan</code> output identifies <code>0.2.0-rc4</code>.</p>
</td>
<td valign="top">
<h2>Kurulum</h2>
<p>Root çalıştırmadan önce public paketin bütünlüğünü doğrulayın, ardından iki runtime dosyasını root-owned libexec dizinine yerleştirin. Kalıcı AEGIS daemon/timer kurulmaz.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-time-nts.sh --help

sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/time-nts
sudo install -o root -g root -m 0755 ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
sudo install -o root -g root -m 0755 ./export-audit.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts-export.sh
sudo restorecon -RFv /usr/local/libexec/aegis/time-nts

AEGIS_TIME=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh</code></pre><p>Runtime’da ayrı <code>--version</code> eylemi yoktur; <code>audit</code>/<code>plan</code> çıktısı <code>0.2.0-rc4</code> sürümünü gösterir.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>First-time use</h2>
<p>Inspect the host before activation. <code>audit</code> is observation only; <code>plan</code> builds and parser-validates a proposed config and prints <code>PLAN_SHA256</code>.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" audit
sudo /usr/bin/bash -p -- "$AEGIS_TIME" plan
sudo /usr/bin/bash -p -- "$AEGIS_TIME" apply
sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status</code></pre><p>Interactive apply requires <code>APPLY &lt;PLAN_SHA256&gt;</code>. After review, non-interactive execution may use <code>--approve &lt;PLAN_SHA256&gt;</code>. Never reuse a digest from another version or changed host state.</p>
</td>
<td valign="top">
<h2>İlk kullanım</h2>
<p>Aktivasyon öncesinde host’u inceleyin. <code>audit</code> yalnız gözlemdir; <code>plan</code> önerilen config’i üretir, parser doğrulaması yapar ve <code>PLAN_SHA256</code> basar.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" audit
sudo /usr/bin/bash -p -- "$AEGIS_TIME" plan
sudo /usr/bin/bash -p -- "$AEGIS_TIME" apply
sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status</code></pre><p>Interactive apply için <code>APPLY &lt;PLAN_SHA256&gt;</code> gerekir. İncelemeden sonra non-interactive kullanımda <code>--approve &lt;PLAN_SHA256&gt;</code> verilebilir. Başka sürüme veya değişmiş host durumuna ait digest’i tekrar kullanmayın.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>What “VERIFIED SNAPSHOT” means</h2>
<p>Live verification collects multiple local Chrony observations and requires a stable selected source, ready NTS keys, authenticated received packets, fresh samples, at least two authenticated/selectable sources, valid tracking/leap state, and remaining correction within 0.1 s. It is evidence of the observed Chrony/NTS state, <strong>not a mathematical guarantee of absolute UTC correctness</strong>.</p><p>A normal source transition can briefly produce <code>NOT VERIFIED: selected source changed or is absent</code>; the bounded wait loop can converge without weakening policy.</p>
</td>
<td valign="top">
<h2>“VERIFIED SNAPSHOT” ne demektir?</h2>
<p>Canlı doğrulama birden fazla yerel Chrony gözlemi toplar; seçili source’un stabil olmasını, NTS key’lerinin hazır olmasını, authenticated RX paketlerini, fresh sample’ları, en az iki authenticated/selectable source’u, geçerli tracking/leap durumunu ve 0.1 s veya daha düşük remaining correction’ı ister. Bu, gözlenen Chrony/NTS durumunun kanıtıdır; <strong>mutlak UTC doğruluğunun matematiksel garantisi değildir</strong>.</p><p>Normal source geçişi kısa süreli <code>NOT VERIFIED: selected source changed or is absent</code> üretebilir; bounded wait loop güvenlik politikasını gevşetmeden yakınsayabilir.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Command reference</h2>
<ul><li><code>audit</code> — read-only local Chrony/service/config observation. Not a live NTS verdict.</li><li><code>plan</code> — validates the proposed config with Chrony parser and emits the plan digest; does not activate.</li><li><code>apply</code> — journaled single-file replacement, chronyd restart verification, then live NTS verification.</li><li><code>verify [--wait 0..300]</code> — live authenticated synchronisation evidence; default wait 120 s.</li><li><code>status</code> — transaction journal status only; <strong>not</strong> a live NTS verdict.</li><li><code>rollback</code> — conflict-aware restore of the original config and chronyd restart. It can restore plaintext sources that were present before hardening.</li><li><code>--approve SHA256</code> — explicit current apply/rollback approval.</li><li><code>export-audit.sh</code> — desktop-user helper that stores a private audit report; report may contain source addresses/config details.</li></ul>
</td>
<td valign="top">
<h2>Komut referansı</h2>
<ul><li><code>audit</code> — salt okunur yerel Chrony/service/config gözlemi. Canlı NTS verdict değildir.</li><li><code>plan</code> — önerilen config’i Chrony parser ile doğrular ve plan digest’i üretir; aktive etmez.</li><li><code>apply</code> — journal’lı tek-dosya replacement, chronyd restart doğrulaması ve ardından canlı NTS doğrulaması.</li><li><code>verify [--wait 0..300]</code> — canlı authenticated synchronisation kanıtı; varsayılan bekleme 120 s.</li><li><code>status</code> — yalnız transaction journal durumu; <strong>canlı NTS verdict değildir</strong>.</li><li><code>rollback</code> — eski config’i conflict-aware geri yükler ve chronyd restart eder. Hardening öncesinde varsa plaintext source’ları geri getirebilir.</li><li><code>--approve SHA256</code> — güncel apply/rollback için açık onay.</li><li><code>export-audit.sh</code> — desktop kullanıcısı adına private audit raporu kaydeder; rapor source adresleri/config ayrıntıları içerebilir.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Network requirements</h2>
<p>NTS key establishment normally uses TCP 4460. The authenticated NTP UDP destination is negotiated; Netnod documents UDP 4123. A firewall policy that assumes every NTP packet must use UDP 123 can break a valid NTS source. This module changes no firewall rule itself.</p>
</td>
<td valign="top">
<h2>Ağ gereksinimleri</h2>
<p>NTS key establishment normalde TCP 4460 kullanır. Kimlik doğrulamalı NTP UDP destination müzakere edilir; Netnod UDP 4123 dokümante eder. Tüm NTP trafiğinin yalnız UDP 123 kullanacağını varsayan firewall politikası geçerli bir NTS source’unu bozabilir. Bu modül firewall kuralını kendisi değiştirmez.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Daily operation</h2>
<p><strong>No daily apply is required.</strong> The existing chronyd service continues to run. Recommended checks are manual <code>verify</code> after reboot, network/firewall changes, Chrony upgrades, certificate/time anomalies, or when the health state is in doubt.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status</code></pre><p>A no-change apply should report <code>NO-OP: no backup, file replacement, restart or persistent journal write.</code> It still performs live verification.</p>
</td>
<td valign="top">
<h2>Günlük kullanım</h2>
<p><strong>Her gün apply gerekmez.</strong> Mevcut chronyd servisi normal şekilde çalışmaya devam eder. Reboot, ağ/firewall değişikliği, Chrony upgrade’i, sertifika/saat anomalisi veya health durumundan şüphe olduğunda manuel <code>verify</code> önerilir.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status</code></pre><p>Değişiklik gerekmeyen apply <code>NO-OP: no backup, file replacement, restart or persistent journal write.</code> vermelidir. Buna rağmen canlı verify yapılır.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Rollback</h2>
<p>The module keeps one protected rollback slot under <code>/var/lib/fedora-hardening/time-nts</code>. Manual rollback prints a fresh <code>ROLLBACK_SHA256</code> and requires <code>ROLLBACK &lt;hash&gt;</code> (or matching <code>--approve</code>). It refuses later conflicting edits.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" rollback</code></pre><p><strong>Warning:</strong> rollback can restore the original unauthenticated/plaintext NTP sources if those were present before hardening. It cannot undo clock adjustments already made.</p>
</td>
<td valign="top">
<h2>Rollback</h2>
<p>Modül <code>/var/lib/fedora-hardening/time-nts</code> altında tek korumalı rollback slot’u tutar. Manuel rollback yeni bir <code>ROLLBACK_SHA256</code> üretir ve <code>ROLLBACK &lt;hash&gt;</code> (veya eşleşen <code>--approve</code>) ister. Sonradan yapılmış çakışan düzenlemeleri ezmez.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_TIME" rollback</code></pre><p><strong>Uyarı:</strong> hardening öncesinde mevcutsa rollback eski unauthenticated/plaintext NTP source’larını geri getirebilir. Daha önce yapılmış saat düzeltmelerini geri alamaz.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Troubleshooting</h2>
<ul><li><strong><code>+NTS</code> missing or Chrony &lt; 4.8:</strong> do not apply; update/review the host first.</li><li><strong>Unexpected systemd drop-in or custom service/config tree:</strong> stop for manual review; the script intentionally refuses unknown ownership semantics.</li><li><strong>NTS keys never become ready:</strong> inspect DNS/connectivity, TCP 4460 and negotiated UDP traffic. Do not disable certificate-time checks or add plaintext fallback as a shortcut.</li><li><strong>Netnod fails while UDP 123 works:</strong> verify that outbound UDP 4123 is not blocked.</li><li><strong>Initial clock is wildly wrong:</strong> fix the bootstrap-time problem separately; the module intentionally keeps certificate time checking enabled.</li><li><strong>Pending transaction/recovery state:</strong> inspect <code>status</code>; do not delete the state directory to bypass the safety gate.</li></ul>
</td>
<td valign="top">
<h2>Sorun giderme</h2>
<ul><li><strong><code>+NTS</code> yok veya Chrony &lt; 4.8:</strong> apply etmeyin; önce host’u update/review edin.</li><li><strong>Beklenmeyen systemd drop-in veya custom service/config tree:</strong> manuel inceleme için durun; betik bilinmeyen ownership semantiğini bilinçli olarak reddeder.</li><li><strong>NTS key’leri hazır olmuyor:</strong> DNS/connectivity, TCP 4460 ve negotiated UDP trafiğini inceleyin. Kısayol olarak certificate-time check’i kapatmayın veya plaintext fallback eklemeyin.</li><li><strong>UDP 123 çalışırken Netnod başarısız:</strong> outbound UDP 4123’ün engellenmediğini doğrulayın.</li><li><strong>İlk saat çok hatalı:</strong> bootstrap-time problemini ayrı çözün; modül certificate time check’i bilinçli olarak açık tutar.</li><li><strong>Pending transaction/recovery:</strong> <code>status</code> inceleyin; safety gate’i aşmak için state dizinini silmeyin.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Exit codes and validation status</h2>
<p><code>0</code> requested action succeeded; <code>1</code> incomplete audit/lower-level failure; <code>2</code> refusal/validation failure; <code>3</code> live verification incomplete; <code>75</code> writer lock busy; signals commonly map to 129/130/143.</p><p><strong>Project-host evidence:</strong> rc4 was activated on the Fedora 44 Surface Pro 9 project host. Repeated live checks showed all three configured sources with NTS keys and authenticated RX, at least two selectable sources, and <code>VERIFIED SNAPSHOT</code>. It also remained verified after Network hardening and reboot. This does not guarantee honesty of remote servers or absolute UTC error.</p>
</td>
<td valign="top">
<h2>Exit kodları ve doğrulama durumu</h2>
<p><code>0</code> istenen eylem başarılı; <code>1</code> eksik audit/alt seviye hata; <code>2</code> refusal/validation hatası; <code>3</code> canlı doğrulama tamamlanmadı; <code>75</code> writer lock busy; sinyaller genellikle 129/130/143.</p><p><strong>Proje host kanıtı:</strong> rc4 Fedora 44 Surface Pro 9 proje cihazında aktive edildi. Tekrarlanan canlı kontroller üç source’un tamamında NTS key ve authenticated RX, en az iki selectable source ve <code>VERIFIED SNAPSHOT</code> gösterdi. Network hardening ve reboot sonrasında da doğrulama geçti. Bu, uzak sunucuların dürüstlüğünü veya mutlak UTC hatasını garanti etmez.</p>
</td>
</tr>
</tbody>
</table>

---

**Security note / Güvenlik notu:** This project reduces selected attack surfaces; it is not a guarantee that a host is secure. Root execution should be limited to reviewed, checksum-verified source. / Bu proje seçili saldırı yüzeylerini azaltır; bir sistemin tamamen güvenli olduğunu garanti etmez. Root çalıştırma yalnız incelenmiş ve checksum doğrulaması yapılmış kaynakla sınırlandırılmalıdır.
