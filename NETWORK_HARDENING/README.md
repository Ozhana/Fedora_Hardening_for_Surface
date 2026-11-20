# AEGIS Network Hardening

**Version:** `0.7.0-rc4`  
**Release status:** VERIFIED on project Fedora 44 / Surface Pro 9 host / Proje Fedora 44 / Surface Pro 9 hostunda VERIFIED  
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
<p>AEGIS Network Hardening is a transaction-based Fedora 44 firewalld/nftables hardening layer. It replaces the old blanket Fedora Workstation exposure with two AEGIS-owned zones and binds the reviewed active physical profile by UUID.</p><ul><li><code>aegis-public</code> becomes the restrictive fallback/default zone and exposes only <code>dhcpv6-client</code>.</li><li><code>aegis-lan</code> is bound only to the reviewed Wi-Fi/Ethernet profile and allows <code>dhcpv6-client</code>, <code>mdns</code>, <code>ipp-client</code> and <code>ws-discovery-client</code> for client-side discovery/printing.</li><li>SSH, Samba/NetBIOS and blanket TCP/UDP <code>1025-65535</code> inbound allowances are removed.</li><li>Essential ICMP remains available; this is not the old “DROP everything” V7 design.</li><li><code>StrictForwardPorts=yes</code> prevents implicit acceptance of container-published DNAT; Docker integration is intentionally a separate layer.</li></ul>
</td>
<td valign="top">
<h2>Genel Bakış</h2>
<p>AEGIS Network Hardening, Fedora 44 için transaction tabanlı firewalld/nftables hardening katmanıdır. Eski Fedora Workstation geniş açıklığını iki AEGIS-owned zone ile değiştirir ve incelenmiş aktif fiziksel profili UUID üzerinden bağlar.</p><ul><li><code>aegis-public</code> restrictive fallback/default zone olur ve yalnız <code>dhcpv6-client</code> expose eder.</li><li><code>aegis-lan</code> yalnız incelenmiş Wi-Fi/Ethernet profiline bağlanır; istemci tarafı keşif/yazdırma için <code>dhcpv6-client</code>, <code>mdns</code>, <code>ipp-client</code>, <code>ws-discovery-client</code> izinlidir.</li><li>SSH, Samba/NetBIOS ve toplu TCP/UDP <code>1025-65535</code> inbound izinleri kaldırılır.</li><li>Temel ICMP korunur; bu eski V7 “her şeyi DROP et” tasarımı değildir.</li><li><code>StrictForwardPorts=yes</code> container-published DNAT’ın implicit kabulünü engeller; Docker entegrasyonu bilinçli olarak ayrı katmandır.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Architecture</h2>
<ul><li>Native <code>firewalld</code> with nftables backend remains the firewall owner; no legacy direct/iptables lockdown whitelist is used.</li><li>NetworkManager profile UUID receives <code>connection.zone=aegis-lan</code>, <code>LLMNR=no</code> and <code>mDNS=resolve-only</code>.</li><li>A NetworkManager drop-in makes LLMNR/mDNS conservative by default for other profiles.</li><li>Redirect/source-route sysctls and loose RPF are managed without owning IP forwarding, BBR, MTU, RA, DNS policy or VPN marks.</li><li>rc4 uses systemd-native per-interface sysctl wildcards so loopback and newly appearing interfaces retain the policy across reboot without an extra daemon/timer.</li><li>Apply uses root-private snapshots plus an independent 180-second transient systemd rollback guard; commit cancels the guard.</li></ul>
</td>
<td valign="top">
<h2>Mimari</h2>
<ul><li>nftables backend kullanan native <code>firewalld</code> firewall sahibi olarak kalır; legacy direct/iptables lockdown whitelist kullanılmaz.</li><li>NetworkManager profile UUID’sine <code>connection.zone=aegis-lan</code>, <code>LLMNR=no</code> ve <code>mDNS=resolve-only</code> verilir.</li><li>NetworkManager drop-in diğer profiller için LLMNR/mDNS varsayılanını muhafazakâr yapar.</li><li>Redirect/source-route sysctl’leri ve loose RPF yönetilir; IP forwarding, BBR, MTU, RA, DNS politikası veya VPN mark’ları sahiplenilmez.</li><li>rc4, loopback ve sonradan oluşan interface’lerde politikanın reboot sonrası kalması için systemd-native per-interface sysctl wildcard’ları kullanır; ekstra daemon/timer yoktur.</li><li>Apply root-private snapshot ve bağımsız 180 saniyelik transient systemd rollback guard kullanır; commit guard’ı iptal eder.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Supported target and safety gates</h2>
<ul><li>Native mutable Fedora 44 with firewalld, NetworkManager, nftables and SELinux support.</li><li>Apply requires a local attributable session and a reviewable active physical Wi-Fi/Ethernet connection.</li><li>If more than one active physical profile exists, choose explicitly with <code>--connection-uuid UUID</code>.</li><li>Foreign/legacy firewall policy at reserved AEGIS paths, unsafe files, unexpected direct/policy rules or conflicting saved-profile zones can block apply.</li><li><strong>Active Docker blocks apply</strong> in this release because <code>StrictForwardPorts=yes</code> changes published-port semantics. Do not disable Docker blindly; integrate the Docker isolation layer separately.</li><li>No application-level outbound allowlist and no claim of VPN-leak prevention.</li></ul>
</td>
<td valign="top">
<h2>Desteklenen hedef ve safety gate’ler</h2>
<ul><li>firewalld, NetworkManager, nftables ve SELinux desteği olan native mutable Fedora 44.</li><li>Apply, kullanıcıya bağlanabilir yerel bir oturum ve incelenebilir aktif fiziksel Wi-Fi/Ethernet bağlantısı ister.</li><li>Birden fazla aktif fiziksel profil varsa <code>--connection-uuid UUID</code> ile açık seçim yapın.</li><li>Reserved AEGIS path’lerinde yabancı/legacy firewall policy, güvensiz dosya, beklenmeyen direct/policy rule veya saved-profile zone çakışması apply’ı durdurabilir.</li><li><strong>Aktif Docker bu sürümde apply’ı engeller</strong>; çünkü <code>StrictForwardPorts=yes</code> published-port semantiğini değiştirir. Docker’ı körlemesine kapatmayın; Docker isolation katmanını ayrı entegre edin.</li><li>Application-level outbound allowlist veya VPN leak prevention garantisi yoktur.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Installation and package tests</h2>
<p>Verify the release, run the reproducible tests, then install the single runtime file. Python is used by package tests, not by the runtime.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-network.sh version
/usr/bin/bash -p -- ./aegis-network.sh --help
sudo /usr/bin/bash -p -- ./tests/run.sh

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening
sudo install -o root -g root -m 0755 ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh
sudo restorecon -RFv /usr/local/libexec/aegis/network-hardening

/usr/bin/bash -p -- ./aegis-network.sh verify-install
AEGIS_NETWORK=/usr/local/libexec/aegis/network-hardening/aegis-network.sh</code></pre><p>Expected version: <code>0.7.0-rc4</code>. <code>verify-install</code> confirms that the installed root-owned single-file runtime matches the checked source/version.</p>
</td>
<td valign="top">
<h2>Kurulum ve paket testleri</h2>
<p>Release bütünlüğünü doğrulayın, tekrar üretilebilir testleri çalıştırın ve ardından tek runtime dosyasını kurun. Python paket testlerinde kullanılır; runtime Python’a bağımlı değildir.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-network.sh version
/usr/bin/bash -p -- ./aegis-network.sh --help
sudo /usr/bin/bash -p -- ./tests/run.sh

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening
sudo install -o root -g root -m 0755 ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh
sudo restorecon -RFv /usr/local/libexec/aegis/network-hardening

/usr/bin/bash -p -- ./aegis-network.sh verify-install
AEGIS_NETWORK=/usr/local/libexec/aegis/network-hardening/aegis-network.sh</code></pre><p>Beklenen sürüm: <code>0.7.0-rc4</code>. <code>verify-install</code>, kurulu root-owned single-file runtime’ın incelenen source/version ile birebir eşleştiğini doğrular.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>First-time use</h2>
<p>Do not jump directly to apply. Audit, inspect the plan, then approve the exact current plan hash.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" audit
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" plan
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" apply
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history</code></pre><p>Interactive apply requires <code>APPLY &lt;PLAN_SHA256&gt;</code>. After review you may use <code>--approve &lt;PLAN_SHA256&gt;</code>. The plan is recomputed before mutation; changed inputs invalidate the approval.</p>
</td>
<td valign="top">
<h2>İlk kullanım</h2>
<p>Doğrudan apply’a atlamayın. Önce audit, sonra plan incelemesi, ardından tam güncel plan hash’i ile onay verin.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" audit
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" plan
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" apply
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history</code></pre><p>Interactive apply <code>APPLY &lt;PLAN_SHA256&gt;</code> ister. İncelemeden sonra <code>--approve &lt;PLAN_SHA256&gt;</code> kullanılabilir. Mutasyon öncesinde plan yeniden hesaplanır; input değişirse onay geçersiz olur.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Command reference</h2>
<ul><li><code>version</code> — print release version.</li><li><code>packages</code> — show runtime/test package expectations; does not install packages.</li><li><code>verify-install</code> — compare checked source with the installed root-owned runtime.</li><li><code>audit</code> — read-only local network/firewall report.</li><li><code>plan [--connection-uuid UUID]</code> — select/review a physical profile and emit <code>PLAN_SHA256</code>.</li><li><code>apply [--connection-uuid UUID] [--approve HASH]</code> — transactional hardening with timed rollback guard.</li><li><code>verify</code> — verify managed files, firewalld/profile runtime state, strict DNAT gate and sysctls.</li><li><code>status</code> — current managed identity and latest transaction status.</li><li><code>history</code> — transaction history.</li><li><code>rollback [TX_ID] [--approve HASH]</code> — conflict-aware manual rollback.</li><li><code>export</code> — save an audit report as the desktop user; report contains IP/route/UUID data and must be reviewed before sharing.</li></ul>
</td>
<td valign="top">
<h2>Komut referansı</h2>
<ul><li><code>version</code> — sürümü gösterir.</li><li><code>packages</code> — runtime/test paket beklentilerini gösterir; paket kurmaz.</li><li><code>verify-install</code> — incelenen kaynak ile kurulu root-owned runtime’ı karşılaştırır.</li><li><code>audit</code> — salt okunur yerel network/firewall raporu.</li><li><code>plan [--connection-uuid UUID]</code> — fiziksel profili seçer/inceler ve <code>PLAN_SHA256</code> üretir.</li><li><code>apply [--connection-uuid UUID] [--approve HASH]</code> — timed rollback guard ile transactional hardening.</li><li><code>verify</code> — yönetilen dosyaları, firewalld/profile runtime durumunu, strict DNAT gate’i ve sysctl’leri doğrular.</li><li><code>status</code> — current managed identity ve son transaction durumunu gösterir.</li><li><code>history</code> — transaction geçmişi.</li><li><code>rollback [TX_ID] [--approve HASH]</code> — conflict-aware manuel rollback.</li><li><code>export</code> — desktop kullanıcısı adına audit raporu kaydeder; IP/route/UUID içerdiğinden paylaşmadan önce incelenmelidir.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Expected firewall state</h2>
<pre><code>Default zone: aegis-public
Active physical Wi-Fi/Ethernet: aegis-lan

aegis-public services:
  dhcpv6-client

aegis-lan services:
  dhcpv6-client ipp-client mdns ws-discovery-client

Not expected:
  ssh
  samba-client / NetBIOS exposure
  1025-65535/tcp
  1025-65535/udp
  forward=yes
  masquerade=yes</code></pre><p>The LAN allowances are client/discovery oriented. They do not intentionally expose a CUPS print server or SSH server.</p>
</td>
<td valign="top">
<h2>Beklenen firewall durumu</h2>
<pre><code>Default zone: aegis-public
Aktif fiziksel Wi-Fi/Ethernet: aegis-lan

aegis-public services:
  dhcpv6-client

aegis-lan services:
  dhcpv6-client ipp-client mdns ws-discovery-client

Beklenmeyenler:
  ssh
  samba-client / NetBIOS exposure
  1025-65535/tcp
  1025-65535/udp
  forward=yes
  masquerade=yes</code></pre><p>LAN izinleri istemci/keşif odaklıdır. Bilinçli olarak CUPS print server veya SSH server expose etmez.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Daily operation</h2>
<p><strong>No daily apply is required.</strong> There is no persistent AEGIS network service/timer. firewalld, NetworkManager and sysctl.d carry the committed policy. Use <code>verify</code> after reboot, Fedora/firewalld/NetworkManager updates, major network-profile changes or when docking/new interfaces are introduced.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status</code></pre><p>A compliant re-apply must be a true no-op: no snapshot, file replacement, firewall reload or profile rewrite.</p>
</td>
<td valign="top">
<h2>Günlük kullanım</h2>
<p><strong>Her gün apply gerekmez.</strong> Kalıcı AEGIS network service/timer yoktur. Commit edilmiş politikayı firewalld, NetworkManager ve sysctl.d taşır. Reboot, Fedora/firewalld/NetworkManager update’i, büyük network profile değişikliği veya dock/yeni interface eklenmesi sonrası <code>verify</code> çalıştırın.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status</code></pre><p>Uyumlu sistemde tekrar apply gerçek no-op olmalıdır: snapshot, dosya replacement, firewall reload veya profile rewrite olmamalıdır.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Printer and local discovery</h2>
<p>The reviewed LAN zone keeps mDNS, IPP-client and WS-Discovery-client specifically to avoid the old V7 behaviour that broke local printer discovery. This is deliberately narrow: a real printer still needs functional acceptance on the actual device/network. If discovery fails, do not reopen broad port ranges; use <code>audit</code> and identify the protocol first.</p>
</td>
<td valign="top">
<h2>Yazıcı ve yerel keşif</h2>
<p>İncelenmiş LAN zone, eski V7’nin yerel printer discovery’yi kıran davranışını önlemek için mDNS, IPP-client ve WS-Discovery-client’ı özellikle korur. Bu bilinçli olarak dardır: gerçek yazıcı yine kendi cihaz/ağında fonksiyonel kabul testi ister. Discovery başarısızsa geniş port aralıklarını yeniden açmayın; önce <code>audit</code> ile protokolü belirleyin.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Rollback</h2>
<p>List transactions, then request rollback of the newest or a specific transaction. The script produces a rollback plan/hash and refuses to overwrite later manual drift.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback
# or
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback 'T-...'</code></pre><p>Rollback validates the restored disk configuration before trying to recover firewalld runtime state. A conflict is a safety stop, not permission to use <code>--force</code>.</p>
</td>
<td valign="top">
<h2>Rollback</h2>
<p>Transaction’ları listeleyin; ardından en yeni veya belirli transaction için rollback isteyin. Betik rollback plan/hash’i üretir ve sonradan oluşmuş manuel drift’in üzerine yazmayı reddeder.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback
# veya
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback 'T-...'</code></pre><p>Rollback, firewalld runtime state’i kurtarmayı denemeden önce geri yüklenen disk config’ini doğrular. Conflict bir safety stop’tur; <code>--force</code> kullanma izni değildir.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Troubleshooting</h2>
<ul><li><strong>Docker active:</strong> apply refusal is expected. Integrate Docker isolation explicitly; do not weaken <code>StrictForwardPorts</code> just to make apply pass.</li><li><strong>Multiple active physical links:</strong> inspect <code>nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active</code> and rerun plan/apply with the intended UUID.</li><li><strong>Legacy V7 files/service present:</strong> retire the old <code>Aegis-Firewall-V7.sh</code>/<code>aegis-firewall-lockdown.service</code> architecture before applying rc4. Running both designs together is unsupported.</li><li><strong>verify fails after reboot on sysctl:</strong> rc4 should persist per-interface values; inspect <code>systemd-analyze cat-config sysctl.d</code>, <code>journalctl -b -u systemd-sysctl</code> and the reported key rather than re-applying blindly.</li><li><strong>Printer discovery fails:</strong> confirm CUPS/Avahi and the printer protocol; do not restore blanket 1025-65535 ranges.</li><li><strong>Rollback conflict:</strong> preserve the later edit, inspect it and resolve ownership intentionally.</li></ul>
</td>
<td valign="top">
<h2>Sorun giderme</h2>
<ul><li><strong>Docker active:</strong> apply refusal beklenen davranıştır. Docker isolation’ı açıkça entegre edin; sırf apply geçsin diye <code>StrictForwardPorts</code> politikasını gevşetmeyin.</li><li><strong>Birden fazla aktif fiziksel link:</strong> <code>nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active</code> ile inceleyin ve hedef UUID ile plan/apply çalıştırın.</li><li><strong>Legacy V7 dosya/servisleri mevcut:</strong> rc4 öncesinde eski <code>Aegis-Firewall-V7.sh</code>/<code>aegis-firewall-lockdown.service</code> mimarisini emekliye ayırın. İki tasarımı birlikte çalıştırmak desteklenmez.</li><li><strong>Reboot sonrası sysctl verify fail:</strong> rc4 per-interface persistence sağlamalıdır; körlemesine re-apply yerine <code>systemd-analyze cat-config sysctl.d</code>, <code>journalctl -b -u systemd-sysctl</code> ve raporlanan key’i inceleyin.</li><li><strong>Printer discovery başarısız:</strong> CUPS/Avahi ve printer protokolünü doğrulayın; toplu 1025-65535 aralıklarını geri açmayın.</li><li><strong>Rollback conflict:</strong> sonradan yapılmış değişikliği koruyun, inceleyin ve ownership’i bilinçli çözün.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Validation status</h2>
<p><strong>VERIFIED on the project host:</strong> Fedora 44 / Surface Pro 9. rc4 passed real apply, independent verify, transaction commit, DNS, IPv4/IPv6 routing, TIME-NTS compatibility, reboot persistence, and post-reboot re-apply as a true <code>NO-OP</code>. The old broad inbound ranges were absent from the live nftables ruleset. Printer functional printing was <strong>NOT TESTABLE</strong> because no CUPS destination was configured on that host; this is not reported as PASS.</p><p>Older rc1/rc2/rc3 candidates are historical development versions and should not be published as the current runtime.</p>
</td>
<td valign="top">
<h2>Doğrulama durumu</h2>
<p><strong>Proje hostunda VERIFIED:</strong> Fedora 44 / Surface Pro 9. rc4 gerçek apply, bağımsız verify, transaction commit, DNS, IPv4/IPv6 routing, TIME-NTS uyumluluğu, reboot persistence ve reboot sonrası gerçek <code>NO-OP</code> re-apply testlerini geçti. Eski geniş inbound aralıkları canlı nftables ruleset içinde yoktu. Printer fonksiyonel yazdırma testi host’ta CUPS destination tanımlı olmadığı için <strong>NOT TESTABLE</strong> kaldı; PASS diye raporlanmıyor.</p><p>Eski rc1/rc2/rc3 adayları tarihsel geliştirme sürümleridir ve current runtime olarak yayınlanmamalıdır.</p>
</td>
</tr>
</tbody>
</table>

---

**Security note / Güvenlik notu:** This project reduces selected attack surfaces; it is not a guarantee that a host is secure. Root execution should be limited to reviewed, checksum-verified source. / Bu proje seçili saldırı yüzeylerini azaltır; bir sistemin tamamen güvenli olduğunu garanti etmez. Root çalıştırma yalnız incelenmiş ve checksum doğrulaması yapılmış kaynakla sınırlandırılmalıdır.
