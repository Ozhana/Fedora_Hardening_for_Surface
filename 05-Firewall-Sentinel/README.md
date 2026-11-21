# 05 — AEGIS Firewall Sentinel | Firewall Güvenlik Katmanı
**Version / Sürüm:** `0.9.0-alpha2-review5` (STRICT) · **Fedora 44** · **Field-verified alpha / Sahada doğrulanmış alfa**
**[Separate full Arabic manual — الدليل العربي الكامل](README_AR.md)** · [English install](docs/INSTALL_EN.md) · [Türkçe kurulum](docs/INSTALL_TR.md) · [Operations](docs/OPERATIONS.md) · [Security & recovery](docs/SECURITY_AND_RECOVERY.md) · [Evidence](docs/FIELD_ACCEPTANCE.md)
> **Evidence boundary / Kanıt sınırı:** Installation (`COMMITTED`), independent `VERIFIED`, `monitor-now INFO`, and **one post-reboot check PASS** on a Fedora 44 Surface Pro 9 (2026-11-21). Not production-certified. No actual print-job test, strict DoT, VPN kill-switch, quarantine, blocklist or cgroup emergency feature was field-tested. / Kurulum, doğrulama ve **bir reboot sonrası test** başarılı; üretim sertifikası değildir. Yazdırma, DoT, VPN, karantina ve acil özellikler saha testinden geçmedi.

---

## 1 — At a glance / Mimari bakış
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Purpose and architectural ownership</h3><p>Sentinel adds **egress restrictions, attestation, forensic telemetry, transactional rollback and emergency containment** on top of `04-Network-Hardening` (`0.7.0-rc4`). The base layer retains ownership of firewalld zones (`aegis-public`, `aegis-lan`), NetworkManager zone bindings and network sysctls. Sentinel owns its `inet aegis_sentinel` nftables table and its own manifest, services, hooks and RAM-only transient tables. It does not run `nft flush ruleset`.</p>
</td><td valign="top">
<h3>Amaç ve bileşen sahipliği</h3><p>Sentinel, `04-Network-Hardening` (`0.7.0-rc4`) üzerine **çıkış trafiği kısıtlamaları, bütünlük denetimi, canlı adli telemetri, işlemsel rollback ve acil izolasyon** ekler. Temel katman firewalld bölgelerinin (`aegis-public`, `aegis-lan`), NetworkManager bağlarının ve ağ sysctl ayarlarının sahibidir. Sentinel yalnızca `inet aegis_sentinel` tablosunu, kendi manifest/servislerini ve RAM tabanlı geçici tablolarını yönetir. `nft flush ruleset` çalıştırmaz.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Default tested policy</h3><p>LLMNR (5355) and NAT-PMP/PCP (5351) egress are blocked. Untrusted-interface mDNS, SSDP and WS-Discovery egress are restricted. LAN SMB/RPC/NetBIOS and LAN SSDP egress default to **BLOCKED**. `Quarantine: OFF`, `VPN kill-switch: OFF`, and **DNS 53: PASSTHROUGH**. `monitor-now INFO` may include listening Avahi/systemd-resolved sockets; a listening socket does not prove reachability through the firewall.</p>
</td><td valign="top">
<h3>Test edilmiş varsayılan politika</h3><p>LLMNR (5355) ve NAT-PMP/PCP (5351) çıkışı engellenir. Güvenilmeyen arayüzlerde mDNS, SSDP ve WS-Discovery çıkışı sınırlandırılır. LAN SMB/RPC/NetBIOS ve LAN SSDP varsayılanı **BLOCKED**. `Quarantine: OFF`, `VPN kill-switch: OFF` ve **DNS 53: PASSTHROUGH**. `monitor-now INFO` içinde Avahi/systemd-resolved dinleyicileri görülebilir; soketin dinlemesi firewall üzerinden erişilebilir olduğunu kanıtlamaz.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Privilege and trust boundary</h3><p>Mutating normal policy commands require `sudo` invoked from an **active, non-remote, physical Linux virtual console** (e.g. `/dev/tty3`) with matching kernel audit/logind provenance. A GUI terminal (`/dev/pts/*`) belonging to the user-manager audit session is refused by design, even if the same user is logged in graphically. Do not weaken this check. **Emergency break-glass (`quarantine-on --force-emergency`, `panic-off`) uses a distinct weaker terminal/loginuid check and is not field-accepted.**</p>
</td><td valign="top">
<h3>Yetki ve güven sınırı</h3><p>Normal politika değiştirme komutları, çekirdek audit/logind bağı doğrulanan **aktif, yerel, fiziksel Linux TTY** (örn. `/dev/tty3`) üzerinden `sudo` gerektirir. Kullanıcı yöneticisi audit oturumundaki grafik terminal (`/dev/pts/*`) aynı kişi tarafından kullanılsa bile bilerek reddedilir. Kontrolü gevşetme. **Acil istisna (`quarantine-on --force-emergency`, `panic-off`) ayrı ve daha zayıf terminal/loginuid kontrolü kullanır; sahada kabul edilmemiştir.**</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Protect printing and DNS truth</h3><p>CUPS and Avahi remained active after installation/reboot. No printer queue was configured on the freshly installed test machine, so no print-job success is claimed. The tested resolver used local router DNS (private RFC1918 gateway) with `DNSOverTLS=no`: DNS resolution worked, but transport was **not encrypted**. Do not enable strict DoT or block port 53 before separately configuring and attesting encrypted DNS.</p>
</td><td valign="top">
<h3>Yazdırmayı koru, DNS durumunu doğru yorumla</h3><p>Kurulum/reboot sonrası CUPS ve Avahi çalışmaya devam etti. Yeni kurulan test makinesinde yazıcı tanımlanmadığından gerçek yazdırma başarısı iddia edilmiyor. Test edilen çözümleyici yerel yönlendirici DNS (özel RFC1918 ağ geçidi) ve `DNSOverTLS=no` kullanıyordu: DNS çalıştı ama taşıma **şifreli değildi**. Şifreli DNS ayrı yapılandırılıp doğrulanmadan strict DoT açma veya port 53 engelleme.</p>
</td></tr></tbody></table>


## 2 — Installation & acceptance / Kurulum ve kabul

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Prerequisite: base Network Hardening</h3><p>Install and verify the separate `04-Network-Hardening` 0.7.0-rc4 first. This quick service check does not replace its own `verify`.</p><p><b>Command</b></p><pre><code>systemctl is-active NetworkManager firewalld</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>active
active</code></pre>
</td><td valign="top">
<h3>Ön koşul: Network Hardening katmanı</h3><p>Önce bağımsız `04-Network-Hardening` 0.7.0-rc4 katmanını kur ve doğrula. Aşağıdaki servis denetimi katmanın kendi `verify` kontrolünün yerine geçmez.</p><p><b>Komut</b></p><pre><code>systemctl is-active NetworkManager firewalld</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>active
active</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Clone source and verify files</h3><p>Clone the reviewed GitHub repository, enter this directory and compare every tracked file to the SHA256SUMS manifest. A matching manifest proves local consistency, not independent code signing.</p><p><b>Command</b></p><pre><code>git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum -c SHA256SUMS</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>README.md: OK
README_AR.md: OK
aegis-firewall-sentinel.py: OK
...</code></pre>
</td><td valign="top">
<h3>Kaynağı indirip dosyaları doğrula</h3><p>İncelenmiş GitHub deposunu klonla, bu klasöre gir ve bütün dosyaları SHA256SUMS ile karşılaştır. Manifest eşleşmesi yerel bütünlük kanıtıdır; bağımsız dijital imza değildir.</p><p><b>Komut</b></p><pre><code>git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum -c SHA256SUMS</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>README.md: OK
README_AR.md: OK
aegis-firewall-sentinel.py: OK
...</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Offline regression suite</h3><p>Execute source/flag documentation contract checks plus static security, 9 session/firewalld and 7 nft transaction tests. No firewall mutation.</p><p><b>Command</b></p><pre><code>bash ./scripts/test-offline.sh</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>REVIEW5_STATIC_SECURITY_TESTS_PASS
Ran 9 tests ... OK
Ran 7 tests ... OK
Ran 5 tests ... OK
OFFLINE_TESTS_PASS: ...</code></pre>
</td><td valign="top">
<h3>Çevrimdışı regresyon testleri</h3><p>Kaynak/parametre dokümantasyon sözleşmesi, statik güvenlik, 9 oturum/firewalld ve 7 nft işlem testini çalıştır. Firewall değiştirilmez.</p><p><b>Komut</b></p><pre><code>bash ./scripts/test-offline.sh</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>REVIEW5_STATIC_SECURITY_TESTS_PASS
Ran 9 tests ... OK
Ran 7 tests ... OK
Ran 5 tests ... OK
OFFLINE_TESTS_PASS: ...</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Controlled preflight installer</h3><p>As a normal GUI terminal user, run preflight. It checks SHA, tests, native `nft --check`, and atomically replaces only the protected root-owned Python runtime. **It does not apply firewall rules.**</p><p><b>Command</b></p><pre><code>bash ./install-preflight.sh</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>[4/8] NATIVE NFT PARSER CHECK — NO FIREWALL MUTATION
...
PREFLIGHT_OK: runtime updated; Sentinel firewall policy NOT applied.</code></pre>
</td><td valign="top">
<h3>Kontrollü kurulum öncesi denetim</h3><p>Normal grafik terminal kullanıcısı olarak preflight çalıştır. SHA, testler, yerel `nft --check` denetlenir ve yalnızca root sahipliğindeki korumalı Python dosyası atomik değiştirilir. **Firewall kuralları uygulanmaz.**</p><p><b>Komut</b></p><pre><code>bash ./install-preflight.sh</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>[4/8] NATIVE NFT PARSER CHECK — NO FIREWALL MUTATION
...
PREFLIGHT_OK: runtime updated; Sentinel firewall policy NOT applied.</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Open an actual physical TTY</h3><p>On the computer keyboard use Ctrl+Alt+F3 (or `sudo chvt 3` from a GUI terminal). Log in as your regular user; do not use SSH, `su`, or `sudo -i`. Inspect terminal, session type and active seat.</p><p><b>Command</b></p><pre><code>tty
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>/dev/tty3
Class=user
Type=tty
Active=yes
Remote=no
Seat=seat0</code></pre>
</td><td valign="top">
<h3>Gerçek fiziksel TTY oturumu aç</h3><p>Fiziksel klavyeden Ctrl+Alt+F3 (veya grafik terminalden `sudo chvt 3`) ile geç. Normal kullanıcı olarak yeniden oturum aç; SSH, `su`, `sudo -i` kullanma. Terminal, oturum tipi ve aktif seat değerlerini denetle.</p><p><b>Komut</b></p><pre><code>tty
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>/dev/tty3
Class=user
Type=tty
Active=yes
Remote=no
Seat=seat0</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Review and apply from the SAME TTY</h3><p>Declare the runtime path in the TTY shell, inspect plan defaults, then apply and type the **current** `APPLY &lt;PLAN_SHA256&gt;` prompt exactly. Different machines/plans have different hashes. This changes firewall/systemd and may disconnect the host.</p><p><b>Command</b></p><pre><code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>ACTION=apply | PLAN_SHA256=&lt;CURRENT_SHA256&gt;
...
Type exactly &quot;APPLY &lt;CURRENT_SHA256&gt;&quot; to continue:
COMMITTED: T-&lt;UTC_TIME&gt;-&lt;HEX&gt;</code></pre>
</td><td valign="top">
<h3>AYNI TTY’de planı inceleyip uygula</h3><p>TTY kabuğunda çalışma yolu değişkenini tanımla, planın varsayılanlarını incele, ardından uygula ve gösterilen **güncel** `APPLY &lt;PLAN_SHA256&gt;` ifadesini tam yaz. Farklı makine/planlarda özet değişir. Firewall/systemd değişebilir ve ağ kesilebilir.</p><p><b>Komut</b></p><pre><code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>ACTION=apply | PLAN_SHA256=&lt;CURRENT_SHA256&gt;
...
Type exactly &quot;APPLY &lt;CURRENT_SHA256&gt;&quot; to continue:
COMMITTED: T-&lt;UTC_TIME&gt;-&lt;HEX&gt;</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Independent post-apply verify</h3><p>Without switching away from the physical TTY, run verification. On `STOP` or `FAILED`, stop and inspect transaction state; do not rerun apply blindly.</p><p><b>Command</b></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.</code></pre>
</td><td valign="top">
<h3>Uygulama sonrası bağımsız doğrulama</h3><p>Fiziksel TTY’den çıkmadan doğrulamayı çalıştır. `STOP` veya `FAILED` varsa dur, işlem durumunu incele; körlemesine apply tekrarlama.</p><p><b>Komut</b></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Post-reboot persistence (field PASS)</h3><p>After saving work, reboot once. From the new shell re-declare AEGIS (shell variables do not survive reboot). Verify units, nft tables, DNS and failures. On the Fedora 44 reference machine **one reboot passed** on 2026-11-21.</p><p><b>Command</b></p><pre><code>sudo systemctl reboot
# In a NEW terminal after boot:
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now
systemctl is-active aegis-firewall-sentinel.service NetworkManager firewalld
sudo nft list tables
systemctl --failed --no-pager</code></pre><p><b>Expected success marker (illustrative)</b></p><pre><code>VERIFIED: base Network Hardening, ... runtime table match.
AEGIS Firewall Sentinel monitor: INFO
active
active
active
table inet firewalld
table inet aegis_sentinel
0 loaded units listed.</code></pre>
</td><td valign="top">
<h3>Reboot sonrası kalıcılık (saha PASS)</h3><p>İşlerini kaydet ve bir kez yeniden başlat. Yeni kabukta AEGIS değişkenini tekrar tanımla (kabuk değişkeni reboot sonrasında kalmaz). Birimleri, nft tablolarını, DNS’i ve hataları kontrol et. Fedora 44 referans makinede 2026-11-21 tarihinde **bir reboot başarılı** oldu.</p><p><b>Komut</b></p><pre><code>sudo systemctl reboot
# In a NEW terminal after boot:
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now
systemctl is-active aegis-firewall-sentinel.service NetworkManager firewalld
sudo nft list tables
systemctl --failed --no-pager</code></pre><p><b>Beklenen başarı göstergesi (örnek)</b></p><pre><code>VERIFIED: base Network Hardening, ... runtime table match.
AEGIS Firewall Sentinel monitor: INFO
active
active
active
table inet firewalld
table inet aegis_sentinel
0 loaded units listed.</code></pre>
</td></tr></tbody></table>


## 3 — Complete user-command catalog / Tüm kullanıcı komutları

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<p><b>Convention:</b> First declare <code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py</code> in each new shell. All placeholders &lt;…&gt; must be replaced. Examples are conditional; a precondition failure legitimately prints <code>STOP</code>. Commands with <b>HIGH/CRITICAL</b> are documented, not recommended for casual execution.</p>
</td><td valign="top">
<p><b>Kural:</b> Her yeni kabukta önce <code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py</code> tanımla. &lt;…&gt; yer tutucularını değiştir. Örnekler koşulludur; önkoşul başarısızlığı <code>STOP</code> üretebilir. <b>HIGH/CRITICAL</b> komutlar deneme önerisi değil, tam referanstır.</p>
</td></tr></tbody></table>


<a id="command-version"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`version` — Version / binary identity</h3><p>Print the runtime version without modifying the system.</p><p><strong>Usage / invocation</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; version</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>0.9.0-alpha2-review5</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`version` — Sürüm / betik kimliği</h3><p>Sistemi değiştirmeden çalışan betiğin sürümünü gösterir.</p><p><strong>Kullanım</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; version</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>0.9.0-alpha2-review5</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-packages"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`packages` — Dependency inventory</h3><p>Display tested Fedora package versions and required executables; it never installs, removes, or updates packages.</p><p><strong>Usage / invocation</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; packages</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>No package is installed, removed, or updated by this script.
firewalld=&lt;VERSION&gt;
nftables=&lt;VERSION&gt;
NetworkManager=&lt;VERSION&gt;
systemd=&lt;VERSION&gt;
nft=PRESENT</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`packages` — Paket ve araç envanteri</h3><p>Test edilmiş Fedora paket sürümlerini ve gerekli araçları listeler; paket kurmaz, kaldırmaz veya güncellemez.</p><p><strong>Kullanım</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; packages</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>No package is installed, removed, or updated by this script.
firewalld=&lt;VERSION&gt;
nftables=&lt;VERSION&gt;
NetworkManager=&lt;VERSION&gt;
systemd=&lt;VERSION&gt;
nft=PRESENT</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-verify-install"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`verify-install` — Installed-file trust check</h3><p>Confirm the root-owned deployed file, its version and SHA-256. With --source, compare against a reviewed source file.</p><p><strong>Usage / invocation</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; verify-install --source ./aegis-firewall-sentinel.py</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>INSTALLED_SHA256=&lt;64_HEX&gt;
INSTALLED_VERSION=0.9.0-alpha2-review5
SOURCE_SHA256=&lt;SAME_64_HEX&gt;
VERIFIED_INSTALL: root-owned runtime is present and version-readable.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`verify-install` — Kurulu dosya bütünlük kontrolü</h3><p>Root sahipliğinde kurulmuş dosyanın sürümünü ve SHA-256 değerini doğrular; --source ile gözden geçirilmiş kaynakla karşılaştırır.</p><p><strong>Kullanım</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; verify-install --source ./aegis-firewall-sentinel.py</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>INSTALLED_SHA256=&lt;64_HEX&gt;
INSTALLED_VERSION=0.9.0-alpha2-review5
SOURCE_SHA256=&lt;SAME_64_HEX&gt;
VERIFIED_INSTALL: root-owned runtime is present and version-readable.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-audit"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`audit` — Bounded diagnostic report</h3><p>Show firewalld/nftables and network-layer evidence read-only; inspect output for local network metadata before sharing.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; audit</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>AEGIS Firewall Sentinel 0.9.0-alpha2-review5 — READ-ONLY AUDIT
=== firewalld unit ===
...
=== nftables tables ===
...
AUDIT NOTE: wildcard listeners ...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`audit` — Sınırlandırılmış tanılama raporu</h3><p>firewalld/nftables ve ağ katmanı bulgularını salt-okunur raporlar; çıktıyı paylaşmadan önce yerel ağ bilgilerini ayıkla.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; audit</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>AEGIS Firewall Sentinel 0.9.0-alpha2-review5 — READ-ONLY AUDIT
=== firewalld unit ===
...
=== nftables tables ===
...
AUDIT NOTE: wildcard listeners ...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-validate"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`validate` — Preflight configuration validation</h3><p>Validate disk configuration, candidate nft syntax, generated systemd units, and the prerequisite Network Hardening layer. It does not apply a policy.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; validate</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>VALIDATED: firewalld disk config, candidate nftables syntax, generated systemd units, and Network Hardening base passed.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`validate` — Ön yapılandırma doğrulaması</h3><p>Disk yapılandırmasını, aday nft sözdizimini, üretilecek systemd birimlerini ve önkoşul Network Hardening katmanını denetler. Politika uygulamaz.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; validate</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>VALIDATED: firewalld disk config, candidate nftables syntax, generated systemd units, and Network Hardening base passed.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-plan"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`plan` — Review proposed changes</h3><p>Print reviewed interfaces/connection UUIDs, intended blocks, toggles, file/unit changes, and a plan SHA. Dry-run only.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>AEGIS Firewall Sentinel 0.9.0-alpha2-review5 | ACTION=apply | PLAN_SHA256=&lt;64_HEX&gt;
Quarantine: OFF
Direct plaintext DNS (53) egress: PASSTHROUGH
=== FIREWALL ACTIONS ===
...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`plan` — Önerilen değişiklikleri inceleme</h3><p>Gözden geçirilmiş arayüzleri/bağlantı UUID’lerini, engelleri, seçenekleri, dosya/birim değişikliklerini ve plan SHA değerini gösterir. Salt-okunurdur.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>AEGIS Firewall Sentinel 0.9.0-alpha2-review5 | ACTION=apply | PLAN_SHA256=&lt;64_HEX&gt;
Quarantine: OFF
Direct plaintext DNS (53) egress: PASSTHROUGH
=== FIREWALL ACTIONS ===
...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-apply"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`apply` — Transactional enforcement</h3><p>Create policy, units, manifest and runtime rules transactionally. Requires verified active local physical TTY and approval of current plan SHA; can disrupt networking.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>Type exactly &quot;APPLY &lt;CURRENT_PLAN_SHA256&gt;&quot; to continue:
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;
# If already identical: NO-OP + VERIFIED</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`apply` — İşlem bütünlüklü uygulama</h3><p>Politika, birimler, manifest ve canlı kuralları işlemsel olarak oluşturur. Aktif fiziksel yerel TTY ve güncel plan SHA onayı gerekir; ağı kesebilir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>Type exactly &quot;APPLY &lt;CURRENT_PLAN_SHA256&gt;&quot; to continue:
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;
# If already identical: NO-OP + VERIFIED</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-verify"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`verify` — Read-only installed-state attestation</h3><p>Check base layer, generated policy files, manifest, quarantine state, systemd units and active nftables semantics; use after reboot and any change.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`verify` — Kurulu durumun salt-okunur doğrulaması</h3><p>Temel katman, üretilmiş politika dosyaları, manifest, karantina durumu, systemd birimleri ve canlı nftables semantiğini kontrol eder; reboot ve değişiklik sonrasında çalıştır.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-status"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`status` — Concise operational snapshot</h3><p>Print current policy, VPN/quarantine flags, transient enforcement state and latest transaction/monitor status.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; status</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>VERSION=0.9.0-alpha2-review5
POLICY_INSTALLED=yes
QUARANTINE=off
NFT_TABLE=present
TRANSACTION_STATUS=COMMITTED
MONITOR_STATUS=info</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`status` — Özet çalışma durumu</h3><p>Politika, VPN/karantina anahtarları, geçici uygulama durumu ve son işlem/izleme durumunu gösterir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; status</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>VERSION=0.9.0-alpha2-review5
POLICY_INSTALLED=yes
QUARANTINE=off
NFT_TABLE=present
TRANSACTION_STATUS=COMMITTED
MONITOR_STATUS=info</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-history"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`history` — Transaction journal</h3><p>List committed and rolled-back transaction IDs; obtain a real transaction ID before invoking rollback.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>T-&lt;UTC_TIMESTAMP&gt;-&lt;HEX&gt; COMMITTED
# Or: NO TRANSACTIONS</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`history` — İşlem geçmişi</h3><p>Tamamlanmış ve geri alınmış işlem kimliklerini listeler; rollback için gerçek işlem kimliğini buradan al.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>T-&lt;UTC_TIMESTAMP&gt;-&lt;HEX&gt; COMMITTED
# Or: NO TRANSACTIONS</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-monitor-now"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`monitor-now` — On-demand drift monitoring</h3><p>Check integrity and non-fatal listener observations. INFO reports are not proof that wildcard sockets are externally reachable.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>AEGIS Firewall Sentinel monitor: INFO
INFO     WILDCARD_LISTENERS: tcp 0.0.0.0:5355; udp 0.0.0.0:5353; ...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`monitor-now` — Anlık bütünlük sapması denetimi</h3><p>Bütünlük denetimi ve ölümcül olmayan dinleyici gözlemleri sunar. INFO raporu wildcard soketlerinin dışarıdan erişildiğini kanıtlamaz.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>AEGIS Firewall Sentinel monitor: INFO
INFO     WILDCARD_LISTENERS: tcp 0.0.0.0:5355; udp 0.0.0.0:5353; ...</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-watch"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`watch` — Live, bounded NFLOG telemetry</h3><p>Stream NFLOG group 10 drops/rejects with tcpdump; press Ctrl+C to exit. No events is possible when nothing matches.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; watch</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>Listening on nflog:10; telemetry is rate-limited ...
# Event lines appear only when matching traffic occurs.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`watch` — Canlı, sınırlanmış NFLOG gözlemi</h3><p>NFLOG grup 10 engelleme/reddetme örneklerini tcpdump ile canlı izler; Ctrl+C ile sonlandır. Engellenen trafik yoksa satır gelmeyebilir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; watch</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>Listening on nflog:10; telemetry is rate-limited ...
# Event lines appear only when matching traffic occurs.</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-list-blocked"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`list-blocked` — Inspect transient deny set</h3><p>List temporary IP/CIDR entries or show that the RAM-only table is inactive.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; list-blocked</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>DYNAMIC BLOCKLIST: inactive (no blocked IPs)
# Or current nft set/table output</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td><td valign="top">
<h3>`list-blocked` — Geçici engel kümesini gösterme</h3><p>Geçici IP/CIDR kayıtlarını listeler veya RAM tablosunun etkin olmadığını bildirir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; list-blocked</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>DYNAMIC BLOCKLIST: inactive (no blocked IPs)
# Or current nft set/table output</code></pre><p><small><b>Risk:</b> LOW</small></p>
</td></tr></tbody></table>


<a id="command-block-ip"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`block-ip` — Temporary address deny</h3><p>Block an address/CIDR in kernel memory with TTL (60 seconds–30 days; default 24 hours). Experimental: may interrupt connections.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; block-ip 203.0.113.15 --ttl 1h</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s in inet aegis_blocklist @blocked_v4</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`block-ip` — Süreli IP/adres engelleme</h3><p>Bir IP/CIDR’ı çekirdek belleğinde TTL ile (60 saniye–30 gün; varsayılan 24 saat) engeller. Deneysel: bağlantıları kesebilir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; block-ip 203.0.113.15 --ttl 1h</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s in inet aegis_blocklist @blocked_v4</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-unblock-ip"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`unblock-ip` — Remove one transient deny</h3><p>Remove a specific temporary IP/CIDR block, without touching the rest of the Sentinel policy.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; unblock-ip 203.0.113.15</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>UNBLOCKED: 203.0.113.15/32 from inet aegis_blocklist @blocked_v4
# Or: DYNAMIC BLOCKLIST TABLE IS NOT ACTIVE</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`unblock-ip` — Tek bir geçici engeli kaldırma</h3><p>Belirli IP/CIDR engelini kaldırır; Sentinel politikasının geri kalanına dokunmaz.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; unblock-ip 203.0.113.15</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>UNBLOCKED: 203.0.113.15/32 from inet aegis_blocklist @blocked_v4
# Or: DYNAMIC BLOCKLIST TABLE IS NOT ACTIVE</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-isolate-cgroup-lan"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`isolate-cgroup-lan` — Block a cgroup from private LAN</h3><p>Apply RAM-only LAN egress isolation to an existing cgroupv2 path; path/inode identity matters. Not field tested.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; isolate-cgroup-lan &#x27;&lt;RELATIVE_CGROUP_PATH&gt;&#x27;</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=&lt;N&gt; path=&lt;PATH&gt; inode=&lt;N&gt;</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`isolate-cgroup-lan` — cgroup için yerel ağ izolasyonu</h3><p>Var olan cgroupv2 yoluna RAM tabanlı LAN çıkış izolasyonu uygular; yol/inode kimliği önemlidir. Saha testi yapılmadı.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; isolate-cgroup-lan &#x27;&lt;RELATIVE_CGROUP_PATH&gt;&#x27;</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=&lt;N&gt; path=&lt;PATH&gt; inode=&lt;N&gt;</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-unisolate-cgroup-lan"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`unisolate-cgroup-lan` — Remove cgroup isolation</h3><p>Remove the RAM-only cgroup filter and temporary binding information.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; unisolate-cgroup-lan</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>CGROUP LAN ISOLATION OFF</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`unisolate-cgroup-lan` — cgroup izolasyonunu kaldırma</h3><p>RAM tabanlı cgroup filtresini ve geçici bağlama bilgilerini kaldırır.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; unisolate-cgroup-lan</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>CGROUP LAN ISOLATION OFF</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-rebind-cgroup-lan"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`rebind-cgroup-lan` — Reattach isolation after cgroup restart</h3><p>Re-bind a previously registered cgroup path to a new inode after re-creation; requires prior state. Experimental.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; rebind-cgroup-lan</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=&lt;N&gt; path=&lt;PATH&gt; inode=&lt;NEW_N&gt;</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td><td valign="top">
<h3>`rebind-cgroup-lan` — Yeniden oluşan cgroup’a izolasyon bağlama</h3><p>Daha önce kaydedilmiş cgroup yolu yeniden oluştuğunda izolasyonu yeni inode’a bağlar; önceki kayıt gerekir. Deneysel.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; rebind-cgroup-lan</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=&lt;N&gt; path=&lt;PATH&gt; inode=&lt;NEW_N&gt;</code></pre><p><small><b>Risk:</b> HIGH</small></p>
</td></tr></tbody></table>


<a id="command-quarantine-on"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`quarantine-on` — High-impact emergency isolation</h3><p>Enable persistent emergency isolation through a transaction; preview with plan --quarantine-on first. Not field-tested.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --quarantine-on
# On physical TTY, only after explicit recovery planning:
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-on</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>ACTION=quarantine-on | PLAN_SHA256=&lt;64_HEX&gt;
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td><td valign="top">
<h3>`quarantine-on` — Yüksek etkili acil karantina</h3><p>İşlemsel olarak kalıcı acil izolasyonu etkinleştirir; önce plan --quarantine-on ile önizle. Saha testi yapılmadı.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --quarantine-on
# On physical TTY, only after explicit recovery planning:
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-on</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>ACTION=quarantine-on | PLAN_SHA256=&lt;64_HEX&gt;
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td></tr></tbody></table>


<a id="command-quarantine-off"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`quarantine-off` — Return to standard Sentinel policy</h3><p>Disable persistent quarantine and rebuild normal Sentinel rules via an approved physical-TTY transaction. Not field-tested.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-off</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>ACTION=quarantine-off | PLAN_SHA256=&lt;64_HEX&gt;
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td><td valign="top">
<h3>`quarantine-off` — Normal Sentinel politikasına dönüş</h3><p>Fiziksel TTY ve onaylı işlemle kalıcı karantinayı kaldırıp normal Sentinel kurallarına döner. Saha testi yapılmadı.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-off</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>ACTION=quarantine-off | PLAN_SHA256=&lt;64_HEX&gt;
...
COMMITTED: T-&lt;TIMESTAMP&gt;-&lt;HEX&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td></tr></tbody></table>


<a id="command-panic-off"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`panic-off` — Clear temporary panic table</h3><p>Remove only the RAM-only inet aegis_panic table. Does not disable persistent quarantine. Recovery only.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; panic-off</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>EMERGENCY PANIC ISOLATION OFF
# Or: EMERGENCY PANIC ISOLATION ALREADY OFF</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td><td valign="top">
<h3>`panic-off` — Geçici panik tablosunu kaldırma</h3><p>Yalnızca RAM tabanlı inet aegis_panic tablosunu kaldırır. Kalıcı karantinayı kapatmaz. Sadece kurtarma kullanımı.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; panic-off</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>EMERGENCY PANIC ISOLATION OFF
# Or: EMERGENCY PANIC ISOLATION ALREADY OFF</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td></tr></tbody></table>


<a id="command-rollback"></a>
<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>`rollback` — Conflict-aware transaction rollback</h3><p>Rollback a committed transaction after checking history and confirming the transaction plan digest. Alters network configuration.</p><p><strong>Usage / invocation</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history
# On verified physical TTY:
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; rollback &#x27;&lt;TX_ID&gt;&#x27;</code></pre><p><strong>Expected output / conditional example</strong></p><pre><code>Type exactly &quot;ROLLBACK &lt;TX_ID&gt; &lt;SHA256_OF_PLAN_JSON&gt;&quot; to continue:
ROLLED BACK: &lt;TX_ID&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td><td valign="top">
<h3>`rollback` — Çakışma denetimli işlem geri alma</h3><p>history ile doğrulanmış tamamlanmış işlemi plan özeti onayıyla geri alır. Ağ yapılandırmasını değiştirir.</p><p><strong>Kullanım</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history
# On verified physical TTY:
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; rollback &#x27;&lt;TX_ID&gt;&#x27;</code></pre><p><strong>Beklenen çıktı / koşullu örnek</strong></p><pre><code>Type exactly &quot;ROLLBACK &lt;TX_ID&gt; &lt;SHA256_OF_PLAN_JSON&gt;&quot; to continue:
ROLLED BACK: &lt;TX_ID&gt;</code></pre><p><small><b>Risk:</b> CRITICAL</small></p>
</td></tr></tbody></table>


## 4 — Complete policy flag reference / Politika parametreleri

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<p>For each option, **plan** is a preview, not policy activation. A different plan, missing prerequisite or unapproved interface may yield <code>STOP</code>. Note that the source exposes deprecated and internal flags too.</p>
</td><td valign="top">
<p>Her seçenek için **plan**, uygulama değil önizlemedir. Plan değişimi, eksik önkoşul veya onaysız arayüz <code>STOP</code> verebilir. Kaynakta artık kullanılmayan ve dahili parametreler de vardır.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>LAN SMB, RPC &amp; NetBIOS</h3><p>Use --allow-lan-smb only when a reviewed trusted profile needs these protocols (e.g. SMB printing). --deny-lan-smb returns to the default block.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-lan-smb</code></pre><p><strong>Expected / conditional</strong></p><pre><code>LAN SMB/RPC/NetBIOS egress: ALLOWED</code></pre>
</td><td valign="top">
<h3>Yerel ağ SMB, RPC ve NetBIOS</h3><p>Yalnızca incelenmiş güvenli profil bu protokollere (ör. SMB yazdırma) gereksinim duyduğunda --allow-lan-smb kullan; --deny-lan-smb varsayılan engele döner.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-lan-smb</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>LAN SMB/RPC/NetBIOS egress: ALLOWED</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>SSDP LAN discovery</h3><p>Allow SSDP only on the trusted profile with --allow-lan-ssdp; --deny-lan-ssdp closes it again.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-lan-ssdp</code></pre><p><strong>Expected / conditional</strong></p><pre><code>LAN SSDP egress: ALLOWED</code></pre>
</td><td valign="top">
<h3>Yerel ağ SSDP keşfi</h3><p>SSDP’yi yalnızca güvenilir profilde --allow-lan-ssdp ile aç; --deny-lan-ssdp yeniden kapatır.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-lan-ssdp</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>LAN SSDP egress: ALLOWED</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Plaintext DNS egress</h3><p>--block-direct-dns prevents port-53 direct outbound traffic outside loopback. --allow-direct-dns restores pass-through when strict DoT is off. Never block before a tested encrypted resolver exists.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --block-direct-dns</code></pre><p><strong>Expected / conditional</strong></p><pre><code>Direct plaintext DNS (53) egress: BLOCKED</code></pre>
</td><td valign="top">
<h3>Düz DNS çıkışı</h3><p>--block-direct-dns loopback dışındaki doğrudan port 53 trafiğini engeller; --allow-direct-dns strict DoT kapalıysa geçişi geri açar. Şifreli çözümleyici doğrulanmadan engelleme yapma.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --block-direct-dns</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>Direct plaintext DNS (53) egress: BLOCKED</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Strict DNS-over-TLS</h3><p>--strict-dot-resolver requires systemd-resolved to pass a verified DoT preflight; --no-strict-dot-resolver releases this requirement. It FAILED on the test machine.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --strict-dot-resolver</code></pre><p><strong>Expected / conditional</strong></p><pre><code>STOP: Strict DoT preflight failed: ...</code></pre>
</td><td valign="top">
<h3>Zorunlu DNS-over-TLS</h3><p>--strict-dot-resolver doğrulanmış systemd-resolved DoT yapılandırması ister; --no-strict-dot-resolver gereksinimi kaldırır. Test makinesinde önkoşul başarısızdı.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --strict-dot-resolver</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>STOP: Strict DoT preflight failed: ...</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Approved DoT IP / TLS name</h3><p>Repeat --dot-server &lt;IP&gt; for approved resolvers and provide --dot-server-name &lt;SNI&gt; to validate the peer TLS name; match actual resolver configuration.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --strict-dot-resolver --dot-server 9.9.9.9 --dot-server-name dns.quad9.net</code></pre><p><strong>Expected / conditional</strong></p><pre><code>STOP: Strict DoT preflight failed: ...  # if not configured</code></pre>
</td><td valign="top">
<h3>DoT sunucu IP ve TLS adı</h3><p>İzinli çözümleyiciler için --dot-server &lt;IP&gt; yinele; TLS adını doğrulamak için --dot-server-name &lt;SNI&gt; ver. Gerçek resolver yapılandırmasıyla uyumlu olmalı.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --strict-dot-resolver --dot-server 9.9.9.9 --dot-server-name dns.quad9.net</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>STOP: Strict DoT preflight failed: ...  # if not configured</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>VPN kill-switch &amp; endpoint</h3><p>--vpn-only &lt;IFACE&gt; enforces tunnel egress; --vpn-endpoint &lt;IP:PORT/proto&gt; supplies a handshake exception. --vpn-off disables it. Example TEST-NET IP is not a real VPN server.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --vpn-only wg0 --vpn-endpoint 198.51.100.10:51820/udp</code></pre><p><strong>Expected / conditional</strong></p><pre><code>VPN kill-switch: ON (iface=wg0, ...)  # only if accepted</code></pre>
</td><td valign="top">
<h3>VPN kill-switch ve uç nokta</h3><p>--vpn-only &lt;IFACE&gt; tünel dışı trafiği sınırlar; --vpn-endpoint &lt;IP:PORT/proto&gt; handshake istisnasıdır. --vpn-off kapatır. TEST-NET örnek IP gerçek VPN sunucusu değildir.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --vpn-only wg0 --vpn-endpoint 198.51.100.10:51820/udp</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>VPN kill-switch: ON (iface=wg0, ...)  # only if accepted</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>LAN while VPN-only</h3><p>--vpn-allow-lan permits reviewed local access within a VPN-only profile; --vpn-deny-lan forbids it. Has meaning only with an active VPN policy.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --vpn-only wg0 --vpn-allow-lan</code></pre><p><strong>Expected / conditional</strong></p><pre><code>VPN kill-switch: ON (iface=wg0, allow_lan=True, ...)  # conditional</code></pre>
</td><td valign="top">
<h3>VPN açıkken LAN erişimi</h3><p>--vpn-allow-lan VPN-only profilinde incelenmiş LAN erişimini açar; --vpn-deny-lan kapatır. Yalnızca VPN politikası etkinse anlamlıdır.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --vpn-only wg0 --vpn-allow-lan</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>VPN kill-switch: ON (iface=wg0, allow_lan=True, ...)  # conditional</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Foreign nftables table allowlist</h3><p>--allow-foreign-table &lt;FAMILY:NAME&gt; attests a specific external table; --remove-foreign-table removes authorization. Never permit unknown hooks blindly.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-foreign-table inet:approved_example</code></pre><p><strong>Expected / conditional</strong></p><pre><code>Approved foreign tables: inet:approved_example  # only after attestation</code></pre>
</td><td valign="top">
<h3>Yabancı nftables tablo izin listesi</h3><p>--allow-foreign-table &lt;FAMILY:NAME&gt; belirli harici tablo için doğrulanmış izin ekler; --remove-foreign-table geri alır. Bilinmeyen hook’lara körlemesine izin verme.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-foreign-table inet:approved_example</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>Approved foreign tables: inet:approved_example  # only after attestation</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Quarantine preview</h3><p>--quarantine-on / --quarantine-off as plan flags show candidate state; applying or invoking quarantine commands changes live policy and can cut network access.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --quarantine-on</code></pre><p><strong>Expected / conditional</strong></p><pre><code>Quarantine: ON  # preview only</code></pre>
</td><td valign="top">
<h3>Karantina önizleme</h3><p>--quarantine-on / --quarantine-off plan seçenekleri aday durumu gösterir; apply veya quarantine komutları canlı politikayı değiştirip ağı kesebilir.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --quarantine-on</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>Quarantine: ON  # preview only</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Reviewed package-version escape</h3><p>--allow-newer-packages relaxes the reviewed package-version guard; it does not update packages and requires compatibility review.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-newer-packages</code></pre><p><strong>Expected / conditional</strong></p><pre><code>PLAN_SHA256=&lt;CURRENT_HEX&gt;  # only if package check passes</code></pre>
</td><td valign="top">
<h3>İncelenmiş paket sürümü sınırı</h3><p>--allow-newer-packages incelenen paket sürüm sınırını gevşetir; paket güncellemez ve uyumluluk incelemesi gerektirir.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --allow-newer-packages</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>PLAN_SHA256=&lt;CURRENT_HEX&gt;  # only if package check passes</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Legacy manual-interface trust flags</h3><p>--trust-interface and --untrust-interface are intentionally disabled. Interface trust comes from approved NetworkManager connection UUIDs.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --trust-interface eth0</code></pre><p><strong>Expected / conditional</strong></p><pre><code>STOP: Legacy --trust-interface/--untrust-interface is disabled: ...</code></pre>
</td><td valign="top">
<h3>Eski elle arayüz güveni seçenekleri</h3><p>--trust-interface ve --untrust-interface bilerek devre dışıdır. Güven ilişkisi onaylı NetworkManager bağlantı UUID’lerinden türetilir.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; plan --trust-interface eth0</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>STOP: Legacy --trust-interface/--untrust-interface is disabled: ...</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Noninteractive approval</h3><p>--approve &lt;CURRENT_PLAN_SHA256&gt; avoids typing the APPLY approval but does NOT bypass physical-TTY/session checks. rollback uses a different plan.json digest.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply --approve &quot;&lt;CURRENT_PLAN_SHA256&gt;&quot;</code></pre><p><strong>Expected / conditional</strong></p><pre><code>STOP: ...  # if wrong session or digest; mutation on success</code></pre>
</td><td valign="top">
<h3>Etkileşimsiz onay özeti</h3><p>--approve &lt;CURRENT_PLAN_SHA256&gt; APPLY onayını yazma gereksinimini kaldırır ancak fiziksel TTY/oturum kontrolünü atlatmaz. rollback ayrı plan.json özetini kullanır.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; apply --approve &quot;&lt;CURRENT_PLAN_SHA256&gt;&quot;</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>STOP: ...  # if wrong session or digest; mutation on success</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Temporary block timeout</h3><p>--ttl &lt;DURATION&gt; on block-ip accepts 60 seconds to 30 days, default 24h. High-risk mutation, not field tested.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; block-ip 203.0.113.15 --ttl 1h</code></pre><p><strong>Expected / conditional</strong></p><pre><code>BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s ...  # conditional</code></pre>
</td><td valign="top">
<h3>Geçici engel süresi</h3><p>block-ip üzerindeki --ttl &lt;DURATION&gt; 60 saniye–30 gün kabul eder; varsayılan 24h. Yüksek riskli ve saha testi yapılmadı.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; block-ip 203.0.113.15 --ttl 1h</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s ...  # conditional</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Compare installed runtime to source</h3><p>verify-install --source compares the protected runtime with a local source file by SHA256; no firewall change.</p><p><strong>Example</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; verify-install --source ./aegis-firewall-sentinel.py</code></pre><p><strong>Expected / conditional</strong></p><pre><code>SOURCE_SHA256=&lt;SAME_64_HEX&gt;
VERIFIED_INSTALL: root-owned runtime is present and version-readable.</code></pre>
</td><td valign="top">
<h3>Kurulu betiği kaynakla karşılaştırma</h3><p>verify-install --source korumalı çalışan dosyayı SHA256 ile yerel kaynakla karşılaştırır; firewall değiştirmez.</p><p><strong>Örnek</strong></p><pre><code>/usr/bin/python3 -I &quot;$AEGIS&quot; verify-install --source ./aegis-firewall-sentinel.py</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>SOURCE_SHA256=&lt;SAME_64_HEX&gt;
VERIFIED_INSTALL: root-owned runtime is present and version-readable.</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Emergency break-glass isolation</h3><p>--force-emergency on quarantine-on is CRITICAL and untested. It uses a distinct, WEAKER emergency terminal/loginuid gate than normal active-logind-session authorization; can disconnect the host.</p><p><strong>Example</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-on --force-emergency</code></pre><p><strong>Expected / conditional</strong></p><pre><code>EMERGENCY PANIC ISOLATION ACTIVE (RAM-ONLY): inet aegis_panic ...</code></pre>
</td><td valign="top">
<h3>Acil durum koruma istisnası</h3><p>quarantine-on --force-emergency KRİTİK ve test edilmemiştir. Normal aktif logind yetkilendirmesinden DAHA ZAYIF ayrı bir TTY/loginuid kapısı kullanır; bağlantıyı kesebilir.</p><p><strong>Örnek</strong></p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; quarantine-on --force-emergency</code></pre><p><strong>Beklenen / koşullu</strong></p><pre><code>EMERGENCY PANIC ISOLATION ACTIVE (RAM-ONLY): inet aegis_panic ...</code></pre>
</td></tr></tbody></table>


## 5 — Internal-only entrypoints / Yalnızca iç servis giriş noktaları

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>runtime-load</h3><p>systemd service boot loader; run only from generated unit. Hand execution is rejected or unsafe.</p><p><strong>Expected output:</strong> normally silent success, or <code>STOP</code> for a wrong systemd/dispatcher context. <b>Do not execute manually.</b></p>
</td><td valign="top">
<h3>runtime-load</h3><p>systemd servis başlangıç yükleyicisi; yalnızca üretilmiş birim çağırır. Elle çalıştırmak reddedilebilir veya güvensizdir.</p><p><strong>Beklenen çıktı:</strong> genellikle sessiz başarı veya yanlış systemd/dispatcher bağlamında <code>STOP</code>. <b>Elle çalıştırma.</b></p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>network-gate</h3><p>NetworkManager startup integrity gate; requires valid committed manifest. Never use as an interactive health check.</p><p><strong>Expected output:</strong> normally silent success, or <code>STOP</code> for a wrong systemd/dispatcher context. <b>Do not execute manually.</b></p>
</td><td valign="top">
<h3>network-gate</h3><p>NetworkManager başlangıç bütünlük kapısı; geçerli committed manifest ister. Elle sağlık kontrolü olarak çalıştırma.</p><p><strong>Beklenen çıktı:</strong> genellikle sessiz başarı veya yanlış systemd/dispatcher bağlamında <code>STOP</code>. <b>Elle çalıştırma.</b></p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>trust-sync --dispatcher</h3><p>NetworkManager dispatcher drives reviewed connection-UUID-to-iface trust mapping; hook-only context.</p><p><strong>Expected output:</strong> normally silent success, or <code>STOP</code> for a wrong systemd/dispatcher context. <b>Do not execute manually.</b></p>
</td><td valign="top">
<h3>trust-sync --dispatcher</h3><p>NetworkManager dispatcher, incelenmiş bağlantı UUID’sinden güvenilir arayüz kümesini oluşturur; yalnızca hook bağlamı.</p><p><strong>Beklenen çıktı:</strong> genellikle sessiz başarı veya yanlış systemd/dispatcher bağlamında <code>STOP</code>. <b>Elle çalıştırma.</b></p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>emergency-rollback</h3><p>Watchdog-driven rollback of an incomplete same-boot transaction; not a general-purpose recovery command.</p><p><strong>Expected output:</strong> normally silent success, or <code>STOP</code> for a wrong systemd/dispatcher context. <b>Do not execute manually.</b></p>
</td><td valign="top">
<h3>emergency-rollback</h3><p>Aynı açılışta yarım kalan işlemi watchdog ile geri alır; genel kurtarma komutu değildir.</p><p><strong>Beklenen çıktı:</strong> genellikle sessiz başarı veya yanlış systemd/dispatcher bağlamında <code>STOP</code>. <b>Elle çalıştırma.</b></p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>monitor-now --systemd</h3><p>Scheduled monitor service invocation; suppresses interactive output. Prefer plain monitor-now manually.</p><p><strong>Expected output:</strong> normally silent success, or <code>STOP</code> for a wrong systemd/dispatcher context. <b>Do not execute manually.</b></p>
</td><td valign="top">
<h3>monitor-now --systemd</h3><p>Zamanlanmış monitor servis çağrısı; etkileşimli çıktıyı sınırlar. Kullanıcı için düz monitor-now tercih edilir.</p><p><strong>Beklenen çıktı:</strong> genellikle sessiz başarı veya yanlış systemd/dispatcher bağlamında <code>STOP</code>. <b>Elle çalıştırma.</b></p>
</td></tr></tbody></table>


## 6 — Troubleshooting with observed failure modes / Kanıtlı hata senaryoları

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Graphical user-manager session refused</h3><p>`STOP: Invoking terminal belongs to a systemd user-manager audit session`. This is intentional. Open physical TTY via Ctrl+Alt+F3, log in, confirm active local Class=user Type=tty, then apply there.</p>
</td><td valign="top">
<h3>Grafik kullanıcı yöneticisi oturumu reddedildi</h3><p>Bu hata kasıtlı güvenlik sınırıdır. Ctrl+Alt+F3 ile fiziksel TTY aç, kullanıcı olarak giriş yap, aktif yerel Class=user Type=tty doğrula, apply komutunu aynı yerde çalıştır.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Policy not installed after preflight</h3><p>`STOP: Firewall Sentinel policy is not installed` from verify is expected after preflight but before accepted apply. Do not call `network-gate` by hand.</p>
</td><td valign="top">
<h3>Preflight sonrası politika henüz yüklü değil</h3><p>Preflight ile kabul edilmiş apply arasında verify için `STOP: Firewall Sentinel policy is not installed` beklenir. `network-gate` elle çağrılmaz.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Stale systemd failure record</h3><p>The previous failed transaction left a unit in failed/not-found state. Before considering `systemctl reset-failed aegis-firewall-sentinel.service`, verify transaction says ROLLED_BACK, policy absent, managed nft table absent and NetworkManager active. Reset-failed clears the historical flag; it does not repair code.</p>
</td><td valign="top">
<h3>Önceki işlemden kalan systemd failed kaydı</h3><p>Önceki başarısız işlem birimi failed/not-found bıraktı. `systemctl reset-failed aegis-firewall-sentinel.service` düşünmeden önce ROLLED_BACK kaydını, politika ve Sentinel nft tablosunun yokluğunu, NetworkManager’ın aktifliğini doğrula. reset-failed yalnızca eski hata işaretini siler, kodu onarmaz.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Historic nft newline parser bug</h3><p>Review4 used a literal backslash-n in one synthetic nft transaction: `unexpected junk ... \n`. Fixed in review5. Never edit live nft rules manually to hide it; validate the installed source hash and run parser regression checks.</p>
</td><td valign="top">
<h3>Geçmiş nft satır sonu hatası</h3><p>Review4 bir nft işleminde gerçek satır sonu yerine metinsel ters bölü-n üretti: `unexpected junk ... \n`. Review5’te düzeltildi. Canlı nft kurallarını elle değiştirerek gizleme; kurulu SHA ve parser testlerini doğrula.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Strict DoT rejected</h3><p>Observed `Strict DoT preflight failed: ...`: systemd-resolved did not attest DNSOverTLS=yes and required `IP#SNI`. This is a genuine unmet policy prerequisite; do not block plaintext DNS until separate resolver work is verified.</p>
</td><td valign="top">
<h3>Zorunlu DoT reddedildi</h3><p>Gözlenen `Strict DoT preflight failed: ...`: systemd-resolved DNSOverTLS=yes ve zorunlu `IP#SNI` değerlerini doğrulamadı. Gerçek önkoşul eksikliğidir; ayrı resolver çalışması doğrulanmadan düz DNS engelleme.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>INFO listener alert</h3><p>`INFO WILDCARD_LISTENERS` recorded 5353 (Avahi) and 5355 (systemd-resolved) sockets; listening alone does not prove external reachability. Do not disable CUPS/Avahi without impact analysis.</p>
</td><td valign="top">
<h3>INFO dinleyici uyarısı</h3><p>`INFO WILDCARD_LISTENERS` 5353 (Avahi) ve 5355 (systemd-resolved) soketlerini gösterdi; dinleme dış erişim kanıtı değildir. Etki analizi olmadan CUPS/Avahi kapatma.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>NetworkManager IPv4 forwarding warning</h3><p>One boot warned `error setting IPv4 forwarding to &#x27;0&#x27;: Success` on a Wi-Fi P2P device; services and attestation stayed healthy. Root cause remains unconfirmed; do not attribute to Sentinel without further evidence.</p>
</td><td valign="top">
<h3>NetworkManager IPv4 forwarding uyarısı</h3><p>Bir açılışta Wi-Fi P2P cihazında `error setting IPv4 forwarding to &#x27;0&#x27;: Success` uyarısı görüldü; servisler ve doğrulama sağlıklı kaldı. Kök neden belirsiz; kanıtsız Sentinel kaynaklı sayma.</p>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>No printers configured</h3><p>`lpstat: No destinations added` on freshly formatted Fedora does not indicate a firewall failure. CUPS and Avahi ran; physical printing remains untested.</p>
</td><td valign="top">
<h3>Henüz yazıcı tanımlanmamış</h3><p>Yeni formatlı Fedora’da `lpstat: No destinations added` firewall hatası kanıtı değildir. CUPS ve Avahi çalıştı; gerçek yazdırma testi bekliyor.</p>
</td></tr></tbody></table>


## 7 — Operational health & evidence collection / İşletim sağlığı ve kanıt toplama

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Post-reboot safe inspection</h3><p>All commands below are observational. Successful DNS lookup on the reference Fedora did NOT mean encrypted transport. Journal output may contain host metadata; redact before sharing.</p><pre><code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now
systemctl is-active aegis-firewall-sentinel.service \
  aegis-firewall-sentinel-monitor.timer \
  aegis-firewall-sentinel-monitor.path \
  NetworkManager.service firewalld.service
sudo nft list tables
resolvectl query example.org
systemctl --failed --no-pager
sudo journalctl -b -u aegis-firewall-sentinel.service \
  -u NetworkManager.service -p warning -n 50 --no-pager</code></pre><p><b>Observed success markers on the test host, 2026-11-21</b></p><pre><code>VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.
AEGIS Firewall Sentinel monitor: INFO
active
active
active
active
active
table inet firewalld
table inet aegis_sentinel
0 loaded units listed.</code></pre>
</td><td valign="top">
<h3>Reboot sonrası güvenli denetim</h3><p>Aşağıdaki komutlar gözlem amaçlıdır. Referans Fedora’da başarılı DNS sorgusu şifreli taşıma anlamına GELMİYORDU. Günlüklerde makine bilgileri olabilir; paylaşmadan önce ayıkla.</p><pre><code>AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; verify
sudo /usr/bin/python3 -I &quot;$AEGIS&quot; monitor-now
systemctl is-active aegis-firewall-sentinel.service \
  aegis-firewall-sentinel-monitor.timer \
  aegis-firewall-sentinel-monitor.path \
  NetworkManager.service firewalld.service
sudo nft list tables
resolvectl query example.org
systemctl --failed --no-pager
sudo journalctl -b -u aegis-firewall-sentinel.service \
  -u NetworkManager.service -p warning -n 50 --no-pager</code></pre><p><b>Test makinesinde 2026-11-21 gözlenen başarı göstergeleri</b></p><pre><code>VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.
AEGIS Firewall Sentinel monitor: INFO
active
active
active
active
active
table inet firewalld
table inet aegis_sentinel
0 loaded units listed.</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>What counts as accepted</h3><p><b>Accepted on one Fedora 44 Surface Pro 9:</b> review5 preflight, committed apply from physical TTY, standalone verify, monitor INFO, one successful reboot with active five units and two nft tables, DNS resolution, zero failed units. <b>Not field-tested:</b> VPN kill-switch, quarantine, block-IP, cgroup controls, actual printing, strict DoT, power-loss rollback and remote management paths. A single success is not certification.</p>
</td><td valign="top">
<h3>Neleri kabul edilmiş sayıyoruz?</h3><p><b>Bir Fedora 44 Surface Pro 9 üzerinde kabul:</b> review5 preflight, fiziksel TTY’den committed apply, bağımsız verify, monitor INFO, beş aktif birim/iki nft tablosu ile başarılı bir reboot, DNS çözümleme, sıfır failed birim. <b>Saha testi yapılmayanlar:</b> VPN kill-switch, karantina, IP bloklama, cgroup, gerçek yazdırma, strict DoT, güç kesintisi rollback ve uzaktan yönetim. Tek başarı sertifika değildir.</p>
</td></tr></tbody></table>


## 8 — Recovery safeguards & release integrity / Kurtarma ve sürüm bütünlüğü

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Fail safely before retrying</h3><p>When apply fails, inspect `history`, transaction `status` files, actual nft tables and NetworkManager before retrying. Earlier failures generated `ROLLED_BACK`; do not assume every rollback succeeded. `reset-failed` is not an automatic fix. Never run `nft flush ruleset`, disable printing services, or call the internal `network-gate` as a manual health test.</p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history
sudo nft list tables
systemctl show NetworkManager.service -p ActiveState -p Result
systemctl --failed --no-pager
sudo journalctl -b -u aegis-firewall-sentinel.service -n 100 --no-pager</code></pre>
</td><td valign="top">
<h3>Tekrar denemeden önce güvenle teşhis et</h3><p>Apply başarısızsa `history`, işlem `status` dosyaları, gerçek nft tabloları ve NetworkManager durumunu incele. Önceki hatalarda `ROLLED_BACK` görüldü; her geri almanın başarılı olduğunu varsayma. `reset-failed` otomatik çözüm değildir. `nft flush ruleset` çalıştırma, yazdırmayı kapatma, iç `network-gate` komutunu sağlık testi gibi çağırma.</p><pre><code>sudo /usr/bin/python3 -I &quot;$AEGIS&quot; history
sudo nft list tables
systemctl show NetworkManager.service -p ActiveState -p Result
systemctl --failed --no-pager
sudo journalctl -b -u aegis-firewall-sentinel.service -n 100 --no-pager</code></pre>
</td></tr></tbody></table>

<table>
<thead><tr><th width="50%">ENGLISH 🇬🇧</th><th width="50%">TÜRKÇE 🇹🇷</th></tr></thead>
<tbody><tr><td valign="top">
<h3>Integrity, privacy, and distribution</h3><p>Every source/document/test file is listed in `SHA256SUMS`; test with `sha256sum -c SHA256SUMS`. No machine-specific Wi-Fi interface, home directory or trusted connection UUID should be committed. GitHub SHA-256 manifest integrity is not a detached, independently verified signature. The root-owned runtime was intentionally unchanged in this documentation release. See [Changelog](docs/CHANGELOG.md) and [Field evidence](docs/FIELD_ACCEPTANCE.md).</p>
</td><td valign="top">
<h3>Bütünlük, mahremiyet ve dağıtım</h3><p>Bütün kaynak/belge/test dosyaları `SHA256SUMS` içinde yer alır; `sha256sum -c SHA256SUMS` ile denetle. Makineye özel Wi-Fi arayüzü, ev dizini ve güvenilir bağlantı UUID’si GitHub’a aktarılmamalıdır. GitHub SHA-256 manifesti bağımsız doğrulanmış ayrık imza değildir. Bu dokümantasyon sürümünde root-owned Python runtime bilerek değiştirilmedi. [Değişiklikler](docs/CHANGELOG.md) ve [Saha kanıtları](docs/FIELD_ACCEPTANCE.md).</p>
</td></tr></tbody></table>


---
**Project / Proje:** [Fedora Hardening for Surface](https://github.com/Ozhana/Fedora_Hardening_for_Surface) · [MIT LICENSE](../LICENSE) · **State / Durum:** Field-verified alpha, reboot PASS on one host.
