# AEGIS Core — Fedora Hardening Stage 1

**Version:** `0.2.0-bash1`  
**Release status:** Project-host validated / Proje hostunda doğrulandı  
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
<p>AEGIS Core is the first hardening layer. It applies a small, explicit set of kernel/sysctl protections and, by default, disables new systemd-coredump payload storage/processing. It is transactional, refuses conflicting managed files, records rollback metadata, and never installs packages automatically.</p><ul><li><strong>10 managed sysctls</strong> covering protected links/FIFOs/regular files, SUID core dumps, kernel pointer/log exposure, ASLR, unprivileged BPF and Yama ptrace policy.</li><li><strong>Optional coredump policy</strong>: <code>Storage=none</code> and <code>ProcessSizeMax=0</code>.</li><li>No firewall, DNS, NTS, AIDE/rkhunter baseline, bootloader or package-management mutation.</li><li>Designed for native mutable Fedora 44; <code>surface-pro9</code> additionally verifies the expected Microsoft Surface Pro 9 Intel/x86_64 identity.</li></ul>
</td>
<td valign="top">
<h2>Genel Bakış</h2>
<p>AEGIS Core ilk hardening katmanıdır. Küçük ve açıkça tanımlanmış bir kernel/sysctl koruma kümesini uygular ve varsayılan olarak yeni systemd-coredump bellek payload’larının saklanmasını/işlenmesini kapatır. Transaction tabanlıdır, çakışan yönetilen dosyaların üzerine yazmaz, rollback metadata’sı tutar ve otomatik paket kurmaz.</p><ul><li><strong>10 yönetilen sysctl</strong>: protected link/FIFO/regular file korumaları, SUID core dump, kernel pointer/log görünürlüğü, ASLR, unprivileged BPF ve Yama ptrace politikası.</li><li><strong>İsteğe bağlı coredump politikası</strong>: <code>Storage=none</code> ve <code>ProcessSizeMax=0</code>.</li><li>Firewall, DNS, NTS, AIDE/rkhunter baseline, bootloader veya paket yönetimi değişikliği yapmaz.</li><li>Native ve mutable Fedora 44 için tasarlanmıştır; <code>surface-pro9</code> profili ayrıca Microsoft Surface Pro 9 Intel/x86_64 kimliğini doğrular.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>What it actually hardens</h2>
<p>The module does not blindly force every value downward/upward. For most controls it enforces a minimum safe target and preserves a stricter existing value. Two irreversible-style transitions are handled conservatively: an existing <code>kernel.unprivileged_bpf_disabled=1</code> is not changed to 2, and the module never introduces <code>kernel.yama.ptrace_scope=3</code>.</p><pre><code>Managed keys:
fs.protected_fifos
fs.protected_hardlinks
fs.protected_regular
fs.protected_symlinks
fs.suid_dumpable
kernel.dmesg_restrict
kernel.kptr_restrict
kernel.randomize_va_space
kernel.unprivileged_bpf_disabled
kernel.yama.ptrace_scope</code></pre><p>The persistent files are <code>/etc/sysctl.d/90-fedora-hardening-stage1.conf</code> and, unless <code>--keep-coredumps</code> is used, <code>/etc/systemd/coredump.conf.d/90-fedora-hardening-stage1.conf</code>.</p>
</td>
<td valign="top">
<h2>Gerçekte neyi sıkılaştırır?</h2>
<p>Modül her değeri körlemesine aşağı/yukarı zorlamaz. Çoğu kontrolde güvenli bir minimum hedef uygular ve mevcut değer daha sıkıysa onu korur. Geri dönüşü problemli olabilecek iki geçiş temkinli ele alınır: mevcut <code>kernel.unprivileged_bpf_disabled=1</code> değeri 2’ye zorlanmaz ve modül <code>kernel.yama.ptrace_scope=3</code> değerini kendisi oluşturmaz.</p><pre><code>Yönetilen anahtarlar:
fs.protected_fifos
fs.protected_hardlinks
fs.protected_regular
fs.protected_symlinks
fs.suid_dumpable
kernel.dmesg_restrict
kernel.kptr_restrict
kernel.randomize_va_space
kernel.unprivileged_bpf_disabled
kernel.yama.ptrace_scope</code></pre><p>Kalıcı dosyalar <code>/etc/sysctl.d/90-fedora-hardening-stage1.conf</code> ve <code>--keep-coredumps</code> kullanılmadıkça <code>/etc/systemd/coredump.conf.d/90-fedora-hardening-stage1.conf</code> yollarındadır.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Supported target and prerequisites</h2>
<ul><li>Native Fedora 44 with systemd; mutable RPM installation.</li><li>SELinux already <strong>Enforcing</strong>; the script does not change SELinux mode.</li><li><code>firewalld.service</code> already active and enabled.</li><li>CUPS/Avahi units must not be masked; the module protects printer/discovery availability from accidental blanket hardening.</li><li>Atomic/OSTree/bootc, WSL, containers and unsupported architectures are refused for mutation.</li><li>The <code>surface-pro9</code> profile is for Intel/x86_64 Surface Pro 9; SQ3/ARM is outside that profile.</li></ul>
</td>
<td valign="top">
<h2>Desteklenen hedef ve önkoşullar</h2>
<ul><li>systemd kullanan native Fedora 44; mutable RPM kurulumu.</li><li>SELinux önceden <strong>Enforcing</strong> olmalıdır; betik SELinux modunu değiştirmez.</li><li><code>firewalld.service</code> önceden active ve enabled olmalıdır.</li><li>CUPS/Avahi unit’leri maskeli olmamalıdır; modül yazıcı/keşif kullanılabilirliğinin kör hardening ile bozulmasını ön kontrol eder.</li><li>Atomic/OSTree/bootc, WSL, container ve destek dışı mimarilerde mutasyon reddedilir.</li><li><code>surface-pro9</code> profili Intel/x86_64 Surface Pro 9 içindir; SQ3/ARM bu profilin kapsamı dışındadır.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Installation</h2>
<p>The script can be run from a verified release directory. For a permanent copy, use a root-owned libexec path; no systemd service or timer is installed.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./fh-terminal.sh --version

sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/core
sudo install -o root -g root -m 0755 ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh
sudo restorecon -RFv /usr/local/libexec/aegis/core

AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
/usr/bin/bash -p -- "$AEGIS_CORE" --version</code></pre><p>Expected version: <code>0.2.0-bash1</code>. Never source the file; start it with <code>/usr/bin/bash -p --</code>.</p>
</td>
<td valign="top">
<h2>Kurulum</h2>
<p>Betik doğrulanmış release klasöründen çalıştırılabilir. Kalıcı bir kopya için root-owned libexec yolu kullanın; systemd service veya timer kurulmaz.</p><pre><code>LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./fh-terminal.sh --version

sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/core
sudo install -o root -g root -m 0755 ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh
sudo restorecon -RFv /usr/local/libexec/aegis/core

AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
/usr/bin/bash -p -- "$AEGIS_CORE" --version</code></pre><p>Beklenen sürüm: <code>0.2.0-bash1</code>. Dosyayı <code>source</code> etmeyin; <code>/usr/bin/bash -p --</code> ile başlatın.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>First-time use</h2>
<p>Use <code>audit → plan → apply → verify → reboot → verify</code>. Review every blocker and the current plan hash before mutation.</p><pre><code>AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh

sudo /usr/bin/bash -p -- "$AEGIS_CORE" audit --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan  --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9</code></pre><p>Interactive apply requires typing <code>APPLY surface-pro9</code> (or <code>APPLY universal</code>). For automation after human review, pass the exact current plan digest with <code>--approve SHA256</code>. A changed plan invalidates the approval.</p>
</td>
<td valign="top">
<h2>İlk kullanım</h2>
<p><code>audit → plan → apply → verify → reboot → verify</code> sırasını kullanın. Mutasyon öncesinde tüm engelleri ve güncel plan hash’ini inceleyin.</p><pre><code>AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh

sudo /usr/bin/bash -p -- "$AEGIS_CORE" audit --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan  --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9</code></pre><p>Interactive apply için <code>APPLY surface-pro9</code> (veya <code>APPLY universal</code>) yazılır. İnsan incelemesinden sonra otomasyon gerekiyorsa güncel plan digest’i <code>--approve SHA256</code> ile verilir. Plan değişirse onay geçersiz olur.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Command reference</h2>
<ul><li><code>audit</code> — read-only host observations plus the current proposed plan. Exit 0 does <em>not</em> mean the host is secure.</li><li><code>plan</code> — shows current/target values, blockers, operations and plan SHA256; does not mutate.</li><li><code>apply</code> — locks state, rechecks the plan, journals the transaction, writes managed files atomically and applies live sysctls.</li><li><code>verify</code> — verifies this module’s live and persistent state; it is not a whole-system security audit.</li><li><code>history</code> — lists root-private transaction records.</li><li><code>rollback TX_ID</code> — conflict-aware rollback of the newest active transaction.</li><li><code>packages</code> — lists required/optional tools and confirms that the module itself installs/removes/updates none.</li><li><code>--profile universal|surface-pro9</code> — target profile.</li><li><code>--keep-coredumps</code> — do not create the coredump policy during plan/apply/verify; it is not an uninstall switch.</li><li><code>--files-only</code> — rollback after a reboot: restore persistent files only, then reboot again.</li><li><code>--version</code>, <code>--help</code> — metadata/help.</li></ul>
</td>
<td valign="top">
<h2>Komut referansı</h2>
<ul><li><code>audit</code> — salt okunur host gözlemleri ve mevcut öneri planı. Exit 0 sistemin güvenli olduğu anlamına gelmez.</li><li><code>plan</code> — mevcut/hedef değerleri, engelleri, işlemleri ve plan SHA256’sini gösterir; mutasyon yapmaz.</li><li><code>apply</code> — state kilidini alır, planı tekrar doğrular, transaction kaydı oluşturur, yönetilen dosyaları atomik yayımlar ve canlı sysctl’leri uygular.</li><li><code>verify</code> — yalnız bu modülün canlı ve kalıcı durumunu doğrular; tüm sistem güvenlik auditi değildir.</li><li><code>history</code> — root-private transaction kayıtlarını listeler.</li><li><code>rollback TX_ID</code> — en yeni aktif transaction’ı conflict-aware olarak geri alır.</li><li><code>packages</code> — gerekli/opsiyonel araçları gösterir; modülün kendisinin paket kurmadığını/silmediğini/güncellemediğini doğrular.</li><li><code>--profile universal|surface-pro9</code> — hedef profil.</li><li><code>--keep-coredumps</code> — plan/apply/verify sırasında coredump politikasını oluşturmaz; uninstall anahtarı değildir.</li><li><code>--files-only</code> — reboot sonrasındaki rollback için yalnız kalıcı dosyaları geri alır; ardından yeniden reboot gerekir.</li><li><code>--version</code>, <code>--help</code> — sürüm/yardım.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Daily operation</h2>
<p><strong>No daily apply is required.</strong> This is not a resident daemon. Once applied, systemd/sysctl persistence carries the policy across boots. Recommended maintenance is verification after reboot, kernel/systemd changes, or when another hardening tool may have touched the same settings.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history</code></pre><p>A second apply on an already compliant system should report <code>NO-OP</code> and create no new transaction record.</p>
</td>
<td valign="top">
<h2>Günlük kullanım</h2>
<p><strong>Her gün apply çalıştırmak gerekmez.</strong> Bu kalıcı çalışan bir daemon değildir. Uygulamadan sonra systemd/sysctl kalıcılığı politikayı reboot’lar arasında taşır. Reboot, kernel/systemd değişikliği veya başka bir hardening aracının aynı ayarlara dokunması sonrasında verify önerilir.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history</code></pre><p>Zaten uyumlu sistemde ikinci apply <code>NO-OP</code> vermeli ve yeni transaction kaydı oluşturmamalıdır.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Rollback / removal</h2>
<p>Do not “uninstall” by deleting the managed files first. Roll back the newest active transaction so the script can check conflicts and restore prior live values.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD...</code></pre><p>If the machine has rebooted since that transaction, live pre-boot sysctl values are intentionally not replayed. Use file-only rollback and reboot:</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD... --files-only
sudo systemctl reboot</code></pre><p>After a successful rollback you may remove the optional libexec copy. Keep the root-private recovery history unless you have independently archived and reviewed it; do not use <code>rm -rf</code> as a recovery shortcut.</p>
</td>
<td valign="top">
<h2>Rollback / kaldırma</h2>
<p>Yönetilen dosyaları önce silerek “uninstall” yapmayın. Betiğin çakışmaları kontrol edip eski canlı değerleri geri yükleyebilmesi için en yeni aktif transaction’ı rollback edin.</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD...</code></pre><p>Transaction’dan sonra reboot olduysa eski boot’un canlı sysctl değerleri bilinçli olarak yeniden oynatılmaz. Yalnız dosya rollback’i yapıp reboot edin:</p><pre><code>sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD... --files-only
sudo systemctl reboot</code></pre><p>Başarılı rollback’ten sonra isteğe bağlı libexec kopyasını silebilirsiniz. Root-private kurtarma geçmişini bağımsız olarak arşivleyip incelemeden silmeyin; kurtarma kısayolu olarak <code>rm -rf</code> kullanmayın.</p>
</td>
</tr>
<tr>
<td valign="top">
<h2>Troubleshooting</h2>
<ul><li><strong>Existing managed file differs:</strong> stop. The script intentionally refuses to overwrite a foreign or manually edited managed path.</li><li><strong>Legacy hardening file detected:</strong> inspect and retire/migrate the legacy layer first; do not delete blindly.</li><li><strong>SELinux/firewalld prerequisite fails:</strong> fix the host prerequisite separately; this module deliberately does not enable or reconfigure those services.</li><li><strong>Partial transaction:</strong> use <code>history</code> and the indicated <code>rollback</code>; do not start a second mutation until recovery is complete.</li><li><strong>verify returns 3:</strong> planned changes still remain; run <code>plan</code> and inspect what drifted.</li></ul>
</td>
<td valign="top">
<h2>Sorun giderme</h2>
<ul><li><strong>Mevcut yönetilen dosya farklı:</strong> durun. Betik yabancı veya elle değiştirilmiş yönetilen path’in üzerine yazmayı bilinçli olarak reddeder.</li><li><strong>Legacy hardening dosyası bulundu:</strong> eski katmanı önce inceleyin ve emekliye ayırın/migrate edin; körlemesine silmeyin.</li><li><strong>SELinux/firewalld önkoşulu geçmiyor:</strong> host önkoşulunu ayrı düzeltin; bu modül bu servisleri bilinçli olarak enable/reconfigure etmez.</li><li><strong>Yarım transaction:</strong> <code>history</code> ve belirtilen <code>rollback</code> akışını kullanın; recovery bitmeden ikinci mutasyon başlatmayın.</li><li><strong>verify 3 döndürüyor:</strong> hâlâ planlanan değişiklik vardır; <code>plan</code> çalıştırıp drift’i inceleyin.</li></ul>
</td>
</tr>
<tr>
<td valign="top">
<h2>Validation status</h2>
<p><strong>Project-host evidence:</strong> this exact <code>0.2.0-bash1</code> source was applied on the project Fedora 44 Surface Pro 9 host, reached all ten target sysctls, and passed post-reboot verification. This is host acceptance evidence, not a universal guarantee for other hardware or future Fedora releases.</p>
</td>
<td valign="top">
<h2>Doğrulama durumu</h2>
<p><strong>Proje host kanıtı:</strong> bu tam <code>0.2.0-bash1</code> kaynak kodu proje Fedora 44 Surface Pro 9 cihazında uygulandı, on sysctl hedefinin tamamına ulaştı ve reboot sonrası verify testini geçti. Bu, host kabul kanıtıdır; başka donanımlar veya gelecekteki Fedora sürümleri için evrensel garanti değildir.</p>
</td>
</tr>
</tbody>
</table>

---

**Security note / Güvenlik notu:** This project reduces selected attack surfaces; it is not a guarantee that a host is secure. Root execution should be limited to reviewed, checksum-verified source. / Bu proje seçili saldırı yüzeylerini azaltır; bir sistemin tamamen güvenli olduğunu garanti etmez. Root çalıştırma yalnız incelenmiş ve checksum doğrulaması yapılmış kaynakla sınırlandırılmalıdır.
