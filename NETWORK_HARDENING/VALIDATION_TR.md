# Doğrulama Özeti — 0.7.0-rc4

## Geçen kapılar

- Bash sözdizimi
- 10 statik güvenlik/regresyon testi
- Zone/config üreticileri ve idempotent firewalld.conf üretimi
- Güncel firewalld service semantiklerinin exact doğrulanması
- Service tanımı tamper edildiğinde fail-closed davranış
- Yerel Wayland/X11/TTY recovery-session kapısı; remote-only reddi
- Vendor symlink hedefi değişmişken güvenli rollback
- Mock Fedora `apply → verify → commit`
- İkinci apply gerçek NO-OP
- Commit sonrası systemd guard'ın rollback yapmaması
- Runtime port drift tespiti
- Commit sonrası yabancı drift'te rollback conflict
- firewalld inactive iken offline doğrulama + service start recovery
- Dosya, NetworkManager profili ve canlı sysctl tam manuel rollback

## Henüz geçmeyen kapılar

- Gerçek Wi-Fi reconnect ve sleep/wake
- Gerçek ağ yazıcısı keşfi ve test sayfası
- Reboot sonrası verify

Bu nedenle sürüm **PARTIALLY VERIFIED / RELEASE CANDIDATE** statüsündedir; GitHub final release değildir.

- NetworkManager 1.56 deprecated `connection.read-only` regression: FIXED; explicit fail-closed property reads tested.

## rc3 ek regresyon kapıları

- `--get-target` yalnız permanent modda çağrılır.
- Runtime zone target `--list-all` üzerinden ayrı doğrulanır.
- Managed identity yalnız verify sonrası publish edilir.
- İlk apply rollback'inde managed identity dosyaları absent durumuna geri döner.
- Önceki managed state varsa rollback snapshot'tan geri getirir.


## rc4 reboot-persistence regression

- Generated sysctl policy contains six systemd interface wildcard directives: PASS.
- Runtime exact-key verification skips wildcard directives and verifies concrete interfaces separately: PASS.
- Apply path no longer treats the systemd glob file as a procps `sysctl --load` file: PASS.
- Real Surface Pro 9/Fedora 44 reboot verification: PENDING.


## Canlı Fedora 44 kanıtı — rc3 tabanı

Aynı hardening mimarisinin rc3 sürümü gerçek Surface Pro 9/Fedora 44 üzerinde şu kapıları geçti: install hash match, canlı apply, COMMITTED transaction, independent verify, `aegis-public/aegis-lan`, geniş 1025-65535/SSH/Samba izinlerinin runtime nftables'tan kalkması, DNS/IPv4/IPv6/NTS uyumluluğu ve ikinci apply NO-OP. Reboot sonrası yalnız per-interface `lo` sysctl kalıcılığı başarısız oldu. rc4 değişikliği bu tek kalıcılık kusurunu hedefler.

rc4'ün gerçek Surface Pro 9/Fedora 44 reboot verify kapısı hâlâ PENDING; bu nedenle final release değildir.
