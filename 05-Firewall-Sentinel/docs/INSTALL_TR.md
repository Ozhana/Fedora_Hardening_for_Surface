# Fedora 44 kurulum, yükseltme ve kabul süreci (TR)

## 0. Ön koşullar

- Fedora 44, mutable Workstation; **doğrudan fiziksel konsola erişim** (klavye/TTY), root parolası değil `sudo` yetkili normal kullanıcı.
- `04-Network-Hardening` sürüm `0.7.0-rc4` kurulu ve doğrulanmış; Sentinel bunun firewalld bölgelerini devralmaz.
- firewalld, nftables, NetworkManager, systemd, SELinux araçları ve `sudo` kullanılabilir. Uzak SSH bağlantısı **kurulum için uygun değildir**.
- Güncel ağ erişimini, önemli VPN/yazıcı ihtiyaçlarını ve planlı bir bakım penceresini kontrol edin.
- Daha önce yarım kalmış `apply` varsa transaction `status` ve `rollback.reason`, `policy.json`, nftables tabloları ve `NetworkManager` durumunu inceleyin. Durumu belirsiz makineye yeniden `apply` çalıştırmayın.

## 1. Kaynağı al ve offline doğrula

```bash
git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum -c SHA256SUMS
bash scripts/test-offline.sh
```

Kaynağı farklı yerde açtıysanız aynı bileşen dizininde çalışabilirsiniz. Kaynakta `sha256sum` eşleşmezse kodu çalıştırmayın. `tests/test_static.py` ile 9+7 offline regresyon testi kontrol edilir.

## 2. Ön kurulum: GUI terminali

```bash
bash ./install-preflight.sh
```

Sırasıyla SHA-256, Python testleri, `sudo`, gerçek `nft --check` (uygulamadan sözdizimi kontrolü), root-owned runtime dosyasının atomik değiştirilmesi, kurulu dosyanın hash'i, `validate` ve `plan` çalışır. **Preflight sistemi hiç değiştirmez demek yanlış olur:** root-owned Python dosyası yenilenir; ancak firewall politikası uygulanmaz. Sonunda `PREFLIGHT_OK` şarttır.

`Unstable unit activity state: failed` görülürse önceki transaction geri alınmış mı, politika kalmış mı, nft tablosu silinmiş mi ve NetworkManager çalışıyor mu kontrol edilmeden `systemctl reset-failed` uygulamayın.

## 3. Uygulama: gerçek fiziksel TTY

- `Ctrl+Alt+F3` → `fedora login:` → normal kullanıcı hesabıyla giriş. Surface cihazlarda Fn/F tuşu davranışı değişebilir.
- Aynı TTY'de `tty`: `/dev/tty3` vb. (grafik terminaldeki `/dev/pts/0` **uygun değildir**).
- `loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat` → `Class=user`, `Type=tty`, `Active=yes`, `Remote=no`, `Seat=seat0`.
- `sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py apply`.
- Gösterilen **güncel** `PLAN_SHA256`, bağlantı, LAN ve DNS seçeneklerini karşılaştırın. Programın istediği tam `APPLY <SHA256>` dizgisini girin.
- `COMMITTED:` olmadan `verify` komutunu kurulum doğrulaması olarak yorumlamayın.

## 4. Başarılı uygulamayı doğrula

Hâlâ fiziksel TTY'de:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py verify
```

`VERIFIED:` ve 0 çıkış kodu hedeflenir. Sonra masaüstüne dönüp:

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
systemctl show aegis-firewall-sentinel.service -p LoadState -p ActiveState -p SubState -p Result
systemctl is-active NetworkManager firewalld cups avahi-daemon
systemctl show aegis-firewall-sentinel-monitor.timer aegis-firewall-sentinel-monitor.path -p ActiveState -p SubState
resolvectl status
resolvectl query example.org
lpstat -p -d || true
```

CUPS'ta `No destinations added` temiz kurulumda yazıcı tanımlanmadığını gösterebilir; fiziki yazdırma testi yerine geçmez. DNS çözümlemesi başarılı olsa bile DoT etkin olmayabilir.

## 5. Yükseltme

Yeni kaynak paketinin checksumlarını doğrulayın ve **yalnızca onaylı yeni sürümü** kullanın. `install-preflight.sh` root-owned Python dosyasını yeniler; kurulu policy/manifest sürümüyle uyumu sağlamak için önce `verify`, `plan`, sonra fiziksel TTY'de kontrollü `apply` ve `verify` gerekir. Çalışan sistemi yeniden yapılandırmadan önce kurtarma olanağını koruyun.

## 6. Reboot kabul testi

**21 Kasım 2026 itibarıyla henüz uygulanmadı.** Yeniden başlatma, NetworkManager başlangıç gate kontrolü nedeniyle bağlantı kaybı riski taşır. Fiziksel konsol erişimini doğrulayıp işleri kaydederek, bakım penceresinde reboot edin. Açılışta `verify`, `monitor-now`, `systemctl --failed`, `NetworkManager`, DNS ve yazıcı testlerini tekrarlayın. Başarılı sonuç olmadan kalıcılığı doğrulandı demeyin.
