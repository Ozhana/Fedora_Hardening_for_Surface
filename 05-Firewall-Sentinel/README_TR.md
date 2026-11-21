# 05 — AEGIS Firewall Sentinel | Türkçe kılavuz

**Sürüm:** `0.9.0-alpha2-review5` (STRICT)  
**Hedef:** Fedora 44 Workstation, systemd + firewalld + nftables  
**Ön koşul:** [04 — AEGIS Network Hardening](../04-Network-Hardening) sürüm `0.7.0-rc4`  
**Ayrıntılı, komut-komut yan yana İngilizce–Türkçe ana kılavuz:** [README.md](README.md) · **Bağımsız Arapça:** [README_AR.md](README_AR.md)

**Ayrıntılar:** [Kurulum](docs/INSTALL_TR.md) · [Günlük kullanım](docs/OPERATIONS.md) · [Güvenlik ve geri alma](docs/SECURITY_AND_RECOVERY.md)

> **Durum: Gerçek Fedora üzerinde kurulumu doğrulanmış ALPHA.** 21 Kasım 2026'da gerçek fiziksel TTY'de `COMMITTED`, ardından ayrıca `VERIFIED` alındı; grafik masaüstünden `monitor-now` sonucu `INFO` idi. **21 Kasım 2026 tarihinde reboot sonrası doğrulama da başarılı oldu. Gerçek yazıcıya baskı, strict DoT, VPN kill-switch, karantina ve acil müdahale komutları hâlâ saha testinden geçmedi.**

## Sentinel ne yapar?

AEGIS Network Hardening'in firewalld bölgelerini ve NetworkManager bağlantı sahipliğini **değiştirmeden**, kendi `inet aegis_sentinel` nftables tablosunda çıkış trafiğine ek kısıtlamalar uygular. LLMNR (5355), NAT-PMP/PCP (5351) çıkışını engeller; mDNS/SSDP/WS-Discovery çıkışını güvenilen fiziksel bağlantıyla sınırlar. SMB/RPC/NetBIOS çıkışı, açıkça izin verilmedikçe engellenir. Değişiklikler SHA-256 plan onayı, transaction, geri alma ve bütünlük izleme ile korunur.

**Varsayılan güvenlik durumu:** Quarantine `OFF`, VPN kill-switch `OFF`, strict DoT `OFF`, doğrudan DNS 53 çıkışı `PASSTHROUGH`. Dolayısıyla **DNS şifrelenmiş kabul edilmez.** Aynı bilgisayarda CUPS ve Avahi çalışmaya devam edebilir; henüz yazıcı eklenmemesi temiz kurulumda arıza sayılmaz.

## Kurulum özeti

Yerel grafik terminalde:

```bash
git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum -c SHA256SUMS
bash ./install-preflight.sh
```

Önce temel `04-Network-Hardening` katmanının **gerçek makinede uygulanmış ve doğrulanmış** olması şart. Preflight `PREFLIGHT_OK` vermeden devam edilmez. Preflight çalışan Python dosyasını atomik olarak günceller ama **güvenlik duvarını uygulamaz**.

Ardından fiziksel `Ctrl+Alt+F3` konsolunda normal kullanıcıyla oturum aç. Grafik terminaldeki `/dev/pts/0` gerçek TTY değildir. Siyah konsolda:

```bash
tty
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat
# Beklenen: /dev/tty3; Class=user; Type=tty; Active=yes; Remote=no; Seat=seat0
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py apply
```

Güncel planı denetle; yalnızca doğruysa programın istediği `APPLY <PLAN_SHA256>` onayını tam olarak ver. Başkasının SHA-256 değerini kopyalama. **`COMMITTED:` gelmeden `verify` sonuçlarını kurulum başarısı sayma.** `COMMITTED:` gelirse aynı TTY'de:

```bash
sudo /usr/bin/python3 -I /usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py verify
```

`VERIFIED:` ve çıkış kodu `0` beklenir. `STOP`, `FAILED`, `CRITICAL` olursa işlemi tekrar tekrar başlatma; önce [günlükleri ve rollback durumunu](docs/SECURITY_AND_RECOVERY.md) incele.

## Günlük kontrol (grafik terminalde yapılabilir)

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" status
sudo /usr/bin/python3 -I "$AEGIS" verify
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
sudo /usr/bin/python3 -I "$AEGIS" history
```

Systemd `aegis-firewall-sentinel.service` için `active (exited)` tek başına hata değildir; politika yükleyici birim çalışması bittikten sonra aktif kalabilir. `aegis-firewall-sentinel-monitor.timer` ve `.path` için `active (waiting)` beklenir. Ayrıca `NetworkManager`, `firewalld`, `cups` ve `avahi-daemon` servislerini koru.

**Notlar:** `monitor-now` üzerindeki 5353 Avahi / 5355 resolved wildcard socket `INFO` mesajları tek başına dış ağ erişimi veya güvenlik açığı kanıtı değildir. İhtiyaç duymadan `network-gate`, `runtime-load`, `trust-sync`, `panic-off` gibi servis/iç kullanım komutlarını elle çalıştırma. Diğer müdahale komutları için [işletim rehberi](docs/OPERATIONS.md) gerekir.

[Yan yana EN–TR tam kılavuz](README.md) · [Arapça tam kılavuz](README_AR.md) · [Tam kurulum](docs/INSTALL_TR.md) · [Kanıtlar ve bilinen sınırlamalar](docs/FIELD_ACCEPTANCE.md)
