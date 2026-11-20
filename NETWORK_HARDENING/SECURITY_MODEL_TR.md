# Güvenlik Modeli ve Mimari Gerekçe

## Korunan varlıklar

- Fedora 44 ağ politikası bütünlüğü,
- aktif Wi-Fi/Ethernet bağlantısının kullanılabilirliği,
- yazıcı keşfi ve IPP istemci işlevi,
- TIME-NTS çıkış trafiği,
- gelecekteki Docker published-port sınırı,
- SSD/log yazma bütçesi,
- rollback kanıtları ve transaction geçmişi.

## Güven sınırları

- Kullanıcı-yazılabilir indirme/Masaüstü alanı → root runtime kurulumu,
- NetworkManager profil verisi → firewalld zone bağlama,
- `/etc/firewalld` → kernel nftables runtime,
- `/etc/sysctl.d` → canlı kernel ağı,
- kesinti/SIGTERM/power-loss → durable transaction recovery,
- package update/vendor config → AEGIS yerel override ve verify.

## Eski V7.2'den korunan fikirler

- özel AEGIS zone,
- native firewalld kullanımı,
- işlem öncesi yedek,
- hata durumunda geri alma,
- Docker ile birlikte düşünme.

## Eski V7.2'den çıkarılan riskler

### HIGH — Geniş lockdown whitelist

`root`, `python3*`, `iptables*`, `nft*` gibi geniş komut desenleri gerçek least-privilege sınırı değildir. Yetkili süreçlerin kapsamını aşırı büyütür. Yeni sürüm firewalld lockdown whitelist kullanmaz; root-owned reviewed runtime, exact action listesi, nftables table ownership ve transaction kontrolü kullanır.

### HIGH — Docker'ı boot bağımlılığı yapmak

Firewall hardening'in `Wants=docker.service` ile Docker'ı başlatması gereksiz attack surface ve termal/bellek yüküdür. Yeni sürüm Docker'ı başlatmaz; Docker aktifse apply'ı reddeder. `StrictForwardPorts=yes` gelecekteki published portların açık izin olmadan geçmesini engeller.

### MEDIUM — `LogDenied=all`

Denial/log flood altında journald ve SSD yazmasını büyütebilir. Yeni politika `LogDenied=off` kullanır. Gerekli olay gözlemi daha sonra rate-limited ve olay odaklı tasarlanmalıdır.

### MEDIUM — ICMP blackout

Echo/timestamp/redirect bloklarını genel zero-trust reçetesi gibi kullanmak PMTU, IPv6 ve tanılama davranışını bozabilir. Yeni zone target belirtilmemiş native firewalld semantiğini kullanır: unmatched uygulama trafiği reddedilir; ICMP korunur.

### MEDIUM — `DROP` ile görünmezlik varsayımı

Endpoint'te `DROP`, izin verilmeyen TCP/UDP için uzun zaman aşımı üretir; güvenlik kapsamını tek başına genişletmez. Native reject davranışı daha hızlı hata, daha iyi tanı ve daha düşük gereksiz bekleme sağlar.

### HIGH — Yalnız trap rollback

SIGKILL, kernel kilitlenmesi veya süreç çökmesi shell trap'ini çalıştırmayabilir. Yeni sürüm hem yerel cleanup rollback hem bağımsız transient systemd rollback timer kullanır.

### MEDIUM — Stale backup ve foreign overwrite

Sabit `.aegis_bak` dosyaları eski durumu yanlışlıkla geri getirebilir. Yeni sürüm benzersiz transaction ID, before/after hash, post-commit conflict kontrolü ve atomik publish kullanır.

## Performans yaklaşımı

- `IndividualCalls=no`: toplu restore yolu.
- `NftablesCounters=no`: sürekli sayaç maliyeti yok.
- `LogDenied=off`: packet-flood log yazması yok.
- `NftablesFlowtable=off`: laptop router değildir; gereksiz forwarding fastpath/karmaşıklık yok.
- normal firewalld reload: daemon restart ve gereksiz service churn yok.
- ikinci apply NO-OP: yeniden yazma/reload yok.
- persistent AEGIS daemon/timer yok; yalnız apply sırasında transient rollback timer vardır.

## Layer sahipliği

Bu modül sahiplenir:

- firewalld temel yerel config,
- `aegis-public` ve `aegis-lan`,
- seçilmiş profil zone/LLMNR/mDNS,
- redirect/source-route ve sınırlı loose RPF değerleri.

Bu modül sahiplenmez:

- BBR ve qdisc,
- MTU probing,
- IPv4/IPv6 forwarding,
- Docker bridge/DOCKER-USER/native container rules,
- DNSSEC/DoT/DoH,
- VPN fwmark/src_valid_mark,
- uygulama bazlı egress allowlist,
- CUPS/Avahi daemon yapılandırması.

Bu ayrım diğer AEGIS katmanlarıyla savaşmayı önler.

## Kurtarma dayanıklılığı

- Shell cleanup, yakalanabilir hata ve sinyallerde aynı transaction snapshot'ını kullanır.
- Ayrı transient systemd guard, apply süreci ölür veya kilitlenirse owner PID'yi sonlandırıp aynı snapshot'ı geri yüklemeyi dener.
- Rollback, firewalld çalışmıyorken disk yapılandırmasını offline doğrular ve servisi başlatmayı dener.
- Commit sonrası yabancı dosya/profil drift'i varsa manuel rollback ezme yapmaz; conflict ile durur.
- Eski vendor symlink hedefi transaction sonrasında değişmişse kör symlink diriltmek yerine snapshot içeriğini güvenli regular file olarak geri getirir.

## Residual riskler

- Bir root saldırganı dosyaları ve runtime'ı değiştirebilir.
- firewalld/nftables/kernel zafiyetleri bu scriptin sınırı dışındadır.
- Yerel LAN güvenilirliği UUID ile kimlik doğrulanmış olmaz; UUID yalnız profil tanımlayıcıdır.
- Yazıcı protokolleri yerel ağ attack surface'i oluşturur; yalnız seçilmiş LAN profile açılmıştır.
- Apply sonrası yazıcı testi teknik verify'ın yerine geçmez; ikisi birlikte kabul kriteridir.
- Ani güç kesintisi snapshot sonrası/publish sırasında olsa dahi sonraki apply unfinished transaction nedeniyle durur; operatör incelemesi gerekebilir.
