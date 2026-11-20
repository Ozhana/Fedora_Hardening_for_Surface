# Eski V7.2 Tasarımından 0.7.0-rc4'e Geçiş

Bu dosya, ilk `aegis-firewall-secure.sh` ve `aegis-firewall-lockdown.service` fikirlerinin yeni tek-betik mimaride nasıl ele alındığını açıklar.

| Eski yaklaşım | Karar | Yeni karşılık |
|---|---|---|
| Tek `aegis-secure` zone | Geliştirildi | Güvenilmeyen/yeni ağlar için `aegis-public`, incelenen yazıcı LAN profili için `aegis-lan` |
| `target=DROP` | Kaldırıldı | Native firewalld default target: unmatched uygulama trafiği hızlı REJECT, ICMP korunur |
| Echo/timestamp/redirect ICMP block | Kaldırıldı | PMTU, IPv6 ve tanılama bütünlüğü korunur; host redirect kabulü sysctl düzeyinde kapatılır |
| `LogDenied=all` | Kaldırıldı | `LogDenied=off`; SSD/log-flood maliyeti yok |
| Lockdown whitelist: root, `python3*`, `iptables*`, `nft*` | Kaldırıldı | Root-owned reviewed runtime, exact action allowlist, nftables table ownership, plan hash ve transaction kontrolü |
| Docker'ı `Wants=` ile başlatma | Kaldırıldı | Docker aktifse apply reddi; `StrictForwardPorts=yes`; sonraki Docker katmanı explicit izinleri yönetir |
| Persistent boot oneshot | Kaldırıldı | Kalıcı native config; yalnız apply sırasında transient rollback guard |
| Sabit `.aegis_bak` dosyaları | Kaldırıldı | Benzersiz transaction ID, durable before/after hash, conflict-aware rollback |
| Trap-only rollback | Geliştirildi | Yerel cleanup + bağımsız systemd timer + inactive-firewalld recovery |
| Yalnız zone doğrulaması | Geliştirildi | Disk hash, native config check, runtime/permanent zone, UUID binding, DNAT gate, sysctl ve route doğrulaması |
| İzin verilmiş tüm yüksek portlar | Kaldırıldı | Yalnız DHCPv6-client, mDNS, IPP-client ve WS-Discovery-client |

## Neden persistent service yok?

Zone XML, firewalld.conf, NetworkManager profile binding ve sysctl dosyaları zaten kalıcıdır. Her boot'ta root mutator çalıştırmak hız veya güvenlik kazandırmaz; tersine attack surface ve boot-order karmaşıklığı üretir. Bu yüzden runtime tek betiktir ve yalnız operatör tarafından çağrılır.
