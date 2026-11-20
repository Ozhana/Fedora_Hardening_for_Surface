# Current official technical sources

Access date: **2026-11-20**.

Bu sürüm için üçüncü taraf blog/hardening listesi kullanılmamıştır. Tasarım current official documentation ve current upstream source ile karşılaştırılmıştır. Runtime ayrıca kurulu firewalld service tanımlarını exact semantics ile doğrular; yalnız dokümana güvenmez.

## firewalld

- Current firewalld.conf manual:
  - https://firewalld.org/documentation/man-pages/firewalld.conf.html
  - DefaultZone, IPv6_rpfilter, IndividualCalls, LogDenied, nftables backend, ReloadPolicy, StrictForwardPorts, NftablesFlowtable, NftablesCounters, NftablesTableOwner.
- Current zone options:
  - https://firewalld.org/documentation/zone/options.html
  - target belirtilmediğinde unmatched packet rejection; service/port/forward semantics.
- Current firewall-cmd manual:
  - https://firewalld.org/documentation/man-pages/firewall-cmd.html
- Current NetworkManager/firewalld zone binding:
  - https://firewalld.org/documentation/zone/connections-interfaces-and-sources
- Current upstream firewalld config:
  - https://github.com/firewalld/firewalld/blob/main/config/firewalld.conf
- Current upstream service definitions:
  - https://github.com/firewalld/firewalld/blob/main/config/services/dhcpv6-client.xml
  - https://github.com/firewalld/firewalld/blob/main/config/services/mdns.xml
  - https://github.com/firewalld/firewalld/blob/main/config/services/ipp-client.xml
  - https://github.com/firewalld/firewalld/blob/main/config/services/ws-discovery-client.xml

## NetworkManager

- Current NetworkManager.conf manual:
  - https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html
- Current connection setting semantics:
  - https://networkmanager.dev/docs/api/latest/nm-settings-nmcli.html
- Current nmcli manual / device reapply:
  - https://networkmanager.dev/docs/api/latest/nmcli

## Linux kernel

- Current IP sysctl documentation:
  - https://docs.kernel.org/networking/ip-sysctl.html

## systemd sysctl persistence

- Current `sysctl.d(5)` semantics (interface globs and hotplug re-application):
  - https://man7.org/linux/man-pages/man5/sysctl.d.5.html
- Current upstream systemd default sysctl policy demonstrates `net.ipv4.conf.*` globs:
  - https://github.com/systemd/systemd/blob/main/sysctl.d/50-default.conf

## Source freshness rule

Public release öncesinde aşağıdakiler yeniden kontrol edilmelidir:

1. Fedora 44 package versions,
2. installed firewalld service semantics,
3. firewalld.conf supported keys,
4. NetworkManager enum behavior,
5. kernel sysctl availability.

Script 2–4 numaralı maddeleri plan/apply sırasında runtime'da da doğrular veya eksiklikte durur.


### Fedora 44 / NetworkManager 1.56 compatibility note

Canlı Fedora 44 sistemi NetworkManager 1.56.1 kullanıyor. Bu nedenle ayrıca 1.56 sürümüne sabitlenmiş resmi referans kontrol edildi:

- https://networkmanager.dev/docs/api/1.56/nm-settings-nmcli.html
- https://networkmanager.dev/docs/api/1.56/nm-dbus-types.html

`connection.read-only` güncel nmcli setting alanı değildir. Güncel D-Bus connection setting dokümantasyonunda da `read-only` deprecated ve anlamı olmayan bir property olarak belirtilir. rc2 bu alanı sorgulamaz.

Kalıcı profil değişikliği için `nmcli connection modify` kullanılır; `--temporary` verilmediği için değişiklik kalıcı profile yazılır. Transaction sonrası `verify`, değerleri yeniden okuyarak kalıcılığı doğrular.

- https://networkmanager.dev/docs/api/latest/nmcli.html
- https://networkmanager.dev/docs/api/latest/settings-connection.html

## rc3 canlı uyumluluk düzeltmesi

- firewalld firewall-cmd current manual: https://firewalld.org/documentation/man-pages/firewall-cmd.html
  - `--get-target` permanent-only semantiği ve runtime/permanent ayrımı rc3 doğrulama tasarımında kullanılmıştır.

## rc4 canlı reboot-persistence düzeltmesi

Gerçek Fedora 44 reboot kabulünde rc3 firewall/NTS/profile kalıcılığını korudu ancak `lo` arayüzünün redirect/source-route raw sysctl değerleri geri döndü. rc4, systemd `sysctl.d` interface-glob semantiğini kullanır. `default` gelecekteki arayüzlerin başlangıç değerini sağlar; wildcard kuralları erken oluşmuş ve sonradan ortaya çıkan somut arayüzlere uygulanır.
