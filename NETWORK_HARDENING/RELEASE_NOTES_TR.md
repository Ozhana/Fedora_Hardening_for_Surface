# 0.7.0-rc4 — reboot sysctl persistence düzeltmesi

rc3 gerçek Fedora 44 reboot testinde firewall, NetworkManager profil bağlama ve NTS kalıcılığını korudu; ancak loopback (`lo`) üzerindeki beş redirect/source-route sysctl değeri reboot sonrası kernel varsayılanına döndü. rc3 bu değerleri apply sırasında mevcut arayüzlere canlı yazıyor, kalıcı dosyada ise yalnız `all/default` değerlerini tutuyordu.

rc4:

- `sysctl.d` dosyasına systemd-native interface wildcard direktifleri ekler;
- IPv4 `accept_redirects`, `secure_redirects`, `send_redirects`, `accept_source_route` değerlerini tüm somut arayüzlerde kalıcılaştırır;
- IPv6 `accept_redirects` ve `accept_source_route` değerlerini tüm somut arayüzlerde kalıcılaştırır;
- systemd-sysctl ağ-interface globs mekanizmasına dayanır; ek daemon/timer eklemez;
- apply sırasında exact/global değerleri ve mevcut arayüzleri açıkça uygular; procps `sysctl --load` sistemd glob dosyasının parser'ı olarak kullanılmaz;
- verify/no-op exact-key kontrolünde wildcard direktifleri anahtar sanmaz; mevcut her interface ayrı doğrulanır.

rc3 final değildir. rc4 gerçek Fedora 44 reboot kabul testinden geçmeden final ilan edilmemelidir.

# AEGIS Network Hardening 0.7.0-rc4

## rc2 canlı Fedora 44 testinden öğrenilenler

rc2 gerçek Fedora 44 / firewalld 2.4.4 üzerinde policy dosyalarını yayımlayıp NetworkManager profiline başarıyla reapply yaptı; ancak verify aşamasında `firewall-cmd --zone=... --get-target` çağrısı kullanıldı. Güncel `firewall-cmd` semantiğinde `--get-target` yalnız `--permanent` ile desteklenir. Bu nedenle rc2 verify yanlış negatif üretti ve fail-safe rollback tetiklendi.

rc3 düzeltmeleri:

- zone target permanent kontrolü `firewall-cmd --permanent --zone=... --get-target` ile yapılır;
- runtime target ayrıca `firewall-cmd --zone=... --list-all` içinden fail-closed olarak doğrulanır;
- verify sırasında profile identity artık commit öncesi kalıcı state'e yazılmaz;
- managed identity dosyaları transaction snapshot/rollback kapsamına alındı;
- `save_managed_identity` yalnız bütün runtime/persistent verify kapıları geçtikten sonra çalışır;
- test mock'u gerçek `--get-target` CLI kısıtını modeller;
- commit ordering ve managed-state rollback için regresyon testleri eklendi.

rc2 public/final release olarak kullanılmamalıdır.

- Rolled-back bir rc2 işleminin bıraktığı stale managed identity artık committed state olarak güvenilmez; no-op/verify yalnız COMMITTED transaction kimliğini kabul eder.
