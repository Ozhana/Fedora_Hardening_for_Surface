# AEGIS Network Hardening

**الإصدار:** `0.7.0-rc4`  
**الحالة:** VERIFIED على جهاز المشروع Fedora 44 / Surface Pro 9  
**الترخيص:** [MIT](../LICENSE)  
**الدليل الثنائي English/Türkçe:** [README.md](README.md)

> هذه هي البنية الحالية. ملفات V7 القديمة وخدمة `aegis-firewall-lockdown.service` لا تُشغّل بالتوازي مع rc4.

## ما هذه الطبقة؟

AEGIS Network Hardening هي طبقة تقوية transactional لـFedora 44 تعتمد على firewalld مع nftables. تستبدل الانفتاح الواسع في منطقة Fedora Workstation بمنطقتين يملكهما AEGIS، وتربط اتصال Wi‑Fi/Ethernet الفعلي الذي تمت مراجعته بواسطة UUID.

### `aegis-public`

المنطقة الافتراضية/fallback المقيدة:

```text
services: dhcpv6-client
ports:    none
forward:  no
masquerade: no
```

### `aegis-lan`

تُربط فقط بالملف الفيزيائي الذي تمت مراجعته:

```text
services: dhcpv6-client ipp-client mdns ws-discovery-client
ports:    none
forward:  no
masquerade: no
```

لا توجد افتراضياً:

```text
ssh
samba-client / NetBIOS
1025-65535/tcp
1025-65535/udp
```

لا يمنع التصميم ICMP الأساسي بالكامل؛ هذه ليست بنية V7 القديمة التي كانت تحاول DROP شامل.

## عناصر الحماية الرئيسية

- يبقى `firewalld` هو مالك nftables؛ لا توجد قواعد direct/iptables قديمة ولا lockdown whitelist.
- يصبح `aegis-public` هو default zone.
- ملف الاتصال الذي تمت مراجعته يحصل على `connection.zone=aegis-lan`.
- LLMNR = off.
- mDNS = resolve-only على ملف LAN المراجع.
- `StrictForwardPorts=yes` يمنع قبول DNAT المنشور من container بشكل ضمني.
- تُدار redirect/source-route sysctls وloose RPF بشكل محدود دون امتلاك forwarding أو BBR أو MTU أو RA أو DNS أو VPN marks.
- rc4 يستخدم wildcard native من systemd-sysctl حتى تبقى قيم interface و`lo` بعد reboot ومن أجل interfaces التي تظهر لاحقاً.
- apply يستخدم snapshots خاصة بـroot وrollback guard مؤقتاً لمدة 180 ثانية. عند commit يتم إلغاء guard.

## الهدف والقيود

- Fedora 44 native وقابل للتعديل.
- firewalld + NetworkManager + nftables.
- apply يحتاج جلسة محلية قابلة للإسناد واتصال Wi‑Fi/Ethernet فعلي يمكن مراجعته.
- إذا كان هناك أكثر من اتصال فيزيائي active، استخدم `--connection-uuid UUID`.
- وجود ملفات legacy أو قواعد direct/policy غير متوقعة أو zones متعارضة يمكن أن يوقف apply.
- **إذا كان Docker active فإن apply يتوقف عمداً.** `StrictForwardPorts=yes` يغير semantics للـpublished ports، لذلك يجب دمج طبقة Docker isolation بشكل منفصل.
- لا توجد application-level outbound allowlist ولا ضمان لمنع VPN leaks.

## التثبيت والاختبارات

```bash
LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-network.sh version
/usr/bin/bash -p -- ./aegis-network.sh --help
sudo /usr/bin/bash -p -- ./tests/run.sh
```

ثم:

```bash
sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening
sudo install -o root -g root -m 0755 ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh
sudo restorecon -RFv /usr/local/libexec/aegis/network-hardening

/usr/bin/bash -p -- ./aegis-network.sh verify-install
AEGIS_NETWORK=/usr/local/libexec/aegis/network-hardening/aegis-network.sh
```

الإصدار المتوقع:

```text
0.7.0-rc4
```

## أول تشغيل

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" audit
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" plan
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" apply
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history
```

apply التفاعلي يتطلب:

```text
APPLY <PLAN_SHA256>
```

بعد مراجعة بشرية يمكن استخدام:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" apply --approve <PLAN_SHA256>
```

يعيد السكربت حساب الخطة قبل التغيير؛ إذا تغيّرت المدخلات تصبح الموافقة القديمة غير صالحة.

## مرجع الأوامر

- `version` — عرض الإصدار.
- `packages` — عرض توقعات الحزم؛ لا يثبت شيئاً.
- `verify-install` — مقارنة source الذي تمت مراجعته مع runtime المثبت والمملوك لـroot.
- `audit` — تقرير محلي للقراءة فقط عن الشبكة/firewall.
- `plan [--connection-uuid UUID]` — اختيار ومراجعة الملف الفيزيائي وإنتاج `PLAN_SHA256`.
- `apply [--connection-uuid UUID] [--approve HASH]` — تطبيق transactional مع rollback guard.
- `verify` — التحقق من الملفات المُدارة، firewalld/profile الحي، strict DNAT gate وsysctls.
- `status` — هوية الملف المُدار وحالة آخر transaction.
- `history` — سجل transactions.
- `rollback [TX_ID] [--approve HASH]` — rollback يدوي مع فحص التعارضات.
- `export` — حفظ تقرير audit باسم مستخدم سطح المكتب؛ يحتوي IP/routes/UUID ويجب مراجعته قبل النشر.

## الاستخدام اليومي

لا تشغّل apply يومياً. لا توجد خدمة أو timer دائم من AEGIS Network. firewalld وNetworkManager وsysctl.d يحملون السياسة عبر reboot.

بعد reboot أو تحديثات Fedora/firewalld/NetworkManager أو تغيّر كبير في profiles أو إضافة dock/interface جديد:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" verify
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" status
```

على جهاز مطابق يجب أن يكون apply التالي:

```text
NO-OP: files, runtime state and managed profile identity already match.
NO-OP: no snapshot, file replacement, firewall reload or profile rewrite.
```

## الطابعات والاكتشاف المحلي

تحتفظ منطقة LAN بـmDNS وIPP-client وWS-Discovery-client حتى لا تعيد مشكلة V7 التي كانت تكسر اكتشاف الطابعة المحلية. هذا سماح ضيق من جهة العميل، وليس فتح print server.

إذا فشل اكتشاف طابعة حقيقية، لا تفتح range واسع مثل 1025-65535. شغّل `audit` وحدد البروتوكول الفعلي أولاً.

## rollback

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" history
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback
# أو transaction محدد
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" rollback 'T-...'
```

يبني السكربت خطة rollback وبصمة موافقة، ويرفض الكتابة فوق تغييرات يدوية لاحقة. وجود conflict هو توقف أمان وليس سبباً لاستخدام force.

## استكشاف المشاكل

### Docker active

رفض apply متوقع. لا تضعف `StrictForwardPorts` لمجرد تمرير الاختبار؛ ادمج Docker isolation بشكل صريح.

### أكثر من رابط فيزيائي active

```bash
nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active
```

ثم:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NETWORK" plan --connection-uuid 'UUID'
```

### ملفات V7 القديمة موجودة

يجب إزالة/أرشفة البنية القديمة بعد المراجعة، خصوصاً:

```text
NETWORK_HARDENING/Aegis-Firewall-V7.sh
NETWORK_HARDENING/aegis-firewall-lockdown.service
/etc/firewalld/lockdown-whitelist.xml
/etc/firewalld/zones/aegis-secure.xml
```

لا تشغّل V7 وrc4 معاً.

### verify يفشل في sysctl بعد reboot

rc4 مصمم لحفظ per-interface sysctls عبر systemd native wildcard. افحص:

```bash
systemd-analyze cat-config sysctl.d
journalctl -b -u systemd-sysctl
```

وافحص المفتاح الذي أبلغ عنه verify بدلاً من إعادة apply بشكل أعمى.

### الطابعة لا تظهر

تحقق من CUPS وAvahi والبروتوكول الذي تستخدمه الطابعة. لا تعِد فتح ranges واسعة.

### rollback conflict

حافظ على التعديل اللاحق، افحصه وحدد من يملك الإعداد قبل أي تغيير جديد.

## حالة التحقق

تم التحقق من rc4 على جهاز المشروع Fedora 44 / Surface Pro 9 عبر:

- apply حقيقي وtransaction COMMITTED.
- verify مستقل.
- التأكد من أن `aegis-public` هو default وأن Wi‑Fi المراجع في `aegis-lan`.
- غياب SSH/Samba/NetBIOS وranges `1025-65535` من nftables الحي.
- نجاح DNS وIPv4/IPv6 routing.
- استمرار TIME-NTS الموثّق.
- نجاح verify بعد reboot.
- نجاح apply بعد reboot كـNO-OP حقيقي بدون snapshot/reload/rewrite.

اختبار الطباعة الفعلية كان **NOT TESTABLE** لأن جهاز الاختبار لم يكن يحتوي CUPS destination مُعداً. لا يتم تسجيله كـPASS.

الإصدارات rc1 وrc2 وrc3 تاريخ تطوير فقط ولا يجب نشرها كـruntime الحالي.
