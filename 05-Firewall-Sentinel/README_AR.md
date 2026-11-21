# 05 — AEGIS Firewall Sentinel | الدليل العربي الكامل

**الإصدار:** `0.9.0-alpha2-review5` (STRICT) · **النظام:** Fedora 44 Workstation  
**دليل الإنجليزية والتركية جنباً إلى جنب:** [README.md](README.md) · **الطبقة الأساسية المطلوبة:** [04-Network-Hardening](../04-Network-Hardening) · [الرخصة MIT](../LICENSE)

> **الحالة: إصدار Alpha جرى التحقق منه عملياً على جهاز واحد، وليس شهادة جاهزية إنتاجية.** بعد إعادة تشغيل Fedora في 21 نوفمبر 2026 نجحت أوامر `verify` و`monitor-now`، وكانت الخدمات الخمس المطلوبة نشطة، وظهر جدولا nftables (`firewalld` و`aegis_sentinel`)، ونجح DNS، ولم تظهر وحدات systemd فاشلة. **لم تُختبر الطباعة الفعلية ولا DoT الصارم ولا VPN kill-switch ولا الحجر الطارئ أو العزل حسب cgroup.**

## 1. الفكرة المعمارية وحدود الثقة

- تمتلك الطبقة `04-Network-Hardening` مناطق firewalld (`aegis-public` و`aegis-lan`)، وربط اتصال NetworkManager المُراجع وإعدادات sysctl. تمتلك Sentinel فقط جدولها المستقل `inet aegis_sentinel` وملفاتها ووحداتها وبعض الجداول المؤقتة في الذاكرة؛ لا تنفذ `nft flush ruleset`.
- يُحظر خروج LLMNR (المنفذ 5355) وNAT-PMP/PCP (5351)، وتُقيَّد بعض بروتوكولات الاكتشاف خارج الاتصال الموثوق، ويُحظر SMB/RPC/NetBIOS افتراضياً إلا عند الموافقة الصريحة.
- **خروج DNS عبر المنفذ 53 في وضع PASSTHROUGH، وDoT غير مُفعّل، وVPN kill-switch والحجر في وضع OFF.** نجاح تحليل اسم DNS لا يعني أنه مُشفّر.
- أوامر التغيير تحتاج إلى `sudo` من جلسة تسجيل دخول محلية **TTY فعلية ونشطة** مرتبطة بمعرّف التدقيق kernel audit. نافذة الطرفية الرسومية `/dev/pts/*` قد تُرفض ولو كان المستخدم نفسه مسجلاً على سطح المكتب؛ لا تتجاوز هذا الفحص.
- استمرت CUPS وAvahi بالعمل في الاختبارات، لكن لم تكن هناك طابعة مضافة إلى النظام الجديد، لذلك لا توجد نتيجة عن طباعة صفحة حقيقية.

## 2. تثبيت متدرج مع علامة نجاح لكل خطوة

### الخطوة 1 — التحقق من الطبقة الأساسية

يجب أن تكون `04-Network-Hardening` بالإصدار `0.7.0-rc4` مثبّتة ومتحققاً منها. على Fedora 44، افتح طرفية المستخدم العادي:

```bash
systemctl is-active NetworkManager firewalld
```

**المخرجات المتوقعة:** `active` لكل خدمة. هذه الخطوة لا تُثبت الطبقة الأساسية وحدها؛ راجع دليلها ونتيجة `verify` الخاصة بها.

### الخطوة 2 — تنزيل المصدر والتحقق منه

```bash
git clone https://github.com/Ozhana/Fedora_Hardening_for_Surface.git
cd Fedora_Hardening_for_Surface/05-Firewall-Sentinel
sha256sum -c SHA256SUMS
```

**المخرجات المتوقعة:** أسطر `OK` لكل ملف مذكور، ومنها `README.md` و`README_AR.md` و`aegis-firewall-sentinel.py`. ظهور `FAILED` يعني التوقف. بصمات SHA-256 المحلية تتحقق من مطابقة المصدر للـmanifest، **وليست توقيعاً رقمياً مستقلاً من جهة موثوقة**.

### الخطوة 3 — الاختبارات غير المُغيّرة للجدار

```bash
bash ./scripts/test-offline.sh
```

**المخرجات المتوقعة:** `REVIEW5_STATIC_SECURITY_TESTS_PASS` ونتائج 9 و7 اختبارات ناجحة، ثم `OFFLINE_TESTS_PASS`. هذه الاختبارات لا تثبت جميع السيناريوهات الواقعية.

### الخطوة 4 — فحص ما قبل التثبيت

```bash
bash ./install-preflight.sh
```

**المخرجات المتوقعة:** ظهور مرحلة `[4/8] NATIVE NFT PARSER CHECK — NO FIREWALL MUTATION` ثم `PREFLIGHT_OK: runtime updated; Sentinel firewall policy NOT applied.`  
**تأثير هذه الخطوة:** تُحدَّث نسخة Python المحمية والمملوكة للمستخدم root بطريقة ذرّية؛ **لا تُفعَّل قواعد الجدار بعد**. يستخدم اختبار parser واجهة اصطناعية اسمها `eth0`، ولا يربط جهازاً حقيقياً.

### الخطوة 5 — تسجيل دخول TTY محلي جديد

اضغط `Ctrl+Alt+F3` في الجهاز الفعلي، وسجّل الدخول باسم المستخدم العادي؛ لا تستخدم `sudo -i` أو SSH بديلاً عن ذلك. على الشاشة النصية السوداء:

```bash
tty
loginctl show-session self -p Class -p Type -p Active -p Remote -p Seat
```

**المخرجات المتوقعة (مثال):**

```text
/dev/tty3
Class=user
Type=tty
Active=yes
Remote=no
Seat=seat0
```

### الخطوة 6 — مراجعة السياسة وتنفيذها في نفس TTY

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" plan
sudo /usr/bin/python3 -I "$AEGIS" apply
```

**المخرجات المتوقعة:** خطة فيها `PLAN_SHA256=<CURRENT_HEX>`، ثم سؤال `Type exactly "APPLY <CURRENT_HEX>" to continue:`. اكتب البصمة المعروضة **في تشغيلك الحالي** فقط. النجاح يُعلن بواسطة `COMMITTED: T-<TIMESTAMP>-<HEX>`. إذا ظهر `STOP` أو `FAILED` فلا تكرر `apply` عشوائياً.

### الخطوة 7 — التحقق المستقل

```bash
sudo /usr/bin/python3 -I "$AEGIS" verify
```

**المخرجات المتوقعة:**

```text
=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.
```

### الخطوة 8 — التحقق بعد إعادة التشغيل

بعد حفظ الأعمال وتجهيز وصول TTY للاسترداد، نفّذ إعادة تشغيل مراقبة. هذه الخطوة **نجحت بالفعل مرة واحدة** على جهاز الاختبار بتاريخ 21-11-2026، لكنها لا تعني ضمان التوافق مع كل الأجهزة.

```bash
sudo systemctl reboot
# After login, re-declare in your new shell:
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
sudo /usr/bin/python3 -I "$AEGIS" verify
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
sudo nft list tables
systemctl --failed --no-pager
```

**المخرجات الموثقة:** `VERIFIED`، و`monitor: INFO`، ووجود الجدولين `inet firewalld` و`inet aegis_sentinel`، و`0 loaded units listed.` إذا أُغلقت الجلسة عند إعادة التشغيل فأعد تعريف متغير `AEGIS` قبل استخدامه.

## 3. المرجع الكامل لأوامر Sentinel

**تعريف المتغير قبل النسخ:**

```bash
AEGIS=/usr/local/libexec/aegis/firewall-sentinel/aegis-firewall-sentinel.py
```

القيم المكتوبة مثل `<TX_ID>` و`<PATH>` **أماكن مخصصة** يجب استبدالها، وهي ليست قيماً حقيقية من جهاز الاختبار. الأوامر ذات الخطورة العالية **معروضة للتوثيق، وليست توصية بتجربتها على جهاز الإنتاج**.


### `version` — الإصدار

**الوظيفة:** يعرض معرّف الإصدار المضمّن؛ لا يحتاج إلى صلاحيات الجذر.

**كيفية الاستخدام:**

```bash
/usr/bin/python3 -I "$AEGIS" version
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
0.9.0-alpha2-review5
```

**مستوى الخطورة:** منخفض.


### `packages` — المتطلبات

**الوظيفة:** يسرد إصدارات الحزم والأدوات المطلوبة، **دون تثبيت أو حذف أو تحديث أي حزمة.**

**كيفية الاستخدام:**

```bash
/usr/bin/python3 -I "$AEGIS" packages
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
No package is installed, removed, or updated by this script.
firewalld=<VERSION>
nftables=<VERSION>
NetworkManager=<VERSION>
systemd=<VERSION>
nft=PRESENT
```

**مستوى الخطورة:** منخفض.


### `verify-install` — التحقق من ملف التثبيت

**الوظيفة:** يفحص ملكية الجذر وإصدار الملف وبصمته SHA-256؛ ويقارن نسخة المصدر عند استعمال `--source`.

**كيفية الاستخدام:**

```bash
/usr/bin/python3 -I "$AEGIS" verify-install --source ./aegis-firewall-sentinel.py
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
INSTALLED_SHA256=<64_HEX>
INSTALLED_VERSION=0.9.0-alpha2-review5
SOURCE_SHA256=<SAME_64_HEX>
VERIFIED_INSTALL: root-owned runtime is present and version-readable.
```

**مستوى الخطورة:** منخفض.


### `audit` — تدقيق تشخيصي محدد

**الوظيفة:** يعرض حالة التقوية الأساسية وfirewalld وقواعد nftables والعدادات والمنافذ. **راجِع المعلومات الحساسة قبل مشاركتها.**

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" audit
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
AEGIS Firewall Sentinel 0.9.0-alpha2-review5 — READ-ONLY AUDIT
=== firewalld unit ===
...
=== nftables tables ===
...
AUDIT NOTE: wildcard listeners ...
```

**مستوى الخطورة:** منخفض.


### `validate` — فحص التهيئة

**الوظيفة:** يتحقق من الطبقة الأساسية وملفات firewalld ووحدات systemd وصياغة nft دون تطبيق سياسة جدار ناري.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" validate
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
VALIDATED: firewalld disk config, candidate nftables syntax, generated systemd units, and Network Hardening base passed.
```

**مستوى الخطورة:** منخفض.


### `plan` — معاينة التغييرات

**الوظيفة:** يعرض السياسة المقترحة والواجهات المعتمدة وبصمة الخطة؛ **لا يطبّق** القواعد.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
AEGIS Firewall Sentinel 0.9.0-alpha2-review5 | ACTION=apply | PLAN_SHA256=<64_HEX>
Quarantine: OFF
Direct plaintext DNS (53) egress: PASSTHROUGH
=== FIREWALL ACTIONS ===
...
```

**مستوى الخطورة:** منخفض.


### `apply` — التطبيق بمعاملة قابلة للاسترجاع

**الوظيفة:** يطبّق السياسة والملفات ضمن معاملة. يتطلب دخولاً محلياً عبر **TTY حقيقي** وتأكيد `APPLY <PLAN_SHA256>`؛ وقد يقطع الاتصال.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" apply
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
Type exactly "APPLY <CURRENT_PLAN_SHA256>" to continue:
...
COMMITTED: T-<TIMESTAMP>-<HEX>
# If already identical: NO-OP + VERIFIED
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `verify` — التحقق من سلامة التطبيق

**الوظيفة:** يقارن الملفات والـmanifest والطبقة الأساسية والوحدات وسياسة nft الحية؛ **بعد كل تغيير أو إعادة تشغيل**.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" verify
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
=== AEGIS Firewall Sentinel verification ===
VERIFIED: base Network Hardening, Sentinel egress policy, manifest, quarantine state, units, and runtime table match.
```

**مستوى الخطورة:** منخفض.


### `status` — ملخص الحالة

**الوظيفة:** يعرض السياسة والعزل وVPN وDNS والقوائم المؤقتة والمعاملات والمراقبة بصيغة مفتاح/قيمة.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" status
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
VERSION=0.9.0-alpha2-review5
POLICY_INSTALLED=yes
QUARANTINE=off
NFT_TABLE=present
TRANSACTION_STATUS=COMMITTED
MONITOR_STATUS=info
```

**مستوى الخطورة:** منخفض.


### `history` — سجل المعاملات

**الوظيفة:** يسرد مُعرّفات المعاملات وحالتها؛ ميّز بين `COMMITTED` و`ROLLED_BACK` ولا تخمّن المعرّف.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" history
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
T-<UTC_TIMESTAMP>-<HEX> COMMITTED
# Or: NO TRANSACTIONS
```

**مستوى الخطورة:** منخفض.


### `monitor-now` — فحص الانحراف الفوري

**الوظيفة:** يفحص سلامة السياسة والمؤشرات، **ويكتب تقرير مراقبة محدوداً** دون تعديل قواعد الجدار؛ ظهور `INFO` لا يثبت وصولاً من الشبكة.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" monitor-now
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
AEGIS Firewall Sentinel monitor: INFO
INFO     WILDCARD_LISTENERS: tcp 0.0.0.0:5355; udp 0.0.0.0:5353; ...
```

**مستوى الخطورة:** منخفض.


### `watch` — مشاهدة NFLOG مباشرة

**الوظيفة:** يعرض رسائل NFLOG للمجموعة 10 مباشرة عبر tcpdump؛ أوقفه بـ`Ctrl+C`. قد لا تظهر حزم إذا لم تحدث عمليات حظر.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" watch
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
Listening on nflog:10; telemetry is rate-limited ...
# Event lines appear only when matching traffic occurs.
```

**مستوى الخطورة:** منخفض.


### `list-blocked` — عرض قائمة الحظر المؤقت

**الوظيفة:** يعرض العناصر المحظورة في الذاكرة أو يذكر أن الجدول غير نشط.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" list-blocked
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
DYNAMIC BLOCKLIST: inactive (no blocked IPs)
# Or current nft set/table output
```

**مستوى الخطورة:** منخفض.


### `block-ip` — حظر مؤقت لعنوان IP أو نطاق

**الوظيفة:** يحظر عنواناً أو نطاقاً في الذاكرة؛ المدة من 60 ثانية إلى 30 يوماً. **غير مختبر ميدانياً وقد يقطع اتصالات مهمة.**

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" block-ip 203.0.113.15 --ttl 1h
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s in inet aegis_blocklist @blocked_v4
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `unblock-ip` — إزالة الحظر المؤقت

**الوظيفة:** يزيل عنصراً محدداً من قائمة الحظر؛ لا يعيد ضبط بقية السياسة.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" unblock-ip 203.0.113.15
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
UNBLOCKED: 203.0.113.15/32 from inet aegis_blocklist @blocked_v4
# Or: DYNAMIC BLOCKLIST TABLE IS NOT ACTIVE
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `isolate-cgroup-lan` — عزل cgroup عن الشبكة المحلية

**الوظيفة:** يمنع وصول cgroupv2 موجود إلى شبكات LAN الخاصة في الذاكرة فقط؛ تحقق من المسار ورقم inode. **لم يُختبر ميدانياً.**

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" isolate-cgroup-lan '<RELATIVE_CGROUP_PATH>'
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=<N> path=<PATH> inode=<N>
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `unisolate-cgroup-lan` — إيقاف عزل cgroup

**الوظيفة:** يزيل قاعدة العزل المحفوظة في الذاكرة وبيانات الربط المؤقتة.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" unisolate-cgroup-lan
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
CGROUP LAN ISOLATION OFF
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `rebind-cgroup-lan` — إعادة ربط cgroup المُنشأ مجدداً

**الوظيفة:** يعيد ربط القاعدة بعد إعادة إنشاء cgroup برقم inode جديد؛ يتطلب وجود سجل ربط سابق. **غير مختبر.**

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" rebind-cgroup-lan
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
CGROUP LAN ISOLATION ACTIVE (RAM-ONLY): level=<N> path=<PATH> inode=<NEW_N>
```

**مستوى الخطورة:** عالٍ — إجراء مُغيِّر/تجريبي.


### `quarantine-on` — تفعيل العزل الدائم الطارئ

**الوظيفة:** يفعّل عزلاً قوياً عبر معاملة؛ **قد يقطع الشبكة بالكامل ولم يُختبر قبولياً**. راجع `plan --quarantine-on` أولاً.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --quarantine-on
# On physical TTY, only after explicit recovery planning:
sudo /usr/bin/python3 -I "$AEGIS" quarantine-on
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
ACTION=quarantine-on | PLAN_SHA256=<64_HEX>
...
COMMITTED: T-<TIMESTAMP>-<HEX>
```

**مستوى الخطورة:** حرج — قد يؤدي إلى عزل الجهاز.


### `quarantine-off` — إيقاف العزل الدائم

**الوظيفة:** يعيد سياسة Sentinel المعتادة بمعاملة، مع TTY فعلي وموافقة على البصمة؛ **غير مختبر ميدانياً**.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" quarantine-off
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
ACTION=quarantine-off | PLAN_SHA256=<64_HEX>
...
COMMITTED: T-<TIMESTAMP>-<HEX>
```

**مستوى الخطورة:** حرج — قد يؤدي إلى عزل الجهاز.


### `panic-off` — إزالة العزل الطارئ من الذاكرة

**الوظيفة:** يزيل جدول `inet aegis_panic` المؤقت **فقط**؛ لا يعطّل الحجر الدائم. استخدمه في جلسة استرداد محلية.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" panic-off
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
EMERGENCY PANIC ISOLATION OFF
# Or: EMERGENCY PANIC ISOLATION ALREADY OFF
```

**مستوى الخطورة:** حرج — قد يؤدي إلى عزل الجهاز.


### `rollback` — التراجع عن معاملة مكتملة

**الوظيفة:** استرجاع معاملة محددة (أو الأخيرة عند حذف المعرّف) مع تأكيد `ROLLBACK <TX_ID> <SHA256_OF_PLAN_JSON>`؛ **يغير إعدادات الشبكة**.

**كيفية الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" history
# On verified physical TTY:
sudo /usr/bin/python3 -I "$AEGIS" rollback '<TX_ID>'
```

**علامة المخرجات المتوقعة (أو المثال التوضيحي):**

```text
Type exactly "ROLLBACK <TX_ID> <SHA256_OF_PLAN_JSON>" to continue:
ROLLED BACK: <TX_ID>
```

**مستوى الخطورة:** حرج — قد يؤدي إلى عزل الجهاز.


## 4. معاملات `plan` و`apply` — أمثلة ومعنى المخرجات

**قاعدة:** جميع الأمثلة أدناه أوامر **معاينة** عند استعمال `plan`، إلا إذا ذُكر أنها إجراء عالي الخطورة. لا تنفذ أوامر `apply` التجريبية دون جلسة TTY حقيقية وخطة استرداد. النتائج المعروضة **مشروطة**، وقد يظهر `STOP` إذا لم تُستوفَ المتطلبات.


### `--allow-lan-smb` — LAN SMB / RPC / NetBIOS

**الشرح:** التحكم في خروج SMB / RPC / NetBIOS: يتيح `--allow-lan-smb` الاتصال فقط بالشبكة المحلية الموثوقة، ويعيد `--deny-lan-smb` الحظر الافتراضي. قد تتأثر الطباعة عبر SMB.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --allow-lan-smb
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
LAN SMB/RPC/NetBIOS egress: ALLOWED
```


### `--allow-lan-ssdp` — SSDP discovery

**الشرح:** يسمح `--allow-lan-ssdp` بالاكتشاف على الواجهة الموثوقة؛ ويعيد `--deny-lan-ssdp` الحظر الافتراضي.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --allow-lan-ssdp
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
LAN SSDP egress: ALLOWED
```


### `--block-direct-dns` — Direct DNS port 53

**الشرح:** يمنع `--block-direct-dns` الاتصالات المباشرة بالمنفذ 53 خارج loopback. يعيد `--allow-direct-dns` السماح إذا كان DoT الصارم متوقفاً؛ لا تغلق DNS قبل تجهيز البديل.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --block-direct-dns
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
Direct plaintext DNS (53) egress: BLOCKED
```


### `--strict-dot-resolver` — Strict DNS-over-TLS

**الشرح:** يتطلب `--strict-dot-resolver` إعداد DoT مُتحققاً في systemd-resolved. فشل هذا الشرط على الجهاز الميداني؛ لذلك المتوقع رسالة `STOP`. يمكن التعطيل بخيار `--no-strict-dot-resolver`.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --strict-dot-resolver
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
STOP: Strict DoT preflight failed: ...
```


### `--strict-dot-resolver --dot-server 9.9.9.9 --dot-server-name dns.quad9.net` — DoT IP and certificate name

**الشرح:** أضف العناوين المسموح بها بخيار `--dot-server` المتكرر واسم الشهادة/SNI بخيار `--dot-server-name`. يجب أن تطابق سياسة DNS الفعلية على الجهاز.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --strict-dot-resolver --dot-server 9.9.9.9 --dot-server-name dns.quad9.net
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
STOP: Strict DoT preflight failed: ...  # if resolver is not attested
```


### `--vpn-only wg0 --vpn-endpoint 198.51.100.10:51820/udp` — VPN tunnel & handshake

**الشرح:** يقصر `--vpn-only` الاتصال على النفق، ويمكن السماح بنقطة مصافحة بخيار `--vpn-endpoint`. استخدمنا عنوان TEST-NET توضيحياً لا خادماً حقيقياً. `--vpn-off` يعطّل القاطع.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --vpn-only wg0 --vpn-endpoint 198.51.100.10:51820/udp
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
VPN kill-switch: ON (iface=wg0, ...)  # only if candidate accepted
```


### `--vpn-allow-lan` — VPN LAN exception

**الشرح:** يسمح `--vpn-allow-lan` بالوصول إلى LAN الموثوق مع قاطع VPN؛ ويمنعه `--vpn-deny-lan` افتراضياً. لا معنى للإعداد إذا لم يكن VPN مفعّلاً.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --vpn-allow-lan
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
VPN kill-switch: ON (iface=<TUNNEL>, allow_lan=True, ...)  # only if VPN is enabled
```


### `--allow-foreign-table inet:approved_example` — Foreign nftables approval

**الشرح:** يوافق `--allow-foreign-table` على جدول خارجي محدد بعد التحقق من بصمة hooks؛ و`--remove-foreign-table` يسحب الموافقة. الاسم المعروض مثال غير موجود على الأجهزة بالضرورة.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --allow-foreign-table inet:approved_example
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
Approved foreign tables: inet:approved_example  # only if actual table/hook attestation passes
```


### `--quarantine-on` — Quarantine preview flags

**الشرح:** مع `plan --quarantine-on` أو `plan --quarantine-off` تُعرض سياسة الحجر دون تطبيق؛ ومع `apply` تتغير القواعد الحية. قد تفقد الاتصال، فلا تُجرّبها دون وصول TTY وخطة استرداد.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --quarantine-on
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
Quarantine: ON
ACTION=quarantine-on | PLAN_SHA256=<HEX>
```


### `--allow-newer-packages` — Package-family override

**الشرح:** يخفف `--allow-newer-packages` حدّ الإصدارات المُراجعة لحزم Fedora 44. لا يثبت حزمًا أو يحدّثها، ويتطلب مراجعة جديدة للتوافق.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --allow-newer-packages
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
AEGIS Firewall Sentinel ... | PLAN_SHA256=<HEX>  # if package family accepted
```


### `--trust-interface eth0` — Deprecated trust flags

**الشرح:** خيارات `--trust-interface` و`--untrust-interface` معطلة عمداً. يعتمد تعريف الواجهة الموثوقة على اتصال NetworkManager ذي UUID المعتمد.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" plan --trust-interface eth0
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
STOP: Legacy --trust-interface/--untrust-interface is disabled: ...
```


### `--approve <CURRENT_PLAN_SHA256>` — Approval hashes

**الشرح:** قد يتجاوز `apply --approve` مطالبة الكتابة لكنه **لا يتجاوز** التحقق من جلسة TTY المعتادة. يستخدم `rollback --approve` بصمة ملف `plan.json` مختلفة.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" apply --approve '<CURRENT_PLAN_SHA256>'
# حالة تغيير حقيقية، ولا تُجرَّب خارج TTY مُتحقَّق
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
Plan approval digest mismatch  # if digest differs
```


### `--ttl 1h` — Blocklist expiration

**الشرح:** يقبل `block-ip` مدة `--ttl` بين 60 ثانية و30 يوماً؛ الافتراضي 24 ساعة. الاستعمال تجريبي وقد يقطع اتصالات قائمة.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" block-ip 203.0.113.15 --ttl 1h
# تغيير تجريبي عالي الخطورة، لا تنفّذه عشوائياً
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
BLOCKED (RAM-ONLY): 203.0.113.15/32 for 3600s ...  # if operation approved
```


### `--source ./aegis-firewall-sentinel.py` — Runtime source comparison

**الشرح:** يستخدم `verify-install --source` مقارنة مصدر Python مع نسخة التشغيل المحمية بواسطة SHA-256؛ لا يغيّر سياسة الشبكة.

**طريقة الاستخدام:**

```bash
/usr/bin/python3 -I "$AEGIS" verify-install --source ./aegis-firewall-sentinel.py
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
SOURCE_SHA256=<SAME_64_HEX>
VERIFIED_INSTALL: ...
```


### `--force-emergency` — Break-glass emergency

**الشرح:** خيار `quarantine-on --force-emergency` **حرج وغير مختبر ميدانياً**. يستعمل حماية طوارئ أضعف (TTY تفاعلي وloginuid) من فحص logind المعتاد، ويمكنه فصل الشبكة.

**طريقة الاستخدام:**

```bash
sudo /usr/bin/python3 -I "$AEGIS" quarantine-on --force-emergency
# خطر حرج، للمراجعة فقط وليس أمراً للتجربة
```

**المخرجات المحتملة أو الإشارة الشرطية:**

```text
EMERGENCY PANIC ISOLATION ACTIVE (RAM-ONLY): inet aegis_panic ...
```

## 5. أوامر النظام الداخلية — ليست للمستخدم

هذه الأوامر موجودة في محلّل الوسائط، لكنها **نقاط تشغيل داخلية محمية** وليست أدوات للصيانة التفاعلية:


- **`runtime-load` — محمل السياسة عبر systemd:** يُستدعى فقط من وحدة systemd المخصصة؛ الاستدعاء اليدوي مرفوض. **المخرجات:** نجاح صامت أو رسالة `STOP` عند غياب سياق systemd الصحيح؛ لا تختبرها يدوياً.


- **`network-gate` — بوابة سلامة NetworkManager:** يعمل أثناء بدء NetworkManager ويتطلب manifest مكتمل؛ **ليس أمراً للتشخيص اليدوي**. **المخرجات:** نجاح صامت أو رسالة `STOP` عند غياب سياق systemd الصحيح؛ لا تختبرها يدوياً.


- **`trust-sync` — مزامنة اتصال NetworkManager:** يحدّث dispatcher مجموعة الواجهات الموثوقة وفق UUID المُراجع؛ يستخدم داخلياً `trust-sync --dispatcher` ويتطلب سياق الاستدعاء الصحيح. **المخرجات:** نجاح صامت أو رسالة `STOP` عند غياب سياق systemd الصحيح؛ لا تختبرها يدوياً.


- **`emergency-rollback` — حارس التراجع التلقائي:** استرجاع آلي لمعاملة لم تكتمل في الإقلاع نفسه؛ تنفذه وحدة الحراسة المطابقة فقط. **المخرجات:** نجاح صامت أو رسالة `STOP` عند غياب سياق systemd الصحيح؛ لا تختبرها يدوياً.


- **`monitor-now --systemd` — نمط المراقبة المجدول:** مخصص لخدمة المراقبة؛ يكتب التقرير ولا ينتج عادة مخرجات تفاعلية. **المخرجات:** نجاح صامت أو رسالة `STOP` عند غياب سياق systemd الصحيح؛ لا تختبرها يدوياً.


## 6. تفسير الأخطاء والتعافي الآمن


### `STOP: Invoking terminal belongs ... class=manager`

جلسة الطرفية تنتمي إلى مدير المستخدم الرسومي؛ سجّل الدخول مجدداً على TTY حقيقي وتحقق من `Active=yes` و`Type=tty`، ولا تُضعف شرط التفويض.


### `STOP: Firewall Sentinel policy is not installed`

لم تُطبّق السياسة بعد؛ preflight يحدّث برنامج التشغيل فقط. لا تشغّل `network-gate` يدوياً.


### `STOP: Unstable unit activity state ... failed`

قد يكون هذا أثراً باقياً من فشل سابق. تحقق أولاً من `ROLLED_BACK` وغياب السياسة وجدول Sentinel وعمل NetworkManager، ثم فقط يمكن النظر في `reset-failed` لوحدة محددة.


### `nft ... unexpected junk ... \n`

خلل تاريخي من review4؛ كان يرسل `\n` حرفياً. صُحح في review5. تأكد من بصمة الملف واختبارات parser ولا تُعدل قواعد nft يدوياً.


### `Strict DoT preflight failed`

الـresolver المشفّر غير مُعتمد في `systemd-resolved`؛ لا توقف DNS التقليدي قسراً قبل استكمال متطلبات DoT.


### `INFO WILDCARD_LISTENERS`

قد يكون الاستماع على 5353 من Avahi وعلى 5355 من systemd-resolved طبيعياً. المنفذ المحلي لا يثبت قابلية الوصول عن بعد.


### Boot warning `IPv4 forwarding ... Success`

سُجل تحذير غير قاتل بعد الإقلاع؛ عملت الخدمات ونجحت الاختبارات، لكن سبب التحذير غير محدد حتى الآن.


### `No destinations added` / printer empty

في الجهاز الجديد لم تُضف طابعة، مع استمرار عمل CUPS وAvahi. غياب الطابعات ليس وحده دليلاً على عطل في الجدار.


### جمع الأدلة أولاً دون تغيير القواعد

```bash
sudo journalctl -b -u aegis-firewall-sentinel.service -n 100 --no-pager -o short-iso
sudo nft list tables
systemctl show NetworkManager -p ActiveState -p Result
systemctl --failed --no-pager
sudo find /var/lib/aegis/firewall-sentinel/transactions -maxdepth 2 -name status -print -exec cat {} \;
```

**المخرجات المتوقعة حسب الحالة:** `ROLLED_BACK` أو `COMMITTED` في ملفات المعاملات؛ و`ActiveState=active` عند سلامة NetworkManager. **لا تكرر `apply` بعد فشل مجهول، ولا تنفّذ `nft flush ruleset`، ولا تعطل خدمات الطباعة، ولا تستخدم `reset-failed` بديلاً عن الإصلاح.**

## 7. حدود النتائج والأمان

- `verify` و`monitor-now` بعد إعادة التشغيل نجحا **مرة واحدة على جهاز الاختبار**. لا توجد شهادة تدقيق أمني مستقل.
- DNS العادي ما زال غير مشفّر في الاختبار؛ DoT الصارم لم يجتز فحص الإعداد. وظهور `DNSSEC=no/unsupported` مختلف عن حالة تشفير النقل.
- لم تُختبر الطباعة من جهاز حقيقي، وميزات VPN والحجر والاستجابة العاجلة وcgroup وblocklist ليست مقبولة ميدانياً.
- رمز الخروج `0` يعني نجاحاً في الحالة العادية، و`2` غالباً تعني `STOP`، و`3` إخفاق `verify` أو تقرير `monitor` من مستوى warning/critical. لا تفترض أن تنفيذ عدة أوامر في Bash يتوقف عند أول خطأ.
- اقرأ [README الإنجليزي والتركي](README.md)، و[قائمة التغييرات](docs/CHANGELOG.md)، و[توثيق الاختبار العملي](docs/FIELD_ACCEPTANCE.md)، و[التعافي](docs/SECURITY_AND_RECOVERY.md).
