# AEGIS TIME-NTS

**الإصدار:** `0.2.0-rc4`  
**الحالة:** تم تفعيل NTS والتحقق منه حياً على جهاز المشروع Fedora 44 / Surface Pro 9  
**الترخيص:** [MIT](../LICENSE)  
**الدليل الثنائي English/Türkçe:** [README.md](README.md)

> راجع `plan` الحالي قبل `apply`. لا تعِد استخدام بصمة خطة من إصدار قديم أو من حالة جهاز تغيّرت.

## الفكرة

AEGIS TIME-NTS ينقل عميل Chrony موجوداً على Fedora 44 إلى سياسة Network Time Security (NTS) موثّقة عبر ثلاثة أسماء مضيفين:

```conf
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
authselectmode require
minsources 2
ntsdumpdir /var/lib/chrony
nocerttimecheck 0
port 0
```

يفصل التصميم بين نتيجتين مختلفتين:

1. نجاح تطبيق الإعداد وإعادة تشغيل Chrony.
2. إثبات أن المزامنة الحية تستخدم NTS وحزماً موثّقة.

نجاح الأولى لا يعني تلقائياً نجاح الثانية.

## ماذا يغيّر؟

- يضيف المصادر الثلاثة المراجعة مع `nts`.
- يفرض `authselectmode require` حتى لا يُختار مصدر غير موثّق.
- يضع `minsources 2`، ما يزيد شرط الاتفاق لكنه قد يقلل التوفر إذا لم يبق إلا مصدر واحد صالح.
- يستخدم `port 0` حتى يبقى Chrony عميلاً ولا يفتح خدمة NTP كخادم.
- يحافظ على `ntsdumpdir /var/lib/chrony` ويفعّل فحص وقت الشهادة عبر `nocerttimecheck 0`.
- يحافظ على إعدادات غير متعلقة بالمصادر مثل `makestep` و`rtcsync` عندما تكون مدعومة.

## ماذا لا يغيّر؟

- لا يثبت حزماً.
- لا يغيّر firewall.
- لا يغيّر DNS أو IPv6.
- لا يحذف NTS cookies تلقائياً.
- لا يقدّم fallback غير موثّق.
- لا يشغّل `date --set` أو `hwclock` أو أمر step مباشر.
- rollback يعيد ملف الإعداد ولا يستطيع إعادة التاريخ السابق للساعة أو timestamps التي كُتبت بالفعل.

## المتطلبات

- Fedora 44 native وغير افتراضي وقابل للتعديل.
- Chrony 4.8 أو أحدث ضمن سلسلة 4.x.
- يجب أن يعرض `chronyd -v` الدعم `+NTS`.
- `chronyd.service` القياسي يجب أن يكون active وenabled مسبقاً.
- لا توجد خدمة وقت منافسة active/enabled.
- WSL وVM والحاويات وAtomic/OSTree هي audit-only لهذه النسخة.
- أي drop-in غير متوقع أو service/config مخصص يحتاج مراجعة يدوية.

## التثبيت

```bash
LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./aegis-time-nts.sh --help

sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/time-nts
sudo install -o root -g root -m 0755 ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
sudo install -o root -g root -m 0755 ./export-audit.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts-export.sh
sudo restorecon -RFv /usr/local/libexec/aegis/time-nts

AEGIS_TIME=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
```

لا يوجد أمر `--version` مستقل؛ يظهر الإصدار `0.2.0-rc4` في خرج `audit` و`plan`.

## أول تشغيل

```bash
sudo /usr/bin/bash -p -- "$AEGIS_TIME" audit
sudo /usr/bin/bash -p -- "$AEGIS_TIME" plan
sudo /usr/bin/bash -p -- "$AEGIS_TIME" apply
sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status
```

الموافقة التفاعلية لـapply تتطلب:

```text
APPLY <PLAN_SHA256>
```

بعد مراجعة بشرية يمكن استخدام:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_TIME" apply --approve <PLAN_SHA256>
```

## معنى VERIFIED SNAPSHOT

يتطلب التحقق الحي، من بين أمور أخرى:

- ثبات المصدر المختار بين ملاحظتين.
- جاهزية NTS keys.
- وصول حزم authenticated RX.
- عينات حديثة.
- مصدرين موثّقين وقابلين للاختيار على الأقل.
- حالة tracking/leap صالحة.
- remaining correction لا يتجاوز 0.1 ثانية.

هذه نتيجة قوية لحالة Chrony/NTS المرصودة، لكنها ليست ضماناً رياضياً للخطأ المطلق عن UTC ولا ضماناً لنزاهة جميع الخوادم البعيدة.

قد يظهر مؤقتاً:

```text
NOT VERIFIED: selected source changed or is absent
```

أثناء انتقال طبيعي بين المصادر. حلقة الانتظار المحدودة تعيد الرصد بدون تخفيف السياسة.

## مرجع الأوامر

- `audit` — فحص محلي للقراءة فقط؛ ليس حكماً حياً على NTS.
- `plan` — يبني الإعداد المقترح ويطلب من Chrony تحليله ثم يعرض `PLAN_SHA256` بدون تفعيل.
- `apply` — يسجّل transaction، يستبدل ملف الإعداد، يتحقق من restart جديد لـChrony ثم يجري verify حي.
- `verify --wait 0..300` — تحقق حي من NTS؛ الافتراضي 120 ثانية.
- `status` — حالة journal فقط، وليست حكماً حياً على NTS.
- `rollback` — يعيد الإعداد الأصلي بعد فحص التعارضات ويعيد تشغيل Chrony.
- `--approve SHA256` — موافقة صريحة لـapply/rollback الحالي.
- `export-audit.sh` — يحفظ تقرير audit خاصاً بالمستخدم؛ قد يحتوي عناوين المصادر وتفاصيل الإعداد.

## متطلبات الشبكة

إنشاء مفاتيح NTS يستخدم عادة TCP 4460. وجهة UDP الخاصة بـNTP يتم التفاوض عليها، وNetnod يوثق UDP 4123. لذلك firewall يسمح فقط بـUDP 123 قد يكسر مصدراً صحيحاً. هذه الطبقة لا تغيّر firewall بنفسها.

## الاستخدام اليومي

لا تشغّل `apply` كل يوم. `chronyd` الموجود يستمر في العمل. استخدم verify بعد reboot أو تغييرات الشبكة/firewall أو ترقية Chrony أو عند الشك:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_TIME" verify --wait 120
sudo /usr/bin/bash -p -- "$AEGIS_TIME" status
```

إذا لم يتغير الإعداد، يجب أن يكون apply التالي `NO-OP` ولا ينشئ backup أو restart أو journal دائم جديد، مع استمرار verify الحي.

## rollback

الحالة محفوظة في:

```text
/var/lib/fedora-hardening/time-nts
```

شغّل:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_TIME" rollback
```

سيظهر `ROLLBACK_SHA256` جديد ويطلب:

```text
ROLLBACK <ROLLBACK_SHA256>
```

**تحذير:** إذا كان الإعداد الأصلي يحتوي مصادر NTP غير موثّقة، يمكن للrollback إعادتها. كما أنه لا يستطيع التراجع عن تعديلات الساعة التي حدثت بالفعل.

## استكشاف المشاكل

- **لا يوجد `+NTS` أو Chrony أقدم من 4.8:** لا تطبّق السياسة قبل إصلاح المتطلب.
- **drop-in أو service مخصص غير متوقع:** توقف للمراجعة اليدوية.
- **NTS keys لا تصبح جاهزة:** افحص DNS والاتصال وTCP 4460 وUDP المتفاوض عليه؛ لا تعطل فحص وقت الشهادة ولا تضف fallback plaintext كحل سريع.
- **Netnod يفشل وحده:** تحقق من outbound UDP 4123.
- **الساعة الابتدائية خاطئة جداً:** عالج bootstrap-time بشكل منفصل؛ لا تُلغِ فحص الشهادة.
- **حالة recovery معلقة:** استخدم `status` و`rollback`، ولا تحذف مجلد الحالة لتجاوز gate الأمان.

## رموز الخروج

- `0` نجاح الإجراء المطلوب.
- `1` فحص ناقص أو فشل أداة أدنى.
- `2` رفض/فشل تحقق.
- `3` التحقق الحي غير مكتمل.
- `75` قفل الكاتب مشغول.
- الإشارات عادة 129/130/143 لـHUP/INT/TERM.

## حالة التحقق

تم تفعيل rc4 على جهاز المشروع Fedora 44 / Surface Pro 9. أظهرت اختبارات حية متكررة المصادر الثلاثة مع NTS keys وauthenticated RX، ومصدرين قابلين للاختيار على الأقل، و`VERIFIED SNAPSHOT`. بقيت النتيجة صحيحة بعد طبقة Network hardening وبعد reboot. هذا لا يضمن نزاهة الخوادم البعيدة أو دقة UTC المطلقة.
