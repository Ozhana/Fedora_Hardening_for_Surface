# 03 — AEGIS Time-NTS

**الإصدار:** `0.2.0-rc4`  
**تم اختباره على:** Fedora 44 مع chrony 4.8+

AEGIS Time-NTS يضبط `chronyd` لاستخدام Network Time Security (NTS). الهدف هو منع شبكة غير موثوقة من إعطاء الجهاز وقتاً غير موثّق بصمت.

> عادةً تثبّت هذه الطبقة مرة واحدة وتطبقها مرة واحدة. بعد ذلك يستمر `chronyd` بالعمل في الخلفية.

## 1. قبل البدء

يلزم:

- Fedora 44.
- أن يكون `chronyd` مثبتاً ومفعلاً ويعمل مسبقاً.
- chrony 4.8+ مع دعم NTS.
- اتصال إنترنت يعمل.

السكربت لا يثبت الحزم تلقائياً.

## 2. التثبيت

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/time-nts

sudo install -o root -g root -m 0755 \
  ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh

sudo restorecon -RFv /usr/local/libexec/aegis/time-nts
```

ثم:

```bash
AEGIS_NTS=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
```

## 3. الاستخدام لأول مرة

افحص النظام:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" audit
```

اعرض الخطة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" plan
```

إذا كانت الخطة سليمة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" apply
```

ثم:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

النتيجة السليمة تنتهي عادةً بسطر مشابه لـ:

```text
VERIFIED SNAPSHOT: authenticated/selectable=3 ...
```

## 4. الاستخدام اليومي

لا يوجد أمر يومي مطلوب.

للتحقق من NTS:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

أمر `status` يعرض حالة المعاملة فقط، وليس فحص أمان NTS حيّاً.

## 5. أهم الأوامر

- `audit` — فحص للقراءة فقط.
- `plan` — يعرض إعداد NTS المقترح.
- `apply` — يطبق الخطة بعد التأكيد.
- `verify` — يتحقق من مصادر NTS الموثّقة الحية.
- `status` — حالة المعاملة فقط.
- `rollback` — يعيد إعداد chrony السابق.
- `--wait SECONDS` — يغيّر مدة انتظار التحقق.
- `--help` — المساعدة.

## 6. عند حدوث مشكلة

إذا لم ينجح `verify` فوراً، انتظر قليلاً ثم أعد المحاولة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
```

افحص chrony:

```bash
systemctl status chronyd --no-pager
chronyc sources -v
```

للعودة إلى الإعداد السابق:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" rollback
```

لا تحذف `/etc/chrony.conf` أو ملفات معاملة AEGIS يدوياً أثناء وجود عملية استعادة معلّقة.
