# 02 — AEGIS Core

**الإصدار:** `0.2.0-bash1`  
**تم اختباره على:** Fedora 44 وSurface Pro 9 (Intel/x86_64)

AEGIS Core هي طبقة التقوية الأساسية. تطبق مجموعة صغيرة من إعدادات حماية kernel/sysctl، ويمكنها تعطيل تخزين payloads الجديدة بواسطة `systemd-coredump`.

هذه الطبقة لا تغيّر الجدار الناري أو DNS أو NTS أو الحزم أو bootloader أو AIDE أو rkhunter.

> عادةً تُثبّت هذه الطبقة مرة واحدة ثم تُترك تعمل. لا حاجة لتشغيل `apply` كل يوم.

## 1. التثبيت

افتح الطرفية داخل هذا المجلد ثم نفّذ:

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/core

sudo install -o root -g root -m 0755 \
  ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh

sudo restorecon -RFv /usr/local/libexec/aegis/core
```

ثم:

```bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
```

## 2. الاستخدام لأول مرة

على Surface Pro 9:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9
```

راجع الخطة. إذا لم توجد موانع:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply \
  --profile surface-pro9
```

ثم:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
```

أعد تشغيل الجهاز مرة واحدة ثم شغّل `verify` مرة أخرى.

على أجهزة Fedora 44 الأخرى المدعومة استخدم:

```bash
--profile universal
```

## 3. الاستخدام اليومي

لا يوجد إجراء يومي مطلوب.

بعد إعادة التشغيل أو تحديث كبير للنظام يمكنك التحقق عبر:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

## 4. أهم الأوامر

- `audit` — فحص للقراءة فقط.
- `plan` — يعرض ما سيتغير دون تعديل النظام.
- `apply` — يطبق الخطة بعد التأكيد.
- `verify` — يتحقق من الإعدادات الحالية والدائمة.
- `history` — يعرض المعاملات السابقة.
- `rollback TX_ID` — يتراجع عن معاملة مناسبة.
- `packages` — يعرض الأدوات المطلوبة ولا يثبت شيئاً ڪلقائياً.
- `--help` / `--version` — المساعدة ومعلومات الإصدار.

## 5. عند حدوث مشكلة

لا تحذف ملفات AEGIS يدوياً.

ابدأ بـ:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9

sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

للتراجع:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID
```

إذا حدثت إعادة تشغيل بعد المعاملة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID \
  --files-only

sudo systemctl reboot
```

> AEGIS يقلل بعض أسطح الهجوم، لكنه لا يعني أن الجهاز أصبح آمناً بالكامل بمفرده.
