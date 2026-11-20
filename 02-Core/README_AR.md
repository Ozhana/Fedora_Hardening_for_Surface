# 02 — AEGIS Core

**الإصدار:** 0.2.0-bash1  
**تم اختباره على:** Fedora 44 وSurface Pro 9 (Intel/x86_64)

> هذه هي طبقة التقوية الأساسية. تطبّق مجموعة صغيرة من إعدادات kernel/sysctl ويمكنها منع تخزين payloads جديدة بواسطة systemd-coredump.

## الفكرة

الهدف ليس تغيير مئات الإعدادات عشوائياً. التسلسل هو:

~~~mermaid
flowchart LR
    A["الخطة"] --> B["التطبيق"]
    B --> C["التحقق"]
    C --> D["إعادة التشغيل"]
    D --> E["التحقق مرة أخرى"]
~~~

## التثبيت

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/core

sudo install -o root -g root -m 0755 \
  ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh

sudo restorecon -RFv /usr/local/libexec/aegis/core
~~~

~~~bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
~~~

## الاستخدام الأول

اعرض الخطة:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan \
  --profile surface-pro9
~~~

إذا كانت الخطة صحيحة، طبّقها:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply \
  --profile surface-pro9
~~~

ثم تحقّق:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
~~~

أعد تشغيل الجهاز مرة واحدة، ثم شغّل verify مرة أخرى.

## الاستخدام اليومي

لا تحتاج إلى apply كل يوم. استخدم verify بعد إعادة التشغيل أو بعد تحديثات كبيرة:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify \
  --profile surface-pro9
~~~

## أهم الأوامر

- audit — فحص للقراءة فقط
- plan — عرض التغييرات قبل تنفيذها
- apply — تطبيق الخطة
- verify — التحقق من الحالة الحية والدائمة
- history — عرض سجل المعاملات
- rollback TX_ID — التراجع عن معاملة
- packages — عرض الأدوات المطلوبة

## التراجع

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID
~~~

إذا حدث reboot بعد المعاملة:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback TX_ID \
  --files-only

sudo systemctl reboot
~~~

> لا تحذف ملفات AEGIS يدوياً أثناء الاسترداد. استخدم plan وhistory وrollback.
