# 04 — AEGIS Network Hardening

**الإصدار:** 0.7.0-rc4  
**تم اختباره على:** Fedora 44 وSurface Pro 9 مع firewalld + nftables

> تقلل هذه الطبقة التعرض غير الضروري للاتصالات الواردة مع الحفاظ على الإنترنت العادي واكتشاف الطابعات على الاتصال المحلي الذي تمت مراجعته.

## الفكرة

~~~mermaid
flowchart TD
    A["اتصال الشبكة"] --> B{"هل هو الاتصال الموثوق الذي راجعته؟"}
    B -->|"نعم"| C["aegis-lan"]
    B -->|"لا"| D["aegis-public"]
    C --> E["firewalld + nftables"]
    D --> E
    E --> F["جهازك"]
~~~

تزيل السياسة الوصول الوارد عبر SSH وSamba/NetBIOS والنطاق الواسع 1025–65535 من الملف الفيزيائي المحدد.

## قبل البدء

- Fedora 44 يعمل بشكل طبيعي
- firewalld يعمل
- NetworkManager يعمل
- لديك جلسة محلية لاستعادة الجهاز
- Docker غير نشط أثناء apply

## التثبيت

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening

sudo install -o root -g root -m 0755 \
  ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh

sudo restorecon -RFv \
  /usr/local/libexec/aegis/network-hardening
~~~

~~~bash
AEGIS_NET=/usr/local/libexec/aegis/network-hardening/aegis-network.sh
~~~

تحقق من النسخة المثبتة:

~~~bash
/usr/bin/bash -p -- "$AEGIS_NET" verify-install
~~~

## الاستخدام الأول

اعرض الخطة أولاً:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan
~~~

راجع الاتصال وUUID والمنطقة المقترحة. إذا كانت صحيحة:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" apply
~~~

ثم:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
~~~

أعد التشغيل مرة واحدة ثم شغّل verify مرة أخرى.

## الاستخدام اليومي

لا يوجد apply يومي.

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
sudo /usr/bin/bash -p -- "$AEGIS_NET" status
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
~~~

## أهم الأوامر

- verify-install — التحقق من نسخة السكربت المثبتة
- audit — فحص شبكة وجدار ناري للقراءة فقط
- plan — عرض التغييرات قبل التطبيق
- apply — تطبيق السياسة
- verify — التحقق من الحالة الحية والدائمة
- status — الحالة الحالية
- history — سجل المعاملات
- rollback TX_ID — التراجع
- export — إنشاء تقرير فحص خاص

## أكثر من اتصال فيزيائي

~~~bash
nmcli -t -f NAME,UUID,TYPE,DEVICE \
  connection show --active
~~~

ثم اختر UUID الصحيح:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan \
  --connection-uuid YOUR_UUID
~~~

## التراجع

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
sudo /usr/bin/bash -p -- "$AEGIS_NET" rollback TX_ID
~~~

> إذا أخبرك plan أن Docker نشط، لا تتجاوز الفحص. أوقف Docker أو استخدم طبقة عزل Docker المخصصة لاحقاً.
