# 03 — AEGIS Time-NTS

**الإصدار:** 0.2.0-rc4  
**تم اختباره على:** Fedora 44 مع chrony 4.8+

> هذه الطبقة تجعل chrony يستخدم Network Time Security (NTS) حتى لا تعتمد الساعة فقط على مصدر وقت غير موثّق.

## لماذا NTS؟

~~~mermaid
flowchart LR
    A["جهازك"] --> B["chronyd"]
    B -->|"وقت موثّق عبر NTS"| C["خوادم الوقت"]
~~~

الوقت الصحيح والوقت الموثّق ليسا الشيء نفسه. NTS يساعدك على التحقق من مصدر الوقت.

## قبل البدء

يجب أن يكون:

- Fedora 44
- chronyd مثبتاً ويعمل
- chrony 4.8 أو أحدث ضمن السلسلة المدعومة
- NTS مدعوماً
- الاتصال بالإنترنت يعمل

## التثبيت

~~~bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/time-nts

sudo install -o root -g root -m 0755 \
  ./aegis-time-nts.sh \
  /usr/local/libexec/aegis/time-nts/aegis-time-nts.sh

sudo restorecon -RFv /usr/local/libexec/aegis/time-nts
~~~

~~~bash
AEGIS_NTS=/usr/local/libexec/aegis/time-nts/aegis-time-nts.sh
~~~

## الاستخدام الأول

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" audit
sudo /usr/bin/bash -p -- "$AEGIS_NTS" plan
sudo /usr/bin/bash -p -- "$AEGIS_NTS" apply
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
~~~

النتيجة السليمة تتضمن عادةً:

~~~text
NTS_key=yes
authenticated_RX=yes
fresh=yes
VERIFIED SNAPSHOT: ...
~~~

## الاستخدام اليومي

لا تحتاج إلى apply كل يوم. للتحقق من NTS استخدم:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" verify
~~~

مهم: status يعرض حالة المعاملة فقط، وليس حكماً حياً على أمان NTS.

## أهم الأوامر

- audit — فحص للقراءة فقط
- plan — عرض إعداد NTS المقترح
- apply — تطبيق الخطة
- verify — التحقق الحي من NTS
- status — حالة المعاملة فقط
- rollback — استعادة إعداد chrony السابق
- --wait SECONDS — تغيير مدة المراقبة

## عند حدوث مشكلة

~~~bash
systemctl status chronyd --no-pager
chronyc sources -v
~~~

وللتراجع:

~~~bash
sudo /usr/bin/bash -p -- "$AEGIS_NTS" rollback
~~~
