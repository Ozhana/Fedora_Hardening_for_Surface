# 04 — AEGIS Network Hardening

**الإصدار:** `0.7.0-rc4`  
**تم اختباره على:** Fedora 44 وSurface Pro 9 مع firewalld + nftables

AEGIS Network Hardening يقلل التعرض غير الضروري للشبكة الواردة. ينشئ منطقتين واضحتين في firewalld:

- `aegis-public` — منطقة افتراضية مقيدة.
- `aegis-lan` — للاتصال المحلي الذي تمت مراجعته، مع دعم اكتشاف/استخدام الطابعة.

تزيل السياسة SSH الوارد وSamba/NetBIOS والسماح الواسع للمنافذ TCP/UDP `1025-65535`.

> عادةً تثبّت هذه الطبقة مرة واحدة وتتركها تعمل. لا تحتاج إلى خدمة AEGIS دائمة ولا إلى `apply` يومي.

## 1. قبل البدء

استخدم هذه الطبقة عندما:

- Fedora 44 يعمل بصورة طبيعية.
- `firewalld` وNetworkManager يعملان.
- لديك جلسة محلية على الجهاز للاستعادة.
- Docker غير نشط أثناء `apply`.

مهم: SSH الوارد ومشاركة Samba غير مسموحين عمداً. يتم الحفاظ على حركة اكتشاف/عميل الطابعة.

## 2. التثبيت

```bash
sha256sum -c SHA256SUMS

sudo install -d -o root -g root -m 0755 \
  /usr/local/libexec/aegis/network-hardening

sudo install -o root -g root -m 0755 \
  ./aegis-network.sh \
  /usr/local/libexec/aegis/network-hardening/aegis-network.sh

sudo restorecon -RFv \
  /usr/local/libexec/aegis/network-hardening
```

ثم:

```bash
AEGIS_NET=/usr/local/libexec/aegis/network-hardening/aegis-network.sh
```

تحقق من النسخة المثبتة:

```bash
/usr/bin/bash -p -- "$AEGIS_NET" verify-install
```

## 3. الاستخدام لأول مرة

اعرض الخطة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan
```

راجع الاتصال والجهاز والمناطق وهاش الخطة.

إذا كانت الخطة صحيحة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" apply
```

ثم:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
```

أعد تشغيل الجهاز مرة واحدة ثم شغّل `verify` مرة أخرى.

## 4. الاستخدام اليومي

لا يوجد أمر يومي مطلوب.

للفحص:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
sudo /usr/bin/bash -p -- "$AEGIS_NET" status
```

إذا كان النظام مضبوطاً بالفعل فيجب أن تكون عملية `apply` الثانية `NO-OP`.

## 5. أهم الأوامر

- `verify-install` — يتحقق من نسخة السكربت المثبتة.
- `audit` — فحص الشبكة والجدار الناري للقراءة فقط.
- `plan` — يعرض ما سيتغير.
- `apply` — يطبق السياسة بعد المراجعة.
- `verify` — يتحقق من المناطق وربط الاتصال وnftables وsysctl.
- `status` — يعرض الحالة الحالية.
- `history` — يعرض المعاملات.
- `rollback [TX_ID]` — يعيد معاملة سابقة.
- `packages` — يعرض الأدوات المطلوبة والاختيارية.
- `export` — ينشئ تقرير فحص خاصاً.

## 6. عند حدوث مشكلة

إذا قال `plan` إن Docker نشط، أوقف Docker أو انتظر طبقة Docker-isolation المنفصلة. لا تتجاوز هذا الفحص.

إذا كان هناك أكثر من اتصال فعلي نشط:

```bash
nmcli -t -f NAME,UUID,TYPE,DEVICE \
  connection show --active
```

ثم اختر UUID الصحيح:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan \
  --connection-uuid YOUR_UUID
```

للاستعادة:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
sudo /usr/bin/bash -p -- "$AEGIS_NET" rollback TX_ID
```

لا تحذف مناطق AEGIS في firewalld يدوياً أثناء وجود معاملة نشطة.

> هذه الطبقة تقلل بعض أسطح الهجوم الواردة، لكنها لا تنشئ قائمة سماح للتطبيقات الصادرة.
