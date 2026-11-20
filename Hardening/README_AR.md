# AEGIS Core — Fedora Hardening Stage 1

**الإصدار:** `0.2.0-bash1`  
**الحالة:** تم اختباره على جهاز المشروع Fedora 44 / Surface Pro 9  
**الترخيص:** [MIT](../LICENSE)  
**الدليل الثنائي English/Türkçe:** [README.md](README.md)

> **تنبيه:** راجع ناتج `plan` الحالي قبل أي عملية تغيّر النظام. لا تستخدم بصمة خطة قديمة ولا تشغّل نسخة قديمة من السكربت مع هذا الإصدار.

## ما هذه الطبقة؟

AEGIS Core هي الطبقة الأولى من التقوية. تطبّق مجموعة صغيرة ومحددة من إعدادات kernel/sysctl، وتمنع افتراضياً تخزين/معالجة payloads جديدة بواسطة `systemd-coredump`. التصميم transactional، ويرفض الكتابة فوق ملف مُدار تم تغييره، ويحفظ معلومات rollback، ولا يثبت أي حزمة تلقائياً.

تشمل المفاتيح المُدارة:

```text
fs.protected_fifos
fs.protected_hardlinks
fs.protected_regular
fs.protected_symlinks
fs.suid_dumpable
kernel.dmesg_restrict
kernel.kptr_restrict
kernel.randomize_va_space
kernel.unprivileged_bpf_disabled
kernel.yama.ptrace_scope
```

والملفات الدائمة هي:

```text
/etc/sysctl.d/90-fedora-hardening-stage1.conf
/etc/systemd/coredump.conf.d/90-fedora-hardening-stage1.conf
```

يمكن استخدام `--keep-coredumps` لمنع إنشاء سياسة coredump في العملية الحالية؛ هذا الخيار ليس أمر إزالة.

## ما الذي لا تفعله؟

- لا تغيّر firewall أو DNS أو NTS.
- لا تحدّث baseline لـ AIDE/rkhunter.
- لا تعدّل bootloader.
- لا تثبت أو تحذف أو تحدّث حزماً.
- لا تغيّر SELinux إلى Enforcing؛ يجب أن يكون Enforcing مسبقاً.

## الهدف المدعوم

- Fedora 44 native مع systemd وتثبيت RPM قابل للتعديل.
- SELinux = Enforcing.
- `firewalld.service` مفعّل ويعمل مسبقاً.
- وحدات CUPS/Avahi غير masked.
- Atomic/OSTree/bootc وWSL والحاويات خارج نطاق التغيير.
- ملف `surface-pro9` مخصص لـ Microsoft Surface Pro 9 Intel/x86_64؛ إصدار SQ3/ARM خارج هذا الملف.

## التثبيت

تحقق من الحزمة أولاً:

```bash
LC_ALL=C sha256sum --check SHA256SUMS
/usr/bin/bash -p -- ./fh-terminal.sh --version
```

لنسخة دائمة:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec/aegis/core
sudo install -o root -g root -m 0755 ./fh-terminal.sh \
  /usr/local/libexec/aegis/core/fh-terminal.sh
sudo restorecon -RFv /usr/local/libexec/aegis/core

AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
/usr/bin/bash -p -- "$AEGIS_CORE" --version
```

الإصدار المتوقع:

```text
0.2.0-bash1
```

لا تستخدم `source` للملف؛ شغّله دائماً عبر `/usr/bin/bash -p --`.

## أول تشغيل

التسلسل الموصى به:

```text
audit → plan → apply → verify → reboot → verify
```

مثال Surface Pro 9:

```bash
AEGIS_CORE=/usr/local/libexec/aegis/core/fh-terminal.sh
sudo /usr/bin/bash -p -- "$AEGIS_CORE" audit  --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" plan   --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" apply  --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9
```

الموافقة التفاعلية تتطلب كتابة:

```text
APPLY surface-pro9
```

أو `APPLY universal`. بعد مراجعة بشرية يمكن تمرير بصمة الخطة الحالية فقط عبر `--approve SHA256`. إذا تغيّرت الخطة تصبح الموافقة القديمة غير صالحة.

## مرجع الأوامر

- `audit` — فحص للقراءة فقط مع الخطة الحالية. نجاحه لا يعني أن الجهاز آمن بالكامل.
- `plan` — يعرض القيم الحالية/المستهدفة، الموانع، العمليات وSHA256 للخطة بدون تغيير النظام.
- `apply` — يقفل الحالة، يعيد فحص الخطة، يسجل transaction، ينشر الملفات ويطبّق sysctl الحي.
- `verify` — يتحقق من حالة هذه الطبقة فقط، وليس تدقيقاً أمنياً كاملاً للنظام.
- `history` — يعرض سجل العمليات الخاص بـroot.
- `rollback TX_ID` — يعيد أحدث transaction نشط بعد فحص التعارضات.
- `packages` — يعرض الأدوات المطلوبة/الاختيارية؛ السكربت لا يثبت شيئاً تلقائياً.
- `--profile universal|surface-pro9` — اختيار الملف.
- `--keep-coredumps` — عدم إنشاء سياسة coredump في plan/apply/verify.
- `--files-only` — rollback بعد reboot للملفات الدائمة فقط، ثم يجب reboot مرة أخرى.
- `--version`, `--help` — الإصدار والمساعدة.

## الاستخدام اليومي

لا حاجة إلى تشغيل `apply` يومياً. لا توجد خدمة أو timer دائم من AEGIS Core. بعد التطبيق تصبح الإعدادات دائمة عبر systemd/sysctl.

شغّل `verify` بعد reboot أو تحديثات kernel/systemd أو عند الاشتباه بأن أداة أخرى غيّرت نفس الإعدادات:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" verify --profile surface-pro9
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

على جهاز مطابق يجب أن يكون apply المتكرر `NO-OP` وألا ينشئ transaction جديداً.

## rollback والإزالة

لا تحذف ملفات `/etc` يدوياً أولاً. اعرض السجل:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" history
```

ثم أعد أحدث transaction:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD...
```

إذا حدث reboot بعد العملية:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_CORE" rollback B-YYYYMMDD... --files-only
sudo systemctl reboot
```

بعد rollback ناجح يمكن حذف النسخة الاختيارية من `/usr/local/libexec/aegis/core`. لا تستخدم `rm -rf` على سجل الحالة كطريقة لتجاوز مشكلة recovery.

## استكشاف المشاكل

- **ملف مُدار موجود لكنه مختلف:** توقف؛ السكربت يرفض الكتابة فوق تعديل يدوي/أجنبي.
- **ملف hardening قديم موجود:** افحصه وهاجره/أزله بشكل واعٍ، ولا تحذفه عشوائياً.
- **SELinux أو firewalld لا يحقق الشرط:** أصلح الشرط خارج هذه الطبقة؛ السكربت لا يفعّل الخدمات نيابة عنك.
- **transaction غير مكتمل:** استخدم `history` ثم `rollback` قبل أي apply جديد.
- **`verify` يرجع 3:** ما زالت هناك تغييرات مطلوبة؛ شغّل `plan` وافحص drift.

## حالة التحقق

تم تطبيق هذا المصدر نفسه `0.2.0-bash1` على جهاز المشروع Fedora 44 / Surface Pro 9، ووصلت مفاتيح sysctl العشرة إلى الحالة المستهدفة، ونجح التحقق بعد reboot. هذا دليل قبول على جهاز محدد، وليس ضماناً عاماً لكل الأجهزة أو الإصدارات المستقبلية.

## ملاحظة أمنية

هذه الطبقة تقلل أسطح هجوم محددة ولا تجعل النظام “غير قابل للاختراق”. شغّل root فقط من مصدر راجعته وتحققت من checksum الخاص به.
