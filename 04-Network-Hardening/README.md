# 04 â€” AEGIS Network Hardening

**Version:** `0.7.0-rc4`  
**Tested on:** Fedora 44, Surface Pro 9, firewalld + nftables  
**Arabic guide:** [README_AR.md](README_AR.md)

AEGIS Network Hardening reduces unnecessary inbound network exposure. It replaces Fedora Workstation's broad default exposure with two controlled firewalld zones:

- `aegis-public` â€” restrictive fallback zone.
- `aegis-lan` â€” selected local connection with printer discovery/client support.

It removes inbound SSH, Samba/NetBIOS, and blanket TCP/UDP `1025-65535` allowances from the selected physical profile.

> This layer is designed to be installed once and left in place. It does not need a permanent AEGIS service or daily `apply`.

## English

### 1. Before you start

Use this layer only if:

- Fedora 44 is running normally.
- `firewalld` and NetworkManager are active.
- you have a local desktop/TTY session for recovery.
- Docker is not active during `apply`.

Important: inbound SSH and Samba sharing are intentionally not allowed by this policy. Printer discovery/client traffic is preserved.

### 2. Install

Open Terminal in this folder:

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

Set a short command variable:

```bash
AEGIS_NET=/usr/local/libexec/aegis/network-hardening/aegis-network.sh
```

Check the installed copy:

```bash
/usr/bin/bash -p -- "$AEGIS_NET" verify-install
```

### 3. First use

Preview the plan:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan
```

Read the selected connection, device, zones, and plan hash.

If the plan is correct:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" apply
```

Then verify:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
```

Reboot once and run `verify` again.

### 4. Normal use

No daily command is required.

Useful checks:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" verify
sudo /usr/bin/bash -p -- "$AEGIS_NET" status
```

A second `apply` on an already-correct system should report `NO-OP`.

### 5. Commands

- `verify-install` â€” checks the installed script copy.
- `audit` â€” read-only network/firewall inspection.
- `plan` â€” shows what would change.
- `apply` â€” applies the reviewed network policy.
- `verify` â€” checks zones, profile binding, nftables gate, and sysctls.
- `status` â€” shows the current managed state.
- `history` â€” lists transactions.
- `rollback [TX_ID]` â€” restores a previous transaction.
- `packages` â€” shows required/optional tools.
- `export` â€” exports a private audit report.

### 6. If something goes wrong

If `plan` says Docker is active, stop Docker first or wait for the separate Docker-isolation layer. Do not bypass this safety check.

If more than one physical connection is active, list them:

```bash
nmcli -t -f NAME,UUID,TYPE,DEVICE \
  connection show --active
```

Then choose the intended UUID:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" plan \
  --connection-uuid YOUR_UUID
```

For recovery:

```bash
sudo /usr/bin/bash -p -- "$AEGIS_NET" history
sudo /usr/bin/bash -p -- "$AEGIS_NET" rollback TX_ID
```

Do not manually delete the AEGIS firewalld zones while a transaction is active.

---

## TÃ¼rkÃ§e

### 1. BaÅŸlamadan Ã¶nce

Bu katmanÄ± yalnÄ±z ÅŸu durumda kullanÄ±n:

- Fedora 44 normal Ã§alÄ±ÅŸÄ±yor.
- `firewalld` ve NetworkManager active.
- kurtarma hÃ§Špå•É•°µ…ÏñÍÓğ½QQd½ÑÕÉÕµÔÙ…È¸(´…ÁÁ±å€ÏÅÉ…ÏÅ¹‘„½­•È…­Ñ¥˜‘—}¥°¸(+Y¹•µ±¤è¥¹‰½Õ¹MM Ù”M…µ‰„Á…å±‡Å´Ä‰ÔÁ½±¥Ñ¥­…‘„‰¥±¥»±¤½±…É…¬‡ŸÅ±µ…è¸e…ëÅÄ­—}™¤½¥ÍÑ•µ¤ÑÉ…™§}¤­½ÉÕ¹ÕÈ¸((ŒŒŒ€È¸-ÕÉÕ±Õ´()Q•Éµ¥¹…±¤‰Ô­±…ÏÙÉ‘”‡ŸÅ¸è()‰…Í )Í¡„ÈÔÙÍÕ´€µŒM!ÈÔÙMU5L()ÍÕ‘¼¥¹ÍÑ…±°€µ€µ¼É½½Ğ€µœÉ½½Ğ€µ´€ÀÜÔÔp(€€½ÕÍÈ½±½…°½±¥‰•á•Œ½…•¥Ì½¹•Ñİ½É¬µ¡…É‘•¹¥¹œ()ÍÕ‘¼¥¹ÍÑ…±°€µ¼É½½Ğ€µœÉ½½Ğ€µ´€ÀÜÔÔp(€€¸½…•¥Ìµ¹•Ñİ½É¬¹Í p(€€½ÕÍÈ½±½…°½±¥‰•á•Œ½…•¥Ì½¹•Ñİ½É¬µ¡…É‘•¹¥¹œ½…•¥Ìµ¹•Ñİ½É¬¹Í ()ÍÕ‘¼É•ÍÑ½É•½¸€µIØp(€€½ÕÍÈ½±½…°½±¥‰•á•Œ½…•¥Ì½¹•Ñİ½É¬µ¡…É‘•¹¥¹œ)€()/ÅÍ„­Õ±±…»Å´‘—}§}­•¹¥¹¤Ñ…»Åµ±…çÅ¸è()‰…Í )%M}9Pô½ÕÍÈ½±½…°½±¥‰•á•Œ½…•¥Ì½¹•Ñİ½É¬µ¡…É‘•¹¥¹œ½…•¥Ìµ¹•Ñİ½É¬¹Í )€()-ÕÉÕ±Ô­½Áå…çÄ­½¹ÑÉ½°•‘¥¸è()‰…Í (½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÙ•É¥™äµ¥¹ÍÑ…±°)€((ŒŒŒ€Ì¸ƒÁ±¬­Õ±±…»Å´()A±…»ÄŸÙËñ¸è()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÁ±…¸)€()M—¥±•¸‰‡}±…¹ÓÅçÄ°¥¡…ëÄ°é½¹”±…ËÄÙ”Á±…¸¡…Í ¥¹¤½­ÕåÕ¸¸()A±…¸‘¿}ÉÕåÍ„è()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9Pˆ…ÁÁ±ä)€()M½¹É„è()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÙ•É¥™ä)€()	¥È­•èÉ•‰½½Ğ•‘¥¸Ù”Ù•É¥™å€­½µÕÑÕ¹ÔÑ•­É…Èƒ…³Ç}ÓÅËÅ¸¸((ŒŒŒ€Ğ¸ñ¹³ñ¬­Õ±±…»Å´()!•ÈŸñ¸­½µÕĞƒ…³Ç}ÓÅÉµ…»Åè•É•­µ•è¸()…å‘…³Ä­½¹ÑÉ½±±•Èè()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÙ•É¥™ä)ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÍÑ…ÑÕÌ)€()M¥ÍÑ•´é…Ñ•¸‘¿}ÉÕåÍ„¥­¥¹¤…ÁÁ±å€9<µ=A€Ù•Éµ•±¥‘¥È¸((ŒŒŒ€Ô¸-½µÕÑ±…È((´Ù•É¥™äµ¥¹ÍÑ…±±€ƒŠP­ÕÉÕ±ÔÍÉ¥ÁĞ­½Áå…ÏÅ»Ä‘¿}ÉÕ±…È¸(´…Õ‘¥Ñ€ƒŠPÍ…±Ğ½­Õ¹ÕÈ¹•Ñİ½É¬½™¥É•İ…±°¥¹•±•µ•Í¤¸(´Á±…¹€ƒŠP¹”‘—}§}•—}¥¹¤ŸÙÍÑ•É¥È¸(´…ÁÁ±å€ƒŠP¥¹•±•¹•¸¹•Ñİ½É¬Á½±¥Ñ¥­…ÏÅ»ÄÕåÕ±…È¸(´Ù•É¥™å€ƒŠPé½¹”°ÁÉ½™¥°‰‡Ä°¹™Ñ…‰±•Ì­…ÃÅÏÄÙ”ÍåÍÑ°±•É¤‘¿}ÉÕ±…È¸(´ÍÑ…ÑÕÍ€ƒŠPçÙ¹•Ñ¥±•¸µ•ÙÕĞ‘ÕÉÕµÔŸÙÍÑ•É¥È¸(´¡¥ÍÑ½Éå€ƒŠPÑÉ…¹Í…Ñ¥½¸­…çÅÑ±…ËÅ»Ä±¥ÍÑ•±•È¸(´É½±±‰…¬mQa}%u€ƒŠPƒÙ¹•­¤ÑÉ…¹Í…Ñ¥½¸ŸÄ•É¤…³ÅÈ¸(´Á…­…•Í€ƒŠP•É•­±¤½½ÁÍ¥å½¹•°…É‡±…ËÄŸÙÍÑ•É¥È¸(´•áÁ½ÉÑ€ƒŠPƒÙé•°‰¥È…Õ‘¥ĞÉ…Á½ÉÔƒñÉ•Ñ¥È¸((ŒŒŒ€Ø¸M½ÉÕ¸½±ÕÉÍ„()Á±…¹€½­•ÈŸÅ¸…­Ñ¥˜½±‘×}Õ¹ÔÏÙå³ñå½ÉÍ„½­•ÈŸÄ‘ÕÉ‘ÕÉÕ¸Ù•å„…åËÄ½­•Èµ¥Í½±…Ñ¥½¸­…Ñµ…»Å»Ä‰•­±•å¥¸¸	ÔŸñÙ•¹±¥¬­½¹ÑÉ½³ñ»ğ…Ñ±…µ…çÅ¸¸()	¥É‘•¸™…é±„™¥é¥­Í•°‰‡}±…¹ÓÄ…­Ñ¥™Í”è()‰…Í )¹µ±¤€µĞ€µ˜95±UU%±QeA±Y%p(€½¹¹•Ñ¥½¸Í¡½Ü€´µ…Ñ¥Ù”)€()¿}ÉÔUU%å¤Í—¥¸è()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÁ±…¸p(€€´µ½¹¹•Ñ¥½¸µÕÕ¥e=UI}UU%)€()I•½Ù•Éä§¥¸è()‰…Í )ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9Pˆ¡¥ÍÑ½Éä)ÍÕ‘¼€½ÕÍÈ½‰¥¸½‰…Í €µÀ€´´€ˆ‘%M}9PˆÉ½±±‰…¬Qa}%)€()­Ñ¥˜ÑÉ…¹Í…Ñ¥½¸Ù…É­•¸%L™¥É•İ…±±é½¹”±…ËÅ»Ä•±±”Í¥±µ•å¥¸¸((ø	Ô­…Ñµ…¸Í—¥±¤¥¹‰½Õ¹Í…±“ÅËÄçñé•å±•É¥¹¤…é…±ÓÅÈ¸UåÕ±…µ„Í•Ù¥å•Í¥¹‘”½ÕÑ‰½Õ¹…±±½İ±¥ÍĞ½±×}ÑÕÉµ…è¸(