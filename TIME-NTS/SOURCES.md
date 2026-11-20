# Official technical references

The first table is retained from the rc2 review; rc3-specific references follow below. These external references explain protocol/tool behavior. They do **not** certify this script, the user's installation, a live public endpoint or the supplied V38 claims. URLs were consulted during this review; public endpoint reachability was not tested.

| Reference | Used for |
|---|---|
| [IETF RFC 8915](https://www.rfc-editor.org/rfc/rfc8915.html) | NTS key establishment versus authenticated NTP; security assumptions and delay/availability limits. |
| [Chrony 4.8 chrony.conf](https://chrony-project.org/doc/4.8/chrony.conf.html) | Source directives, authselectmode, minsources, sourcedir, port and certificate-time policy. |
| [Chrony 4.8 chronyc](https://chrony-project.org/doc/4.8/chronyc.html) | Local socket, -u root, numeric/CSV/original names, sources/authdata/ntpdata/tracking. |
| [Chrony 4.7 chronyd](https://chrony-project.org/doc/4.7/chronyd.html) | Parse-and-print -p behavior; distinction from time-setting execution. Installed parser still needs native validation. |
| [Chrony 4.7 chrony.conf](https://chrony-project.org/doc/4.7/chrony.conf.html) | NTS cookie/key dump persistence; /var/lib/chrony is not an implicit ntscookies subdirectory. |
| [Chrony FAQ](https://chrony-project.org/faq.html) | NTS bootstrap, wrong clocks and RTC/normal system operation. |
| [Cloudflare NTS](https://developers.cloudflare.com/time-services/nts/) | Official time.cloudflare.com NTS service information. |
| [Netnod: how to use NTS](https://www.netnod.se/netnod-time/how-to-use-nts) | NTS client configuration; TCP 4460 and UDP 4123 requirement. |
| [PTB: time dissemination via the Internet](https://www.ptb.de/cms/en/ptb/fachabteilungen/abt4/fb-44/ag-442/dissemination-of-legal-time/time-dissemination-via-the-internet.html) | Official PTB time service context. Retrieved material did not suffice to certify current NTS for the retained ptbtime1.ptb.de endpoint. |
| [Fedora 44 Chrony package](https://packages.fedoraproject.org/pkgs/chrony/chrony/fedora-44.html) | Installed file locations and privilege-drop packaging context; not a claim about the user's installed version. |
| [GNU coreutils: sync](https://www.gnu.org/s/coreutils/manual/html_node/sync-invocation.html) | sync with pathname operands versus filesystem-wide -f. |
| [GNU Bash manual](https://www.gnu.org/software/bash/manual/bash.html) | Startup -p, exec -c, traps, errexit context and redirection. |
| [Upstream chrony client.c](https://github.com/mlichvar/chrony/blob/master/client.c) | Source report formatting cross-check; CSV keeps source mode/state as separate fields, reachability is octal. Master is not the user's installed binary. |
| [Upstream chronyc simulation test](https://github.com/mlichvar/chrony/blob/master/test/simulation/110-chronyc) | Report structure cross-check; these upstream tests were read, not executed here. |

No source text has been copied into the program as third-party implementation. The package's tests and policy decisions are its own review artifacts. Changes to the repository's licence are not part of this deliverable.

## rc3 Fedora service drop-in review (2026-10-25)

- [Fedora 44 systemd file list](https://packages.fedoraproject.org/pkgs/systemd/systemd/fedora-44.html): distribution package includes the global `service.d/10-timeout-abort.conf` file. The listed build does not establish the installed version on a particular machine.
- [Fedora Shorter Shutdown Timer](https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer): origin and purpose of `TimeoutStopFailureMode=abort`.
- [systemd.syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html): comment lines, whitespace, continuation and repeated assignment semantics. rc3 accepts only a documented narrow subset.
- [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html): unit load paths and global/type-specific drop-ins.
- [RPM manual](https://rpm.org/docs/4.20.x/man/rpm.8): file-owner package selection and read-only verification with `--noscripts --nodeps`. Verification compares installed files against the local RPM database, not an independent attestation of the host.

The target-machine user supplied package ownership, unit contents and an RPM verification exit code of zero before this revision. No local IP address, boot identifier or machine identity is included in the public evidence. The offline tests remain separate from native Fedora integration and live NTS evidence.
