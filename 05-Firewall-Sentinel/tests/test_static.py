from pathlib import Path
import importlib.util, sys, re, ast
P=Path(__file__).resolve().parents[1] / 'aegis-firewall-sentinel.py'
src=P.read_text()
ast.parse(src)
spec=importlib.util.spec_from_file_location('aegis',P); m=importlib.util.module_from_spec(spec); sys.modules['aegis']=m; spec.loader.exec_module(m)

def need(c,msg):
    if not c: raise AssertionError(msg)
need(m.VERSION=='0.9.0-alpha2-review5','version')
need(m.NFLOG_RATE==5 and m.NFLOG_BURST==20,'nflog bounds')
need('Requires=aegis-firewall-sentinel.service' not in m.networkmanager_dropin_text().decode(),'NM Requires returned')
need('trust-sync --dispatcher' in m.networkmanager_dispatcher_text().decode(),'dispatcher missing')
need(all(x in m.MANAGED_PATHS for x in (m.NM_TRUST_DISPATCH,m.NM_TRUST_PRE_UP,m.NM_TRUST_PRE_DOWN)),'dispatcher not managed')
need('sync_trusted_interfaces(force_clear=True)' in src[src.index('def network_gate'):src.index('def _proc_sysctl')],'network gate does not clear trust')
need('meta l4proto ipv6-icmp' in src,'modern IPv6 L4 selector missing')
need('size 4096' in src and 'gc-interval 30s' in src,'blocklist bound missing')
need('rebind-cgroup-lan' in src and 'CGROUP_LAN_STALE' in src,'cgroup stale/rebind missing')
need('approved_foreign_hook_fingerprints' in src and 'APPROVED_FOREIGN_TABLE_DRIFT' in src,'foreign hook fingerprinting missing')
need('dot_resolver_attestation' in src and 'dot_server_name' in src,'DoT attestation missing')
need('flush ruleset' not in src,'global flush')

need('{"user", "user-early", "user-light", "user-early-light"}' in src,'modern interactive session classes missing')
need('_sudo_invoker_audit_sessions' in src and 'SUDO_UID' in src and 'SUDO_TTY' in src,'sudo ancestor session binding missing')
need('props.get("Audit") not in invoker_audits' in src,'logind session not bound to sudo ancestor audit')
need('["--permanent", "--get-default-zone"]' not in src,'invalid permanent default-zone query remains')
# Rate limit must be on a separate non-terminal rule.
pair=m._logged_verdict('tcp dport 1','x','drop').splitlines()
need(len(pair)==2,'logged verdict not two rules')
need('limit rate 5/second burst 20 packets log ' in pair[0] and ' drop' not in pair[0],'telemetry line wrong')
need('counter drop comment "x"' in pair[1] and 'limit rate' not in pair[1],'enforcement rate limited')
# Baseline and feature renders.
u='11111111-2222-4333-8444-555555555555'
def policy(**kw):
    q=kw.pop('quarantine',False); smb=kw.pop('allow_lan_smb',False); ssdp=kw.pop('allow_lan_ssdp',False)
    old=m.resolve_dot_uid; m.resolve_dot_uid=lambda: 999
    try: return m.render_policy(['wlan0'],q,trusted_connection_uuids=[u],allow_lan_smb=smb,allow_lan_ssdp=ssdp,**kw)
    finally: m.resolve_dot_uid=old
base=policy(); txt=m.render_nft(base).decode()
need('elements = {' not in txt.split('set trusted_ifaces',1)[1].split('}',1)[0],'trusted set statically populated')
need('limit rate 5/second burst 20 packets log prefix "aegis:block-llmnr-tcp ' in txt,'NFLOG rate missing')
need('\n        tcp dport 5355 counter reject with tcp reset comment "aegis:block-llmnr-tcp"' in txt,'unconditional drop missing')
# Count generated chain rules matches semantic formulas.
def count(text,ch):
    mm=re.search(r'chain '+re.escape(ch)+r' \{\n(.*?)\n    \}',text,re.S)
    if not mm: return None
    return len([l for l in mm.group(1).splitlines() if l.strip() and not l.strip().startswith(('type ','comment '))])
need(count(txt,'egress_guard')==17 and count(txt,'output_guard')==1,'baseline rule counts')
allp=policy(quarantine=True,allow_lan_smb=True,allow_lan_ssdp=True,strict_dot_resolver=True,dot_servers=['9.9.9.9','2620:fe::fe'],dot_server_name='dns.quad9.net',vpn_killswitch={'enabled':True,'interface':'tun0','endpoints':[{'ip':'1.2.3.4','family':4,'port':1194,'proto':'udp'}],'allow_lan':True})
allt=m.render_nft(allp).decode()
need(count(allt,'egress_guard')==28,'all feature egress count')
need(count(allt,'vpn_killswitch')==10,'vpn count')
need(count(allt,'quarantine_in')==3 and count(allt,'quarantine_out')==3 and count(allt,'quarantine_forward')==2,'quarantine counts')
# Parser/CLI additions.
args=m.parse_args(['plan','--dot-server-name','dns.quad9.net'])
need(args.dot_server_name=='dns.quad9.net','dot SNI CLI')
need(m.parse_args(['rebind-cgroup-lan']).command=='rebind-cgroup-lan','rebind CLI')
print('REVIEW5_STATIC_SECURITY_TESTS_PASS')
