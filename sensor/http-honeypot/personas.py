"""Fake product responses. Each route returns just enough to look like a live,
vulnerable target so automated exploit chains continue to their payload stage."""
import re

from aiohttp import web



def page(title: str, body: str, status: int = 200, **headers) -> web.Response:
    return web.Response(text=f"<!DOCTYPE html><html><head><title>{title}</title></head><body>{body}</body></html>",
                        status=status, content_type="text/html", charset="utf-8", headers=headers)


def text(body: str, status: int = 200, ctype: str = "text/plain", **headers) -> web.Response:
    return web.Response(text=body, status=status, content_type=ctype, headers=headers)


def login_form(title: str, action: str, user: str = "username", pw: str = "password") -> str:
    return (f'<form method="post" action="{action}"><h2>{title}</h2>'
            f'<input name="{user}" placeholder="Username"><input name="{pw}" type="password">'
            '<button type="submit">Log in</button></form>')


FAKE_ENV = """APP_NAME=portal
APP_ENV=production
APP_KEY=base64:q3V5ZmR3a2xqc2RmOTgzNDI3ODk0MjM3OGRmc2Q=
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=10.0.12.4
DB_PORT=3306
DB_DATABASE=portal_prod
DB_USERNAME=portal
DB_PASSWORD=Pr0d!portal#2024
MAIL_HOST=smtp.mailgun.org
MAIL_USERNAME=postmaster@mg.portal.local
MAIL_PASSWORD=8c1f0e9d2b7a4c3e6f5d0a9b8c7d6e5f-1a2b3c4d
AWS_ACCESS_KEY_ID=AKIA4XQ7EXAMPLE3MPL
AWS_SECRET_ACCESS_KEY=Zt9wQ2EXAMPLEKEYb7Xr4Lm1Nq8Vc3Hs6Jd0Pf5
AWS_DEFAULT_REGION=us-east-1
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://deploy:ghp_EXAMPLEo1Xk9Qz7TfR3bW2nL5mV8cY4dH6@github.com/portal-corp/portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""


def wordpress_login(req, body):
    if req.method == "POST":
        return page("Log In &lsaquo; Portal &#8212; WordPress",
                    '<div id="login_error"><strong>Error:</strong> The password you entered is incorrect.</div>'
                    + login_form("Portal", "/wp-login.php", "log", "pwd"))
    return page("Log In &lsaquo; Portal &#8212; WordPress", login_form("Portal", "/wp-login.php", "log", "pwd"))


def xmlrpc(req, body):
    if req.method != "POST":
        return text("XML-RPC server accepts POST requests only.", 405)
    fault = ('<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct>'
             '<member><name>faultCode</name><value><int>403</int></value></member>'
             '<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>'
             '</struct></value></fault></methodResponse>')
    return text(fault, ctype="text/xml")


def tomcat_manager(req, body):
    return text("<html><body><h1>401 Unauthorized</h1></body></html>", 401, "text/html",
                **{"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'})


def fortigate(req, body):
    if "fgt_lang" in req.raw_path:
        return text("var fgt_lang = {};", ctype="application/javascript")
    return page("FortiGate", login_form("FortiGate SSL VPN", "/remote/logincheck"),
                **{"Set-Cookie": "SVPNCOOKIE=; path=/; secure; httponly"})


def globalprotect(req, body):
    if req.raw_path.startswith("/ssl-vpn/hipreport.esp"):
        return text("<response status=\"success\"/>", ctype="application/xml")
    return page("GlobalProtect Portal", login_form("GlobalProtect Portal", "/global-protect/login.esp", "user", "passwd"))


def ivanti(req, body):
    if "/api/v1/" in req.raw_path:
        return web.json_response({"result": "ok"})
    return page("Ivanti Connect Secure", login_form("Ivanti Connect Secure", "/dana-na/auth/url_default/login.cgi"))


def citrix(req, body):
    if "openid-configuration" in req.raw_path:
        return web.json_response({"issuer": "https://gateway.local", "authorization_endpoint": "https://gateway.local/oauth/idp/login"})
    return page("Citrix Gateway", login_form("Citrix Gateway", "/cgi/login", "login", "passwd"))


def router_soap(req, body):
    return text('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                '<s:Body><u:UpgradeResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"/>'
                '</s:Body></s:Envelope>', ctype="text/xml")


def gpon(req, body):
    return page("GPON Home Gateway", "<script>top.location='/login.html'</script>")


def router_login(req, body):
    return page("Router", login_form("Wireless Router", "/goform/login"))


def hikvision(req, body):
    return text('<?xml version="1.0" encoding="UTF-8"?><ResponseStatus version="1.0"><statusCode>1</statusCode>'
                "<statusString>OK</statusString></ResponseStatus>", ctype="application/xml")


def phpmyadmin(req, body):
    return page("phpMyAdmin", login_form("Welcome to phpMyAdmin", "index.php", "pma_username", "pma_password"),
                **{"Set-Cookie": "phpMyAdmin=4f1c9b2e8d; path=/phpmyadmin/; HttpOnly"})


def spring_actuator(req, body):
    if req.raw_path.startswith("/actuator/env"):
        return web.json_response({"activeProfiles": ["prod"], "propertySources": [
            {"name": "systemEnvironment", "properties": {"SPRING_DATASOURCE_PASSWORD": {"value": "******"}}}]})
    return web.json_response({"status": "UP"})


def exchange(req, body):
    return page("Outlook", login_form("Outlook Web App", "/owa/auth.owa"), **{"X-OWA-Version": "15.1.2375.7"})


def php_ok(req, body):
    return text("", 200, "text/html")


ROUTES = [
    (re.compile(r"^/\.env(\.\w+)?(\?|$)"), "env-leak", lambda r, b: text(FAKE_ENV)),
    (re.compile(r"^/\.git/config"), "git-leak", lambda r, b: text(FAKE_GIT_CONFIG)),
    (re.compile(r"^/\.git/HEAD"), "git-leak", lambda r, b: text("ref: refs/heads/main\n")),
    (re.compile(r"^/(wp-login\.php|wp-admin)"), "wordpress", wordpress_login),
    (re.compile(r"^/xmlrpc\.php"), "wordpress", xmlrpc),
    (re.compile(r"^/manager/(html|text)"), "tomcat", tomcat_manager),
    (re.compile(r"^/remote/"), "fortigate", fortigate),
    (re.compile(r"^/(global-protect|ssl-vpn)/"), "globalprotect", globalprotect),
    (re.compile(r"^/(dana-na|dana|api/v1/)"), "ivanti", ivanti),
    (re.compile(r"^/(vpn|vpns|oauth/idp|cgi/login|logon/LogonPoint)"), "citrix", citrix),
    (re.compile(r"^/(ctrlt/|picsdesc\.xml|wanipcn\.xml|upnp/)", re.I), "router-upnp", router_soap),
    (re.compile(r"^/GponForm/", re.I), "gpon", gpon),
    (re.compile(r"^/(boaform|goform|cgi-bin/luci|cgi-bin/mainfunction\.cgi|HNAP1)", re.I), "router", router_login),
    (re.compile(r"^/(SDK|ISAPI)/", re.I), "hikvision", hikvision),
    (re.compile(r"^/(phpmyadmin|pma|myadmin)", re.I), "phpmyadmin", phpmyadmin),
    (re.compile(r"^/actuator"), "spring", spring_actuator),
    (re.compile(r"^/(owa|ecp|autodiscover)", re.I), "exchange", exchange),
    (re.compile(r"eval-stdin\.php|\.php(\?|$)"), "php", php_ok),
]


def default_page(req, body) -> web.Response:
    if req.raw_path in ("/", "/index.html") or req.raw_path.startswith("/?"):
        return page("Portal", "<h1>It works!</h1>")
    return page("404 Not Found", "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>", 404)
