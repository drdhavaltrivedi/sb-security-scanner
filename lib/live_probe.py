#!/usr/bin/env python3
"""
Service Buddy - live (black-box) security probe. PASSIVE AND READ-ONLY.

This never attempts to break in, inject, brute-force, or forge anything. It
makes ordinary, well-formed HTTP requests and inspects the responses - the same
traffic a normal browser makes - so it is safe to run against production.

Checks:
  * security headers on the web app and API (CSP, HSTS, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
  * HTTP->HTTPS redirect; legacy TLS 1.0/1.1 offered (handshake only)
  * public source maps (full source code exposure)
  * common sensitive paths served (.env, .git, swagger/openapi, bull-board,
    /metrics, /health verbosity) - GET only, nothing modified
  * CORS policy (does the API reflect an arbitrary Origin / allow credentials)
  * framework/version disclosure (X-Powered-By, Server)
  * login user-enumeration and password-policy, via ONE well-formed request for
    a clearly fake, non-existent account (no brute force, no real user touched)
  * if AUTH_TOKEN is supplied by the user, decode-only analysis of their own JWT
    (expiry, alg, sensitive claims) - no forging, no tampering

Env: APP_URL, API_URL, SIGNIN_PATH (default /user/signin), AUTH_TOKEN, OUT_DIR
Usage: python3 -I live_probe.py <findings.tsv>
"""
import base64
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

FAKE_EMAIL = "sb-security-probe-no-such-user@example.invalid"
UA = "ServiceBuddy-SecurityScan/1.0 (authorized passive assessment)"
rows = []


def add(sev, fid, title, loc, snip=""):
    rows.append((sev, fid, title, loc, re.sub(r"\s+", " ", str(snip))[:180]))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


def req(method, url, headers=None, body=None, timeout=15):
    h = {"User-Agent": UA}
    h.update(headers or {})
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        resp = OPENER.open(r, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(400000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(400000)
    except Exception as e:
        return 0, {}, str(e).encode()


def get_json(url, obj, headers=None):
    """Single well-formed request; used only for the fake-account semantics check."""
    hh = {"Content-Type": "application/json"}
    hh.update(headers or {})
    return req("POST", url, hh, json.dumps(obj))


def is_prod(url):
    host = urllib.parse.urlparse(url).hostname or ""
    return not re.search(r"(staging|stage|\bdev\b|test|qa|sandbox|preview|localhost|127\.0\.0\.1)", host)


# ------------------------------------------------------------------ headers / transport
def headers_check(name, url, api=False):
    st, h, _ = req("GET", url + "/")
    if st == 0:
        add("LOW", "LV-UNREACHABLE", f"{name} not reachable", url)
        return
    need = {"strict-transport-security": "MEDIUM", "x-content-type-options": "MEDIUM", "referrer-policy": "LOW"}
    if not api:
        need.update({"content-security-policy": "MEDIUM", "x-frame-options": "MEDIUM", "permissions-policy": "LOW"})
    for k, sev in need.items():
        if k == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if k not in h:
            add(sev, f"LV-HDR-{k}", f"{name} is missing the {k} header", url)
    hsts = h.get("strict-transport-security", "")
    m = re.search(r"max-age=(\d+)", hsts)
    if m and int(m.group(1)) < 15552000:
        add("LOW", "LV-HSTSSHORT", f"{name} HSTS max-age is under 180 days", url, hsts)
    if "x-powered-by" in h:
        add("LOW", "LV-XPB", f"{name} discloses its framework (X-Powered-By)", url, h["x-powered-by"])
    if re.search(r"\d", h.get("server", "")):
        add("LOW", "LV-SERVERVER", f"{name} discloses its server version (Server header)", url, h["server"])


def https_redirect(name, url):
    host = urllib.parse.urlparse(url).hostname
    st, h, _ = req("GET", f"http://{host}/")
    if st == 0:
        return
    if not (300 <= st < 400 and h.get("location", "").startswith("https://")):
        add("MEDIUM", "LV-NOHTTPS", f"{name} answers plain HTTP without redirecting to HTTPS", f"http://{host}/", f"HTTP {st}")


def legacy_tls(name, url):
    import warnings
    host = urllib.parse.urlparse(url).hostname
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            versions = ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1"))
        except Exception:
            return
        for ver, label in versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                try:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((host, 443), timeout=8) as s:
                    with ctx.wrap_socket(s, server_hostname=host):
                        add("MEDIUM", "LV-OLDTLS", f"{name} accepts {label} - set the CloudFront/ALB security policy to TLSv1.2_2021", host, label)
            except Exception:
                pass  # refused (good) or local OpenSSL cannot offer it - inconclusive, stay quiet


# ------------------------------------------------------------------ exposure (GET only)
def source_maps(app):
    _, _, body = req("GET", app + "/")
    html = body.decode("utf-8", "replace")
    for a in sorted(set(re.findall(r'(?:src|href)="(/[^"]+\.js)"', html)))[:6]:
        st, _, b = req("GET", app + a + ".map")
        if st == 200 and b[:1] == b"{":
            add("HIGH", "LV-MAP", "Source map is publicly downloadable - full original source code is exposed", app + a + ".map", f"{len(b)} bytes")
    return html


EXPOSED = [
    ("/.env", "HIGH", r"[A-Z_]+="), ("/.git/config", "HIGH", r"\[core\]"), ("/.git/HEAD", "HIGH", r"ref:"),
    ("/.npmrc", "HIGH", r"_auth|registry"), ("/swagger", "MEDIUM", r"swagger"), ("/api-docs", "MEDIUM", r"swagger|openapi"),
    ("/api-json", "MEDIUM", r"openapi|swagger"), ("/docs", "MEDIUM", r"swagger|openapi|redoc"),
    ("/swagger-ui.html", "MEDIUM", r"swagger"), ("/graphql", "MEDIUM", r"graphql|__schema"), ("/metrics", "MEDIUM", r"process_cpu|nodejs_"),
    ("/admin/queues", "HIGH", r"bull|queue"), ("/queues", "HIGH", r"bull|queue"), ("/bull-board", "HIGH", r"bull|queue"),
    ("/health", "LOW", r"mongo|database|memory|version"), ("/status", "LOW", r"uptime|version|memory"),
    ("/uploads/", "MEDIUM", r"Index of|\.pdf|\.png"), ("/.DS_Store", "LOW", r"Bud1"),
]


def exposed_files(name, base, spa_html=None):
    for path, sev, rx in EXPOSED:
        st, _, b = req("GET", base + path)
        if st != 200:
            continue
        txt = b[:20000].decode("utf-8", "replace")
        if spa_html and txt.strip()[:300] == spa_html.strip()[:300]:
            continue  # SPA fallback page, not the real file
        if re.search(rx, txt, re.I):
            add(sev, "LV-EXPOSED", f"{name} serves {path}", base + path, txt[:100])


def cors(name, api):
    # A well-formed CORS preflight - the same request a browser sends. Read-only.
    for origin in ("https://evil.example", "null"):
        st, h, _ = req("OPTIONS", api + "/", {"Origin": origin, "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": "authorization,content-type"})
        aco = h.get("access-control-allow-origin", "")
        acc = h.get("access-control-allow-credentials", "")
        if aco == origin and acc.lower() == "true":
            add("HIGH", "LV-CORSCRED", f"{name} reflects the request Origin WITH credentials - any website can make authenticated calls on a user's behalf", api, f"{aco} / credentials {acc}")
            return
        if aco in ("*", origin):
            add("MEDIUM", "LV-CORS", f"{name} CORS accepts arbitrary origins ({aco})", api, f"Origin: {origin}")
            return


def login_semantics(name, api, signin):
    # ONE well-formed request for a clearly fake, non-existent account. No brute
    # force, no real user, nothing changed - just reads how the API answers.
    st, _, b = get_json(api + signin, {"email": FAKE_EMAIL, "password": "Probe-Password-123!"})
    t = b.decode("utf-8", "replace")
    if st == 404 or re.search(r"(don.?t have an account|not found|no user|not registered|does not exist|please sign ?up)", t, re.I):
        add("MEDIUM", "LV-ENUM", f"{name} login response reveals whether an email is registered (different answer for unknown vs known accounts)", api + signin, f"HTTP {st}: {t[:120]}")
    m = re.search(r"longer than or equal to (\d+)", t)
    if m and int(m.group(1)) < 8:
        add("MEDIUM", "LV-PWPOLICY", f"{name} password minimum length is {m.group(1)} characters (OWASP/NIST recommend 8+ and a breached-password check)", api + signin, t[:120])


def _b64d(s):
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def jwt_analysis(token):
    # Decode-only inspection of a token the USER chose to provide. Never forged
    # or replayed - just base64-decoded and its claims examined.
    try:
        h, p, _ = token.split(".")
        hdr, pl = _b64d(h), _b64d(p)
    except Exception:
        add("LOW", "LV-JWTPARSE", "AUTH_TOKEN was provided but is not a readable JWT - skipped token analysis", "AUTH_TOKEN")
        return
    if str(hdr.get("alg", "")).lower() == "none":
        add("HIGH", "LV-JWTNONE", "The issued access token uses the 'none' algorithm (unsigned)", "AUTH_TOKEN", json.dumps(hdr))
    if "exp" not in pl:
        add("HIGH", "LV-JWTNOEXP", "The issued access token has no expiry (exp) claim", "AUTH_TOKEN", ",".join(pl))
    elif "iat" in pl and pl["exp"] - pl["iat"] > 86400:
        days = (pl["exp"] - pl["iat"]) / 86400
        add("MEDIUM", "LV-JWTLONG", f"Access-token lifetime is {days:.1f} days - prefer 15-60 min with a refresh token", "AUTH_TOKEN", "")
    bad = [k for k in pl if re.search(r"pass|hash|secret|otp|card|ssn|account.?num", k, re.I)]
    if bad:
        add("HIGH", "LV-JWTCLAIMS", "The token payload carries sensitive claims, readable by anyone who holds it", "AUTH_TOKEN", ",".join(bad))


def main():
    out = sys.argv[1]
    app = os.environ.get("APP_URL", "").rstrip("/")
    api = os.environ.get("API_URL", "").rstrip("/")
    signin = os.environ.get("SIGNIN_PATH", "/user/signin")
    token = os.environ.get("AUTH_TOKEN", "")
    if app:
        note = "production" if is_prod(app) else "non-production"
        print(f"  live probe (passive, read-only) on web app [{note}]: {app}")
        headers_check("Web app", app, api=False)
        https_redirect("Web app", app)
        legacy_tls("Web app", app)
        html = source_maps(app)
        exposed_files("Web app", app, spa_html=html)
    if api:
        print(f"  live probe (passive, read-only) on API: {api}")
        headers_check("API", api, api=True)
        https_redirect("API", api)
        legacy_tls("API", api)
        exposed_files("API", api)
        cors("API", api)
        login_semantics("API", api, signin)
    if token:
        jwt_analysis(token)
    with open(out, "a", encoding="utf-8") as fh:
        for r in rows:
            fh.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in r) + "\n")
    print(f"  live probe: {len(rows)} findings")


if __name__ == "__main__":
    main()
