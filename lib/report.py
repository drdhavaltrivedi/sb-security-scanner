#!/usr/bin/env python3
"""Turn findings.tsv + gates.tsv into a self-contained HTML report and a SARIF
file (for GitHub code scanning). Reads config from environment set by the
shell script. No third-party dependencies."""
import csv
import html
import json
import os
import re
import time

OUT = os.environ["OUT_DIR"]
FINDINGS = os.environ["FINDINGS"]
GATES = os.environ["GATES_TSV"]
ROUTES = os.environ.get("ROUTES_CSV", "")
TARGET = os.environ.get("TARGET", "")
PATHS = os.environ.get("SCANPATHS", "")

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEV_COLOR = {"HIGH": "#c0392b", "MEDIUM": "#d68910", "LOW": "#7f8c8d"}
# short remediation hints keyed by finding-id prefix
HINTS = {
    "LV-MAP": "Build with sourcemap:'hidden'; exclude *.map from the S3 sync; purge existing maps + invalidate CloudFront.",
    "LV-HDR": "Add a CloudFront Response Headers Policy (web) / helmet() (API).",
    "LV-CORS": "Replace enableCors() with an env allow-list of your own domains.",
    "LV-ENUM": "Return the same 'invalid email or password' for unknown and known accounts.",
    "LV-XPB": "app.disable('x-powered-by') / helmet(); server_tokens off in nginx.",
    "ROUTE-NOAUTH": "Add @UseGuards(JwtAuthGuard) or register an APP_GUARD globally.",
    "ROUTE-IDOR": "Pass the authenticated user/company into the service and filter the query by it.",
    "ROUTE-NOROLE": "Add a @Roles()/permissions guard to this sensitive route.",
    "TENANT": "Add { companyId: user.companyId } to the query; never trust the id from the URL alone.",
    "DTO-NOVALID": "Add class-validator decorators and ValidationPipe({whitelist:true, forbidNonWhitelisted:true}).",
    "DTO-NEGATIVE": "Add @Min(0)/@IsPositive so amounts cannot go negative.",
    "DTO-PRIVFIELD": "Remove the field from the DTO; set it from the logged-in user server-side.",
    "DB-SANITIZE": "Enable mongoose sanitizeFilter / express-mongo-sanitize to strip $-operators.",
    "DB-REGEX": "Escape user input before $regex (escape-string-regexp) and anchor it.",
    "SCHEMA-CARD": "Never store PAN/CVV; keep only provider tokens + last4 (PCI DSS).",
    "SCHEMA-TOKEN": "Hash reset/OTP tokens with an expiry; encrypt OAuth tokens at rest.",
    "AUTH-GOOGLE": "Verify the Google ID token with OAuth2Client.verifyIdToken({ audience: CLIENT_ID }).",
    "AUTH-REVOKE": "Add tokenVersion/passwordChangedAt so logout and password change invalidate old JWTs.",
    "WEBHOOK-RAWBODY": "Create the app with { rawBody:true } and verify the provider signature on the raw body.",
    "PAY-AMOUNT": "Recompute the charge amount from the invoice in the DB; ignore any client amount.",
    "IN-DBPORT": "Bind the DB port to 127.0.0.1 or drop the host port mapping.",
    "FE-DOM": "Sanitize with DOMPurify, or use DOMParser/textContent for text-only helpers.",
    "FE-TOKEN": "Move the session to an HttpOnly, Secure, SameSite cookie set by the API.",
    "DEP-": "Upgrade the package to the fixed version (see the advisory text).",
}


def hint(fid):
    for k, v in HINTS.items():
        if fid.startswith(k):
            return v
    return ""


def load_findings():
    rows = []
    if os.path.exists(FINDINGS):
        with open(FINDINGS, encoding="utf-8", errors="replace") as f:
            seen = set()
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 4:
                    continue
                sev, fid, title, loc = p[0], p[1], p[2], p[3]
                snip = p[4] if len(p) > 4 else ""
                if sev not in SEV_ORDER:
                    continue
                key = (sev, fid, loc, snip)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(dict(sev=sev, id=fid, title=title, loc=loc, snip=snip))
    rows.sort(key=lambda r: (SEV_ORDER[r["sev"]], r["id"], r["loc"]))
    return rows


def load_gates():
    g = []
    if os.path.exists(GATES):
        for p in csv.reader(open(GATES, encoding="utf-8"), delimiter="\t"):
            if len(p) >= 6:
                g.append(p)
    return g


def sarif(rows):
    results, rules, ruleidx = [], [], {}
    lvl = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    for r in rows:
        if r["id"] not in ruleidx:
            ruleidx[r["id"]] = len(rules)
            rules.append({"id": r["id"], "name": r["id"],
                          "shortDescription": {"text": r["title"][:120]},
                          "defaultConfiguration": {"level": lvl[r["sev"]]}})
        m = re.match(r"(.+?):(\d+)$", r["loc"])
        loc_file, line = (m.group(1), int(m.group(2))) if m else (r["loc"], 1)
        results.append({
            "ruleId": r["id"], "ruleIndex": ruleidx[r["id"]], "level": lvl[r["sev"]],
            "message": {"text": r["title"] + (" | " + r["snip"] if r["snip"] else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc_file},
                "region": {"startLine": max(1, line)}}}],
        })
    doc = {"version": "2.1.0",
           "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "sb-security-scan", "informationUri": "https://servicebuddy.io",
                                          "version": "1.0", "rules": rules}}, "results": results}]}
    json.dump(doc, open(os.path.join(OUT, "findings.sarif"), "w"), indent=1)


def htmlpage(rows, gates):
    nH = sum(r["sev"] == "HIGH" for r in rows)
    nM = sum(r["sev"] == "MEDIUM" for r in rows)
    nL = sum(r["sev"] == "LOW" for r in rows)
    is_prod = "staging" not in TARGET and "localhost" not in TARGET and "local code" not in TARGET
    env_badge = ("PRODUCTION" if is_prod else "non-production") if TARGET != "local code" else "static code scan"
    e = html.escape
    out = []
    out.append(f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Service Buddy Security Report</title><style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e3e3e3;--card:#fafafa}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16181c;--fg:#e8e8e8;--mut:#9aa0a6;--line:#2c2f36;--card:#1d2026}}}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}}
.wrap{{max-width:1040px;margin:0 auto;padding:24px 16px 80px}}
h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:18px;margin:34px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.sub{{color:var(--mut);font-size:13px;margin-bottom:18px}}
.badge{{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600;color:#fff}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.kpi{{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.kpi .n{{font-size:28px;font-weight:700}}.kpi .l{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
table{{width:100%;border-collapse:collapse;font-size:13.5px;margin:6px 0 10px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.03em}}
.pill{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}}
code{{background:var(--card);padding:1px 5px;border-radius:5px;font-size:12.5px;word-break:break-all}}
.gate{{font-weight:700}}.PASS{{color:#1e8449}}.WARN{{color:#d68910}}.FAIL{{color:#c0392b}}
details{{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:4px 12px}}
summary{{cursor:pointer;font-weight:600;padding:6px 0}}summary .pill{{margin-right:8px}}
.hint{{color:var(--mut);font-size:12.5px;margin:3px 0 2px}}.loc{{color:var(--mut)}}
.filter{{margin:6px 0 14px}}.filter button{{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:16px;padding:4px 12px;margin-right:6px;cursor:pointer;font-size:12px}}
.filter button.off{{opacity:.35}}
</style></head><body><div class=wrap>
<h1>Service Buddy &mdash; Security Assessment</h1>
<div class=sub>Target: <b>{e(TARGET)}</b> &nbsp;<span class=badge style="background:{'#c0392b' if is_prod else '#2874a6'}">{e(env_badge)}</span>
&nbsp;&middot;&nbsp; {time.strftime('%Y-%m-%d %H:%M')} &nbsp;&middot;&nbsp; sources: <code>{e(PATHS)}</code></div>
<div class=kpis>
<div class=kpi><div class=n style="color:{SEV_COLOR['HIGH']}">{nH}</div><div class=l>High</div></div>
<div class=kpi><div class=n style="color:{SEV_COLOR['MEDIUM']}">{nM}</div><div class=l>Medium</div></div>
<div class=kpi><div class=n style="color:{SEV_COLOR['LOW']}">{nL}</div><div class=l>Low</div></div>
<div class=kpi><div class=n>{len(rows)}</div><div class=l>Total</div></div>
</div>
<h2>Security gates</h2><table><tr><th>Gate</th><th>Area</th><th>Result</th><th>H</th><th>M</th><th>L</th></tr>""")
    for g in gates:
        out.append(f"<tr><td>{e(g[0])}</td><td>{e(g[1])}</td><td class='gate {e(g[2])}'>{e(g[2])}</td><td>{e(g[3])}</td><td>{e(g[4])}</td><td>{e(g[5])}</td></tr>")
    out.append("</table>")
    out.append("""<p class=sub>A gate fails on any High finding. Pattern and deep-scan results are heuristics &mdash;
each High/Medium should be confirmed or marked a false positive by a developer. IDOR/tenant items list every
unscoped lookup; confirm each also filters by the caller's company.</p>""")
    out.append("""<h2>Findings</h2><div class=filter>
<button data-s=HIGH onclick="t(this)">High</button><button data-s=MEDIUM onclick="t(this)">Medium</button>
<button data-s=LOW onclick="t(this)">Low</button></div><div id=list>""")
    # group by id within severity
    from itertools import groupby
    for sev in ("HIGH", "MEDIUM", "LOW"):
        srows = [r for r in rows if r["sev"] == sev]
        for fid, grp in groupby(srows, key=lambda r: r["id"]):
            grp = list(grp)
            t = grp[0]["title"]
            h = hint(fid)
            out.append(f"<details class=item data-s={sev} open><summary><span class=pill style='background:{SEV_COLOR[sev]}'>{sev}</span>"
                       f"<code>{e(fid)}</code> &nbsp;{e(t)} <span class=loc>&times;{len(grp)}</span></summary>")
            if h:
                out.append(f"<div class=hint><b>Fix:</b> {e(h)}</div>")
            out.append("<table><tr><th>Location</th><th>Detail</th></tr>")
            for r in grp[:60]:
                out.append(f"<tr><td><code>{e(r['loc'])}</code></td><td>{e(r['snip'])}</td></tr>")
            if len(grp) > 60:
                out.append(f"<tr><td colspan=2 class=loc>&hellip; {len(grp)-60} more in findings.tsv</td></tr>")
            out.append("</table></details>")
    out.append("</div>")
    # route inventory
    if ROUTES and os.path.exists(ROUTES):
        rr = list(csv.reader(open(ROUTES, encoding="utf-8")))
        if len(rr) > 1:
            out.append(f"<h2>API route inventory ({len(rr)-1})</h2>")
            out.append("<p class=sub>auth = how the route is protected; user_context = whether the handler receives the caller (needed to scope data). Rows with auth NONE or an IDOR note are in the findings above.</p>")
            out.append("<table><tr>" + "".join(f"<th>{e(c)}</th>" for c in rr[0][:8]) + "</tr>")
            def bad(row):
                return row[2] == "NONE" or "IDOR" in row[7] or "NO AUTH" in row[7]
            for row in sorted(rr[1:], key=lambda x: (0 if bad(x) else 1, x[1])):
                style = " style='background:#fbebeb33'" if bad(row) else ""
                out.append(f"<tr{style}>" + "".join(f"<td>{e(c)}</td>" for c in row[:8]) + "</tr>")
            out.append("</table>")
    # Claude Code hand-off prompt
    promptfile = os.path.join(os.path.dirname(__file__), "claude_code_prompt.md")
    if os.path.exists(promptfile):
        ptxt = open(promptfile, encoding="utf-8").read()
        out.append("<h2>Hand-off to Claude Code</h2>")
        out.append("<p class=sub>Open the API repo in Claude Code and paste this prompt. It triages every finding, verifies the backend route-by-route (auth, roles, tenant isolation, payments, QuickBooks, files, secrets) and writes <code>BACKEND_RESULTS.md</code>. Also saved as <code>CLAUDE_CODE_PROMPT.md</code> next to this report.</p>")
        out.append(f"<details><summary>Show the Claude Code prompt</summary><pre style='white-space:pre-wrap;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;font-size:12.5px'>{html.escape(ptxt)}</pre></details>")
    out.append("""<script>
function t(b){b.classList.toggle('off');var on=[].slice.call(document.querySelectorAll('.filter button')).filter(x=>!x.classList.contains('off')).map(x=>x.dataset.s);
document.querySelectorAll('.item').forEach(d=>d.style.display=on.indexOf(d.dataset.s)>=0?'':'none');}
</script></div></body></html>""")
    open(os.path.join(OUT, "REPORT.html"), "w", encoding="utf-8").write("".join(out))


def main():
    rows = load_findings()
    htmlpage(rows, load_gates())
    sarif(rows)


if __name__ == "__main__":
    main()
