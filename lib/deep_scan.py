#!/usr/bin/env python3
"""
Service Buddy - deep static analysis for NestJS 10 + Mongoose + React.

Goes beyond line-by-line grep: parses controllers, services, DTOs and schemas
across multiple lines to find
  * every HTTP route with its guards / roles / user-context  -> routes.csv
  * routes with no authentication, IDOR candidates, admin routes without roles
  * Mongo queries not scoped to the caller's company (tenant isolation)
  * DTO fields with no validation, negative money amounts, privileged fields
  * schemas storing passwords / card / bank / token data unsafely
  * auth-flow weaknesses (Google token verification, reset/OTP tokens,
    token revocation, backdoor passwords, timing-unsafe compares)
  * risky server features (headless-Chrome PDF, templates, XXE, vm2,
    WebSocket gateways, bull-board, static uploads, raw body for webhooks)
  * docker-compose databases exposed / unauthenticated
  * dependencies pinned to versions with known advisories

Usage: python3 -I deep_scan.py <findings.tsv> <routes.csv> <root> [<root>...]
Appends rows to findings.tsv: SEVERITY \t ID \t title \t file:line \t snippet
"""
import csv
import json
import os
import re
import sys

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", ".turbo",
             "vendor", "storybook-static", ".cache", "tmp"}
CODE_EXT = (".ts", ".js", ".mjs", ".cjs")
TEST_RX = re.compile(r"(\.spec\.|\.test\.|__tests__|/test/|/e2e/|/mocks?/)")

findings = []


def add(sev, fid, title, loc, snippet=""):
    snippet = re.sub(r"\s+", " ", snippet or "").strip()[:180]
    findings.append((sev, fid, title, loc, snippet))


# --------------------------------------------------------------------------- files
class Src:
    def __init__(self, root, path):
        self.root, self.path = root, path
        self.rel = os.path.basename(root) + "/" + os.path.relpath(path, root)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.text = f.read()
        except OSError:
            self.text = ""
        self._nl = None

    def line(self, pos):
        if self._nl is None:
            self._nl = [i for i, c in enumerate(self.text) if c == "\n"]
        lo, hi = 0, len(self._nl)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._nl[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    def loc(self, pos):
        return f"{self.rel}:{self.line(pos)}"

    def snippet(self, pos, n=160):
        s = self.text.rfind("\n", 0, pos) + 1
        e = self.text.find("\n", pos)
        return self.text[s:e if e != -1 else None][:n]


def walk(roots):
    out = []
    for root in roots:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
            for fn in fns:
                p = os.path.join(dp, fn)
                if fn.endswith(CODE_EXT) and not fn.endswith(".d.ts") and not TEST_RX.search(p):
                    out.append(Src(root, p))
    return out


def strip_comments(t):
    # keep offsets: replace comment chars with spaces
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    t = re.sub(r"/\*.*?\*/", blank, t, flags=re.S)
    t = re.sub(r"(?<![:'\"`])//[^\n]*", blank, t)
    return t


def match_paren(t, i, open_c="(", close_c=")"):
    """t[i] == open_c ; return index of matching close or -1 (skips strings)."""
    depth, q = 0, None
    j = i
    while j < len(t):
        c = t[j]
        if q:
            if c == "\\":
                j += 2
                continue
            if c == q:
                q = None
        elif c in "'\"`":
            q = c
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


# --------------------------------------------------------------------------- routes
HTTP_DEC = re.compile(r"@(Get|Post|Put|Patch|Delete|All|Head|Options)\(\s*(?:['\"`]([^'\"`]*)['\"`])?")
GUARD_RX = re.compile(r"@(UseGuards|Auth\w*|Roles|Role|Permissions?|RequirePermissions?|HasRoles?|Protected|Authenticated|AdminOnly|IsAdmin|JwtAuth\w*)\b")
ROLE_RX = re.compile(r"@(Roles|Role|Permissions?|RequirePermissions?|HasRoles?|AdminOnly|IsAdmin)\b|@Auth\w*\(\s*[A-Za-z\[]")
PUBLIC_RX = re.compile(r"@(Public|SkipAuth|AllowAnonymous|IsPublic|NoAuth|PublicRoute)\b|SetMetadata\(\s*['\"](isPublic|public|skipAuth)")
USERCTX_RX = re.compile(r"@(Req|Request)\(|@(CurrentUser|User|GetUser|AuthUser|ReqUser|LoggedInUser|Company|CurrentCompany|Tenant|CompanyId|UserId)\b|req\.user|request\.user|companyId|tenantId", re.I)
AUTHISH_PATH = re.compile(r"(webhook|health|ping|status|signin|sign-in|signup|sign-up|login|register|forgot|reset|verify|callback|oauth|public|portal|unsubscribe|invite|accept|confirm|token)", re.I)
ADMINISH_PATH = re.compile(r"(admin|setting|role|permission|employee|staff|payout|refund|export|import|bulk|subscription|billing|integration|quickbooks|stripe|rainforest|merchant|company|commission|payroll|delete)", re.I)
DANGER_PATH = re.compile(r"(seed|debug|/test|/dev/|internal|migrat|reset-db|run-cron|cron/run|flush|truncate|backdoor)", re.I)
METHOD_RX = re.compile(r"([A-Za-z_]\w*)\s*\(")
NON_METHOD = {"if", "for", "while", "switch", "return", "catch", "function", "constructor", "super", "await", "get", "set"}


def parse_controllers(files, has_global_guard):
    routes = []
    any_roles = False
    for f in files:
        if not re.search(r"@Controller\(", f.text):
            continue
        t = strip_comments(f.text)
        for cm in re.finditer(r"@Controller\(\s*(?:\{[^}]*path\s*:\s*)?(?:['\"`]([^'\"`]*)['\"`])?", t):
            prefix = cm.group(1) or ""
            cls = re.compile(r"export\s+(?:default\s+)?class\s+(\w+)").search(t, cm.end())
            if not cls:
                continue
            class_decos = t[max(0, t.rfind("\n\n", 0, cm.start())):cls.start()]
            # decorators directly above @Controller too
            pre = t[max(0, cm.start() - 600):cls.start()]
            class_guard = bool(GUARD_RX.search(pre))
            class_roles = bool(ROLE_RX.search(pre))
            class_public = bool(PUBLIC_RX.search(pre))
            brace = t.find("{", cls.end())
            end = match_paren(t, brace, "{", "}")
            body = t[brace:end if end > 0 else len(t)]
            base = brace
            for hm in HTTP_DEC.finditer(body):
                verb, sub = hm.group(1).upper(), hm.group(2) or ""
                # method name = first identifier( after the decorators that is not
                # itself a decorator name (@X), a member call (.x), or a keyword.
                sig = None
                for sm in METHOD_RX.finditer(body, hm.end()):
                    name = sm.group(1)
                    if name in NON_METHOD:
                        continue
                    j = sm.start() - 1
                    while j >= 0 and body[j] in " \t\n":
                        j -= 1
                    if j >= 0 and body[j] in "@.":
                        continue  # decorator name or a chained call, not the method
                    sig = sm
                    break
                if not sig:
                    continue
                prev_end = max(body.rfind("}\n", 0, hm.start()), body.rfind(";\n", 0, hm.start()), 0)
                decos = body[prev_end:sig.start()]
                pstart = sig.end() - 1
                pend = match_paren(body, pstart)
                params = body[pstart:pend + 1] if pend > 0 else ""
                bstart = body.find("{", pend if pend > 0 else sig.end())
                bend = match_paren(body, bstart, "{", "}")
                mbody = body[bstart:bend + 1] if bstart > 0 and bend > 0 else ""
                path = "/" + "/".join(p.strip("/") for p in (prefix, sub) if p.strip("/"))
                guarded = class_guard or bool(GUARD_RX.search(decos))
                roles = class_roles or bool(ROLE_RX.search(decos))
                public = class_public or bool(PUBLIC_RX.search(decos))
                any_roles = any_roles or roles
                userctx = bool(USERCTX_RX.search(params) or USERCTX_RX.search(mbody[:3000]))
                if public:
                    auth = "public"
                elif guarded:
                    auth = "guarded"
                elif has_global_guard:
                    auth = "global-guard"
                else:
                    auth = "NONE"
                bm = re.search(r"@Body\(\s*(?:['\"]\w+['\"])?\s*(?:,[^)]*)?\)\s*\w+\s*(?::\s*([\w<>\[\]{}, |]+))?", params)
                body_type = (bm.group(1) or "untyped").strip() if bm else ""
                qm = re.search(r"@Query\(\s*\)\s*\w+\s*(?::\s*([\w<>\[\]{}, |]+))?", params)
                query_type = (qm.group(1) or "untyped").strip() if qm else ""
                pos = base + hm.start()
                r = dict(method=verb, path=path, loc=f.loc(pos), auth=auth, roles="yes" if roles else "no",
                         user_context="yes" if userctx else "no", body_type=body_type, query_type=query_type,
                         notes=[])
                # ---- findings per route
                if auth == "NONE":
                    if DANGER_PATH.search(path):
                        add("HIGH", "ROUTE-DEBUG", "Debug/seed/internal route with no authentication", r["loc"], f"{verb} {path}")
                        r["notes"].append("debug route, no auth")
                    elif not AUTHISH_PATH.search(path):
                        add("HIGH", "ROUTE-NOAUTH", "Route has no guard (no class/method @UseGuards, no global APP_GUARD) - anyone can call it", r["loc"], f"{verb} {path}")
                        r["notes"].append("NO AUTH")
                elif DANGER_PATH.search(path):
                    add("MEDIUM", "ROUTE-DEBUG", "Debug/seed/internal route reachable in production - remove or restrict to admins + non-prod", r["loc"], f"{verb} {path}")
                if auth == "public" and verb in ("POST", "PUT", "PATCH", "DELETE") and not AUTHISH_PATH.search(path):
                    add("MEDIUM", "ROUTE-PUBLICWRITE", "Public route that changes data - confirm it must be anonymous and is rate limited", r["loc"], f"{verb} {path}")
                if auth != "NONE" and ":" in path and not userctx and auth != "public":
                    add("HIGH", "ROUTE-IDOR", "Route takes an id from the URL but never passes the caller (user/company) to the service - any logged-in user can likely read/modify another company's record (IDOR)", r["loc"], f"{verb} {path}")
                    r["notes"].append("IDOR candidate")
                if body_type in ("untyped", "any", "object", "{}") or body_type.startswith("Record"):
                    add("MEDIUM", "DTO-ANYBODY", "@Body() is untyped/any - ValidationPipe cannot validate it (mass assignment, operator injection)", r["loc"], f"{verb} {path} body:{body_type}")
                if query_type in ("untyped", "any", "object") or query_type.startswith("Record"):
                    add("MEDIUM", "DTO-ANYQUERY", "@Query() is untyped/any - query objects can carry Mongo operators", r["loc"], f"{verb} {path}")
                if ADMINISH_PATH.search(path) and not roles and auth in ("guarded", "global-guard"):
                    r["notes"].append("sensitive path without role check")
                routes.append(r)
    if routes and not any_roles:
        add("MEDIUM", "ROUTE-NOROLES", "No role/permission decorators on any route - every logged-in user (e.g. a technician) can call admin, settings, payout and export endpoints", "(project-wide)", f"{len(routes)} routes")
    else:
        for r in routes:
            if "sensitive path without role check" in r["notes"]:
                add("MEDIUM", "ROUTE-NOROLE", "Sensitive route without a role/permission check", r["loc"], f"{r['method']} {r['path']}")
    return routes


# --------------------------------------------------------------------------- tenant scoping
QUERY_RX = re.compile(r"this\.(\w+)\.(find|findOne|findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|exists|distinct|replaceOne)\(")
EXEMPT_MODEL = re.compile(r"^(user|users|company|companies|tenant|organi[sz]ation|plan|country|countries|state|currency|counter|migration|global|system|setting?s?Global|permission|role|lookup|timezone)", re.I)
SCOPED_RX = re.compile(r"company|tenant|organi[sz]ation|business|accountId|owner|createdBy|userId|\buser\b|\$in", re.I)


def tenant_checks(files):
    for f in files:
        if not re.search(r"(\.service|\.repository|\.controller|\.processor|\.gateway)\.(ts|js)$", f.path):
            continue
        t = strip_comments(f.text)
        for m in QUERY_RX.finditer(t):
            model, op = m.group(1), m.group(2)
            if not re.search(r"model|repo|collection", model, re.I):
                continue
            mname = re.sub(r"(Model|Repository|Repo|Collection)$", "", model)
            if EXEMPT_MODEL.match(mname):
                continue
            o = m.end() - 1
            c = match_paren(t, o)
            args = t[o + 1:c] if c > 0 else t[o + 1:o + 200]
            after = t[c:c + 600] if c > 0 else ""
            func_ctx = t[max(0, m.start() - 1500):m.start()]
            if SCOPED_RX.search(args):
                if op in ("updateMany", "deleteMany") or "company" in args.lower() or "tenant" in args.lower():
                    pass
                continue
            if op in ("findById", "findByIdAndUpdate", "findByIdAndDelete", "findByIdAndRemove"):
                if re.search(r"company|tenant|owner", after[:400], re.I):
                    continue  # ownership compared right after fetch
                add("HIGH" if op != "findById" else "MEDIUM", "TENANT-BYID",
                    f"{mname}.{op}() by id with no company/owner check - cross-company read/write (IDOR) unless verified elsewhere",
                    f.loc(m.start()), f.snippet(m.start()))
                continue
            if op in ("updateMany", "deleteMany") and (args.strip() in ("", "{}") or not SCOPED_RX.search(args)):
                add("HIGH", "TENANT-BULK", f"{mname}.{op}() not scoped to a company - can modify/delete other companies' data", f.loc(m.start()), f.snippet(m.start()))
                continue
            ident = re.fullmatch(r"\s*\{?\s*\.\.\.?(\w+)\s*\}?\s*|\s*(\w+)\s*(,.*)?", args, re.S)
            if ident and re.search(r"company|tenant|owner", func_ctx[-900:], re.I):
                continue  # filter variable built with company earlier in the function
            if op == "aggregate":
                if not re.search(r"\$match[^}]*(company|tenant)", args, re.I | re.S):
                    add("MEDIUM", "TENANT-AGG", f"{mname}.aggregate() pipeline has no $match on company first - reports/dashboards may mix companies", f.loc(m.start()), f.snippet(m.start()))
                continue
            add("MEDIUM", "TENANT-UNSCOPED", f"{mname}.{op}() filter has no company/tenant condition - verify the caller can only see their own company's data", f.loc(m.start()), f.snippet(m.start()))
        for m in re.finditer(r"\.select\(\s*['\"`][^'\"`]*\+(password|hash|salt|token|secret|otp)", t):
            add("MEDIUM", "DB-SELECTSECRET", "Query explicitly selects a hidden secret field - make sure it never reaches a response", f.loc(m.start()), f.snippet(m.start()))
        for m in re.finditer(r"\.(select|sort|populate|projection)\(\s*(req\.|query\.|dto\.|body\.|params\.|filters?\.)", t):
            add("MEDIUM", "DB-USERPROJ", f".{m.group(1)}() driven by request input - can expose hidden fields (e.g. +password) or inject operators; allow-list values", f.loc(m.start()), f.snippet(m.start()))
        for m in re.finditer(r"\.limit\(\s*(?!Math\.min)(?:Number\()?\s*(req\.|query\.|dto\.|limit\b|pageSize\b)", t):
            add("LOW", "DB-NOLIMITCAP", "Page size from request without an upper bound - a client can request millions of rows (DoS / bulk scraping)", f.loc(m.start()), f.snippet(m.start()))


# --------------------------------------------------------------------------- DTOs
VALIDATOR_RX = re.compile(r"@(Is[A-Z]\w*|Min|Max|Length|MinLength|MaxLength|Matches|ValidateNested|Equals|NotEquals|Contains|ArrayMinSize|ArrayMaxSize|ArrayNotEmpty|Allow|ValidateIf|Validate|IsDefined|Type)\b")
MONEY_RX = re.compile(r"(amount|price|total|qty|quantity|discount|tax|rate|cost|fee|tip|deposit|balance|hours|percent|commission|credit|refund|payout|subtotal)", re.I)
PRIV_FIELDS = re.compile(r"^(role|roles|isAdmin|admin|isSuperAdmin|permissions|companyId|company|tenantId|ownerId|createdBy|balance|credits|plan|subscription|isVerified|emailVerified|stripeCustomerId|stripeAccountId|merchantId|rainforestMerchantId|realmId|isDeleted|deletedAt|password Hash|passwordHash)$")
PROP_RX = re.compile(r"^\s*(?:readonly\s+)?([A-Za-z_]\w*)\s*[?!]?\s*:\s*([^;=\n]+)", re.M)


def dto_checks(files):
    for f in files:
        if not (f.path.endswith((".dto.ts", ".input.ts")) or "/dto/" in f.path or "/dtos/" in f.path):
            continue
        t = strip_comments(f.text)
        for cm in re.finditer(r"export\s+class\s+(\w+)[^{]*\{", t):
            cname = cm.group(1)
            end = match_paren(t, cm.end() - 1, "{", "}")
            body = t[cm.end():end if end > 0 else len(t)]
            off = cm.end()
            no_max = 0
            prev = 0
            for pm in PROP_RX.finditer(body):
                name, typ = pm.group(1), pm.group(2).strip()
                if name in ("constructor",) or "(" in name:
                    continue
                decos = body[prev:pm.start()]
                prev = pm.end()
                loc = f.loc(off + pm.start())
                has_val = bool(VALIDATOR_RX.search(decos))
                if not has_val:
                    add("MEDIUM", "DTO-NOVALID", f"{cname}.{name} has no class-validator decorator (@IsOptional alone validates nothing)", loc, pm.group(0).strip())
                if MONEY_RX.search(name) and re.search(r"\bnumber\b", typ) and not re.search(r"@(Min|IsPositive|IsNonNegative)\b", decos):
                    add("MEDIUM", "DTO-NEGATIVE", f"{cname}.{name} is a money/quantity field without @Min(0)/@IsPositive - negative values can flip charges, discounts or commissions", loc, pm.group(0).strip())
                if MONEY_RX.search(name) and re.search(r"\bnumber\b", typ) and not re.search(r"@Max\b", decos):
                    pass
                if PRIV_FIELDS.match(name) and re.search(r"(Create|Update|Edit|Patch|Signup|SignUp|Register|Profile|Upsert)", cname):
                    add("MEDIUM", "DTO-PRIVFIELD", f"{cname} lets the client set '{name}' - privilege escalation / cross-company assignment; derive it from the logged-in user instead", loc, pm.group(0).strip())
                if re.search(r"password", name, re.I) and not re.search(r"confirm|old|current", name, re.I):
                    ml = re.search(r"@(?:MinLength|Length)\(\s*(\d+)", decos)
                    if not ml or int(ml.group(1)) < 8:
                        add("MEDIUM", "AUTH-PWPOLICY", f"{cname}.{name}: password minimum length is {ml.group(1) if ml else 'not set'} (staging enforces 6) - require 8+ chars and check against breached passwords", loc, pm.group(0).strip())
                if "@ValidateNested" in decos and "@Type" not in decos:
                    add("MEDIUM", "DTO-NESTED", f"{cname}.{name}: @ValidateNested without @Type(() => X) - nested object is NOT validated", loc, pm.group(0).strip())
                if re.search(r"\bstring\b", typ) and not re.search(r"@(MaxLength|Length|IsEmail|IsMongoId|IsEnum|IsUUID|IsIn|Matches|IsDateString|IsISO8601|IsUrl|IsPhoneNumber)\b", decos):
                    no_max += 1
                if re.search(r"(Id|Ids)$", name) and re.search(r"string", typ) and not re.search(r"@(IsMongoId|IsUUID)", decos):
                    add("LOW", "DTO-ID", f"{cname}.{name} id not validated with @IsMongoId - malformed ids cause 500/CastError leaks", loc, pm.group(0).strip())
            if no_max:
                add("LOW", "DTO-MAXLEN", f"{cname}: {no_max} free-text string field(s) without @MaxLength - unbounded payloads (storage/DoS, huge PDFs)", f.loc(cm.start()), cname)


# --------------------------------------------------------------------------- schemas
CARD_RX = re.compile(r"\b(cardNumber|cardNo|card_number|pan|cvv|cvc|cvv2|securityCode|expiryDate|cardExpiry)\b")
BANK_PII_RX = re.compile(r"\b(accountNumber|account_number|routingNumber|routing_number|bankAccount|iban|swift|ssn|socialSecurity\w*|taxId|ein|tin|dateOfBirth|dob|driverLicen[cs]e\w*|passport\w*)\b")
TOKEN_RX = re.compile(r"\b(resetToken|resetPasswordToken|passwordResetToken|otp|otpCode|verificationToken|verifyToken|inviteToken|refreshToken|accessToken|apiKey|apiSecret|secretKey|clientSecret|webhookSecret|qb\w*Token|quickbooks\w*Token|intuit\w*Token)\b")


def schema_checks(files):
    for f in files:
        if not (re.search(r"(\.schema|\.model|\.entity)\.(ts|js)$", f.path) or "new Schema(" in f.text or "@Schema(" in f.text):
            continue
        t = strip_comments(f.text)
        for m in re.finditer(r"\bpassword\w*\b\s*[:!?]", t):
            ctx = t[max(0, m.start() - 250):m.start() + 250]
            if re.search(r"confirm", m.group(0), re.I):
                continue
            if not re.search(r"select\s*:\s*false", ctx):
                add("MEDIUM", "SCHEMA-PWSELECT", "Password field without select:false - every query returns the hash unless each caller remembers to exclude it", f.loc(m.start()), f.snippet(m.start()))
            break
        for m in CARD_RX.finditer(t):
            add("HIGH", "SCHEMA-CARD", f"Schema stores card data ('{m.group(1)}') - PCI DSS scope; store only Stripe/Rainforest tokens and last4", f.loc(m.start()), f.snippet(m.start()))
        for m in BANK_PII_RX.finditer(t):
            add("MEDIUM", "SCHEMA-PII", f"Schema stores sensitive '{m.group(1)}' - encrypt at rest (field-level / CSFLE) and mask in API responses", f.loc(m.start()), f.snippet(m.start()))
        for m in TOKEN_RX.finditer(t):
            add("MEDIUM", "SCHEMA-TOKEN", f"Schema stores '{m.group(1)}' - store reset/OTP tokens hashed with an expiry, and encrypt OAuth/API tokens (QuickBooks) at rest", f.loc(m.start()), f.snippet(m.start()))
        if re.search(r"@Schema\(|new Schema\(", t) and not re.search(r"company|tenant|organi[sz]ation", t, re.I):
            cname = re.search(r"class\s+(\w+)|const\s+(\w+)\s*=\s*new Schema", t)
            nm = (cname.group(1) or cname.group(2)) if cname else os.path.basename(f.path)
            if not EXEMPT_MODEL.match(nm or ""):
                add("LOW", "SCHEMA-NOTENANT", f"Schema '{nm}' has no company/tenant field - confirm these documents are global and never company data", f.rel, nm)


# --------------------------------------------------------------------------- auth, crypto, risky features (project-wide)
def project_checks(files):
    alltext = "\n".join(f.text for f in files)
    has = lambda rx: re.search(rx, alltext, re.I | re.S) is not None
    nest = has(r"@nestjs/(core|common)")

    def each(rx, sev, fid, title, flags=0, only=None):
        for f in files:
            if only and not re.search(only, f.path):
                continue
            t = strip_comments(f.text)
            for m in re.finditer(rx, t, flags):
                add(sev, fid, title, f.loc(m.start()), f.snippet(m.start()))

    # Google sign-in
    if has(r"signin/google|google-auth-library|OAuth2Client|googleapis\.com/oauth2|loginWithGoogle|GoogleStrategy"):
        if not has(r"verifyIdToken"):
            if has(r"oauth2\.googleapis\.com/tokeninfo|googleapis\.com/oauth2/v\d/(tokeninfo|userinfo)"):
                if not has(r"\baud\b|audience|azp"):
                    add("HIGH", "AUTH-GOOGLE", "Google token checked via tokeninfo/userinfo without verifying 'aud' = our client id - a token issued to ANY app can log in as that user", "(project-wide)", "")
            elif not has(r"passport-google|GoogleStrategy"):
                add("HIGH", "AUTH-GOOGLE", "Google sign-in found but no OAuth2Client.verifyIdToken() - the Google ID token may not be verified (account takeover)", "(project-wide)", "")
        elif not has(r"verifyIdToken\s*\(\s*\{[^}]*audience"):
            add("HIGH", "AUTH-GOOGLE", "verifyIdToken() called without 'audience' - accepts Google tokens minted for other apps", "(project-wide)", "")
    # token revocation
    if nest and has(r"JwtModule|jsonwebtoken|@nestjs/jwt") and not has(r"tokenVersion|passwordChangedAt|jti|denylist|blacklist|revok|sessionId|tokenId"):
        add("MEDIUM", "AUTH-REVOKE", "JWTs cannot be revoked (no tokenVersion / passwordChangedAt / jti denylist) - logout, password change and user deactivation leave old tokens valid until expiry", "(project-wide)", "")
    if has(r"JwtModule\.register") and not has(r"algorithms?\s*:"):
        add("LOW", "AUTH-JWTALG", "JWT algorithm not pinned in verify options - pin algorithms: ['HS256'] (or RS256)", "(project-wide)", "")
    # reset / otp
    for f in files:
        t = strip_comments(f.text)
        if re.search(r"forgot|resetPassword|reset-password|passwordReset", t, re.I) and re.search(r"(Service|controller)", f.path, re.I) is not None or re.search(r"forgot|reset", f.path, re.I):
            if re.search(r"Math\.random", t):
                add("HIGH", "AUTH-RESETRAND", "Password-reset token generated with Math.random - predictable; use crypto.randomBytes(32)", f.rel, "")
            if re.search(r"(reset|forgot)", t, re.I) and re.search(r"token", t, re.I) and not re.search(r"expir|ttl|validUntil|expiresAt", t, re.I):
                add("MEDIUM", "AUTH-RESETEXP", "Password-reset token with no visible expiry - tokens should expire in <= 1 hour and be single-use", f.rel, "")
        if re.search(r"\botp\b|one.?time", t, re.I):
            if re.search(r"Math\.random", t):
                add("HIGH", "AUTH-OTPRAND", "OTP generated with Math.random - use crypto.randomInt", f.rel, "")
            if re.search(r"Math\.floor\(\s*1000\s*\+|randomInt\(\s*1000\s*,\s*9999|\b\d{4}\b.*otp", t, re.I):
                add("MEDIUM", "AUTH-OTP4", "4-digit OTP - brute-forceable in 10k tries; use 6+ digits with attempt limits", f.rel, "")
            if not re.search(r"attempt|tries|retry|throttle|lock", t, re.I):
                add("MEDIUM", "AUTH-OTPBRUTE", "OTP verification without an attempt counter/lockout", f.rel, "")
    each(r"\b(master|super|universal|backdoor|god|default)_?(password|pass|pwd|otp|key)\b|password\s*===?\s*['\"`][^'\"`]+['\"`]", "HIGH", "AUTH-BACKDOOR", "Hard-coded/master password or bypass - remove", re.I)
    each(r"(?<!confirm)(?<!Confirm)\bpassword\s*(===|!==|==|!=)\s*(user|dto|body|existing|found)\w*\.password", "HIGH", "AUTH-PLAINPW", "Password compared directly (plaintext storage?) - use bcrypt/argon2 compare", re.I)
    each(r"impersonat|loginAs|login-as|switchUser|ghostLogin|assumeUser", "MEDIUM", "AUTH-IMPERSONATE", "Impersonation / login-as feature - restrict to super-admins, audit-log every use, show a banner", re.I)
    each(r"(signature|hmac|digest|sig|expectedSig)\w*\s*(===|!==)\s*\w+", "MEDIUM", "CRYPTO-TIMING", "Signature/HMAC compared with === - use crypto.timingSafeEqual", re.I)
    each(r"createCipher\(", "HIGH", "CRYPTO-CIPHER", "crypto.createCipher is deprecated and IV-less - use createCipheriv with AES-256-GCM and random IV")
    each(r"aes-\d+-ecb|des-|rc4", "HIGH", "CRYPTO-WEAK", "Weak cipher mode/algorithm", re.I)
    each(r"\biv\s*=\s*(['\"`]|Buffer\.from\(\s*['\"`]|Buffer\.alloc\()", "MEDIUM", "CRYPTO-STATICIV", "Static/zero IV - generate a random IV per encryption")
    each(r"res\.cookie\((?![^)]*httpOnly\s*:\s*true)[^)]*\)", "MEDIUM", "AUTH-COOKIEFLAGS", "res.cookie() without httpOnly:true (and secure/sameSite)")
    # PDF / SSRF / templates / deserialization
    each(r"--no-sandbox", "MEDIUM", "PDF-SANDBOX", "Headless Chrome started with --no-sandbox - combined with user HTML in invoices/quotes this widens the impact of a renderer exploit")
    each(r"\.setContent\(|page\.goto\(", "MEDIUM", "PDF-SSRF", "Headless browser renders HTML/URLs - user content in invoices/quotes can load http://169.254.169.254 (AWS keys) or file:// - sanitize HTML and block non-allow-listed requests with page.setRequestInterception")
    if has(r"['\"]html-pdf['\"]|phantomjs"):
        add("HIGH", "PDF-PHANTOM", "html-pdf / PhantomJS is unmaintained and allows local file read through HTML - replace with Puppeteer + request interception", "(project-wide)", "")
    each(r"(Handlebars|handlebars|hbs)\.compile\(\s*(?!['\"`])", "MEDIUM", "SSTI", "Template compiled from a variable (e.g. company-editable email/invoice template) - server-side template injection risk; use precompiled templates / restrict helpers")
    each(r"ejs\.render\(\s*(?!['\"`])|pug\.compile\(\s*(?!['\"`])|_.template\(\s*(?!['\"`])", "HIGH", "SSTI", "Template engine renders a dynamic template string - code execution if the template is user-controlled")
    each(r"noent\s*:\s*true|libxmljs", "HIGH", "XXE", "XML parsed with external entities enabled (XXE)")
    each(r"node-serialize|serialize-to-js|\.unserialize\(", "HIGH", "DESERIALIZE", "Insecure deserialization library")
    each(r"['\"]vm2['\"]|new\s+VM\(|new\s+NodeVM\(", "HIGH", "SANDBOX-VM2", "vm2 is abandoned with known sandbox escapes")
    # WebSockets
    for f in files:
        t = strip_comments(f.text)
        m = re.search(r"@WebSocketGateway\(([^)]*)\)", t)
        if m:
            if not re.search(r"UseGuards|handleConnection[\s\S]{0,800}(verify|jwt|token|auth)", t, re.I):
                add("HIGH", "WS-NOAUTH", "WebSocket gateway with no auth on connect - anyone can subscribe to events (job/notification data)", f.loc(m.start()), m.group(0))
            if re.search(r"origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true", m.group(1)):
                add("MEDIUM", "WS-CORS", "WebSocket gateway accepts any origin", f.loc(m.start()), m.group(0))
    # exposure
    each(r"@bull-board|createBullBoard|BullBoardModule", "MEDIUM", "EXPOSE-BULLBOARD", "bull-board queue UI - must sit behind admin auth")
    each(r"playground\s*:\s*true|introspection\s*:\s*true", "MEDIUM", "EXPOSE-GQL", "GraphQL playground/introspection enabled")
    each(r"useStaticAssets\(|ServeStaticModule\.forRoot|express\.static\(", "MEDIUM", "EXPOSE-STATIC", "Static file serving - make sure uploads/ (invoices, photos, signatures) are not served publicly; use private S3 + presigned URLs")
    each(r"limit\s*:\s*['\"](\d{3,}|[5-9]\d)mb['\"]", "LOW", "DOS-BODYLIMIT", "Very large request body limit - DoS / memory pressure", re.I)
    if nest:
        if not has(r"useGlobalFilters|APP_FILTER|@Catch\("):
            add("LOW", "NEST-NOFILTER", "No global exception filter - unexpected errors may leak Mongo/stack details; add a filter that logs internally and returns a generic message", "(project-wide)", "")
        if has(r"ConfigModule\.forRoot") and not has(r"validationSchema|validate\s*:"):
            add("LOW", "NEST-CONFIGVALID", "ConfigModule without validationSchema - app can boot with missing/weak secrets (empty JWT secret)", "(project-wide)", "")
        if has(r"webhook") and has(r"from ['\"]stripe['\"]|rainforest") and not has(r"rawBody\s*:\s*true|bodyParser\.raw|express\.raw|raw\(\s*\{"):
            add("HIGH", "WEBHOOK-RAWBODY", "Webhooks exist but the raw request body is not kept (NestFactory.create(..., { rawBody: true }) / express.raw) - signature verification cannot work, so it is probably skipped", "(project-wide)", "")
        if not has(r"helmet"):
            pass  # covered by shell check BE-HELMET
    # rate limiting present but client IP not trusted behind the proxy
    if has(r"ThrottlerModule|express-rate-limit|rate-limiter-flexible") and not has(r"trust\s*proxy|trustProxy|X-Forwarded-For|getTracker"):
        add("MEDIUM", "AUTH-TRUSTPROXY", "Rate limiting is configured but the app does not trust the proxy (app.set('trust proxy', 1)) - behind nginx/CloudFront every request looks like one IP, so per-IP limits and lockouts are wrong or bypassable", "(project-wide)", "")
    # request-driven upsert can create cross-tenant documents
    each(r"upsert\s*:\s*true", "LOW", "DB-UPSERT", "Query uses upsert:true - make sure the filter is scoped to the caller's company so it updates an existing record instead of silently creating one", re.I)
    # findOneAndUpdate/new document without setting companyId server-side
    each(r"new\s+this\.\w*[Mm]odel\(\s*(req\.body|body|dto)\s*\)", "MEDIUM", "DB-NEWDOC", "A document is constructed directly from the request body - set companyId/ownerId from the logged-in user, not the payload (mass assignment)")
    # logging bodies / PII
    for f in files:
        if re.search(r"(interceptor|middleware|logger|logging)", f.path, re.I):
            t = strip_comments(f.text)
            for m in re.finditer(r"(log|info|debug|warn|error)\([^)]*(req|request)\.body", t):
                add("MEDIUM", "LOG-BODY", "Request bodies logged - passwords, card/bank details and tokens end up in logs", f.loc(m.start()), f.snippet(m.start()))
    # CSV/Excel export injection
    if has(r"json2csv|csv-writer|csv-stringify|papaparse|exceljs|['\"]xlsx['\"]|fast-csv") and not has(r"\^\[=\+\\?-@|\[=\+\-@|startsWith\(['\"]=['\"]\)"):
        add("LOW", "CSV-INJECTION", "CSV/Excel export without formula escaping - client names like '=HYPERLINK(...)' execute in Excel; prefix cells starting with = + - @ with a quote", "(project-wide)", "")
    # mail
    each(r"\bto\s*:\s*(dto|body|req\.body)\.\w+", "LOW", "MAIL-OPENRELAY", "Email recipient taken from request - can be abused to send branded mail to anyone (rate limit + allow-list)")
    # Rainforest / Stripe specifics
    each(r"status\s*===?\s*['\"](succeeded|paid|captured|approved)['\"]", "MEDIUM", "PAY-CLIENTSTATUS", "Payment status compared from a value - make sure it comes from the provider API/webhook, never from the client request", 0, r"(controller|dto)")
    each(r"(stripe|rainforest)\w*\.(refunds|refund)\w*\.?create|createRefund", "MEDIUM", "PAY-REFUND", "Refund endpoint - require admin role, cap at captured amount, idempotency key, audit log", re.I)


# --------------------------------------------------------------------------- docker-compose
def compose_checks(roots):
    for root in roots:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                if not re.match(r"(docker-)?compose.*\.ya?ml$", fn):
                    continue
                p = os.path.join(dp, fn)
                rel = os.path.basename(root) + "/" + os.path.relpath(p, root)
                t = open(p, encoding="utf-8", errors="replace").read()
                for m in re.finditer(r"['\"]?(?:0\.0\.0\.0:)?(27017|6379|5432|3306|9200|5672|15672):\d+['\"]?", t):
                    add("HIGH", "IN-DBPORT", f"Database/cache port {m.group(1)} published to the host network - bind to 127.0.0.1 or remove", f"{rel}:{t[:m.start()].count(chr(10)) + 1}", m.group(0))
                if re.search(r"image:\s*mongo", t) and not re.search(r"MONGO_INITDB_ROOT_PASSWORD", t):
                    add("HIGH", "IN-MONGOAUTH", "MongoDB container without root password (auth disabled)", rel, "")
                if re.search(r"image:\s*redis", t) and not re.search(r"requirepass|REDIS_PASSWORD", t):
                    add("MEDIUM", "IN-REDISAUTH", "Redis container without a password", rel, "")
                for m in re.finditer(r"(PASSWORD|SECRET|KEY|TOKEN)\w*\s*[:=]\s*['\"]?(?!\$\{)[^\s'\"$]{6,}", t):
                    add("HIGH", "IN-COMPOSESECRET", "Plain-text secret in docker-compose", f"{rel}:{t[:m.start()].count(chr(10)) + 1}", m.group(0)[:60])


# --------------------------------------------------------------------------- dependency advisories
def vparse(v):
    v = re.sub(r"^[^\d]*", "", v or "")
    parts = re.findall(r"\d+", v)[:3]
    return tuple(int(x) for x in parts + ["0"] * (3 - len(parts))) if parts else None


def lt(v, ref):
    return v is not None and v < vparse(ref)


# (package, predicate(version_tuple)->bool, severity, advisory text)
ADVISORIES = [
    ("jsonwebtoken", lambda v: lt(v, "9.0.0"), "HIGH", "jsonwebtoken < 9.0.0: signature validation bypass / weak key acceptance (CVE-2022-23529, -23539, -23540, -23541)"),
    ("mongoose", lambda v: v and ((v[0] == 5 and lt(v, "5.13.20")) or (v[0] == 6 and lt(v, "6.13.6")) or (v[0] == 7 and lt(v, "7.8.4")) or (v[0] == 8 and lt(v, "8.9.5")) or v[0] < 5), "HIGH", "mongoose: prototype pollution / $where search injection (CVE-2023-3696, CVE-2024-53900, CVE-2025-23061) - upgrade to 8.9.5+ (or 7.8.4 / 6.13.6)"),
    ("class-validator", lambda v: lt(v, "0.14.0"), "HIGH", "class-validator < 0.14.0: validation bypass (CVE-2019-18413) - upgrade and set forbidUnknownValues"),
    ("axios", lambda v: lt(v, "1.8.2"), "MEDIUM", "axios < 1.8.2: XSRF-token leak (CVE-2023-45857) / SSRF with absolute URLs (CVE-2025-27152)"),
    ("express", lambda v: v and v[0] == 4 and lt(v, "4.20.0"), "MEDIUM", "express < 4.20.0: open redirect / XSS in res.redirect (CVE-2024-29041, CVE-2024-43796)"),
    ("body-parser", lambda v: v and v[0] == 1 and lt(v, "1.20.3"), "HIGH", "body-parser < 1.20.3: DoS with url-encoding (CVE-2024-45590)"),
    ("path-to-regexp", lambda v: v and v[0] == 0 and lt(v, "0.1.12"), "HIGH", "path-to-regexp 0.1.x < 0.1.12: ReDoS (CVE-2024-45296, CVE-2024-52798)"),
    ("xlsx", lambda v: v is not None, "HIGH", "xlsx (SheetJS) from npm is no longer patched: prototype pollution + ReDoS (CVE-2023-30533, CVE-2024-22363) - install from cdn.sheetjs.com or use exceljs"),
    ("multer", lambda v: lt(v, "2.0.2"), "HIGH", "multer < 2.0.2: DoS via malformed multipart (CVE-2025-47935, -47944, -48997, -7338)"),
    ("lodash", lambda v: lt(v, "4.17.21"), "HIGH", "lodash < 4.17.21: prototype pollution / command injection in template"),
    ("crypto-js", lambda v: lt(v, "4.2.0"), "HIGH", "crypto-js < 4.2.0: PBKDF2 1000x weaker than spec (CVE-2023-46233)"),
    ("xml2js", lambda v: lt(v, "0.5.0"), "MEDIUM", "xml2js < 0.5.0: prototype pollution (CVE-2023-0842)"),
    ("ws", lambda v: v and v[0] == 8 and lt(v, "8.17.1"), "MEDIUM", "ws 8 < 8.17.1: DoS with many headers (CVE-2024-37890)"),
    ("moment", lambda v: lt(v, "2.29.4"), "MEDIUM", "moment < 2.29.4: ReDoS in RFC2822 parsing (CVE-2022-31129)"),
    ("jspdf", lambda v: lt(v, "3.0.2"), "MEDIUM", "jspdf < 3.0.2: ReDoS / DoS via crafted input (CVE-2025-29907, CVE-2025-57810)"),
    ("cookie", lambda v: v and v[0] == 0 and lt(v, "0.7.0"), "LOW", "cookie < 0.7.0: cookie name/path injection (CVE-2024-47764)"),
    ("nodemailer", lambda v: lt(v, "6.9.9"), "LOW", "nodemailer < 6.9.9: ReDoS in attachment parsing"),
    ("request", lambda v: v is not None, "MEDIUM", "request is deprecated and unpatched (SSRF via redirects, CVE-2023-28155) - use axios/undici"),
    ("html-pdf", lambda v: v is not None, "HIGH", "html-pdf is unmaintained (PhantomJS) - local file read via HTML"),
    ("node-serialize", lambda v: v is not None, "HIGH", "node-serialize allows remote code execution"),
    ("vm2", lambda v: v is not None, "HIGH", "vm2 is abandoned with critical sandbox escapes"),
]


def installed_versions(pkgdir):
    vers = {}
    lock = os.path.join(pkgdir, "package-lock.json")
    if os.path.exists(lock):
        try:
            j = json.load(open(lock))
            for k, v in (j.get("packages") or {}).items():
                if k.startswith("node_modules/") and isinstance(v, dict) and not v.get("dev"):
                    name = k.split("node_modules/")[-1]
                    vers.setdefault(name, set()).add(v.get("version", ""))
            for k, v in (j.get("dependencies") or {}).items():
                if isinstance(v, dict) and not v.get("dev"):
                    vers.setdefault(k, set()).add(v.get("version", ""))
        except Exception:
            pass
    ylock = os.path.join(pkgdir, "yarn.lock")
    if os.path.exists(ylock):
        cur = None
        for line in open(ylock, encoding="utf-8", errors="replace"):
            m = re.match(r'^"?(@?[^@\s"]+)@', line)
            if m and not line.startswith(" "):
                cur = m.group(1)
            m2 = re.match(r'^\s+version:?\s+"?([^"\s]+)', line)
            if m2 and cur:
                vers.setdefault(cur, set()).add(m2.group(1))
    if not vers:
        try:
            pj = json.load(open(os.path.join(pkgdir, "package.json")))
            for k, v in (pj.get("dependencies") or {}).items():
                vers.setdefault(k, set()).add(v)
        except Exception:
            pass
    return vers


def dep_checks(roots):
    for root in roots:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            if "package.json" not in fns:
                continue
            vers = installed_versions(dp)
            rel = os.path.basename(root) + "/" + os.path.relpath(os.path.join(dp, "package.json"), root)
            for name, pred, sev, text in ADVISORIES:
                for ver in sorted(vers.get(name, ())):
                    try:
                        if pred(vparse(ver)):
                            add(sev, f"DEP-{name}", text, rel, f"{name}@{ver}")
                    except Exception:
                        pass


# --------------------------------------------------------------------------- main
def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    out_tsv, out_routes, roots = sys.argv[1], sys.argv[2], sys.argv[3:]
    files = walk(roots)
    has_global = any(re.search(r"APP_GUARD|useGlobalGuards", f.text) for f in files)
    routes = parse_controllers(files, has_global)
    tenant_checks(files)
    dto_checks(files)
    schema_checks(files)
    project_checks(files)
    compose_checks(roots)
    dep_checks(roots)
    with open(out_tsv, "a", encoding="utf-8") as fh:
        for row in findings:
            fh.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in row) + "\n")
    if routes:
        with open(out_routes, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["method", "path", "auth", "roles", "user_context", "body_type", "query_type", "notes", "location"])
            for r in sorted(routes, key=lambda r: (r["path"], r["method"])):
                w.writerow([r["method"], r["path"], r["auth"], r["roles"], r["user_context"], r["body_type"],
                            r["query_type"], "; ".join(r["notes"]), r["loc"]])
    print(f"  deep scan: {len(files)} files, {len(routes)} routes, {len(findings)} findings")


if __name__ == "__main__":
    main()
