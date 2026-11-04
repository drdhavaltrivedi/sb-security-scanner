#!/usr/bin/env bash
# =============================================================================
#  Service Buddy - Security Scanner
#  Stack (fingerprinted from staging, 2026-11-04):
#    Frontend : React 18 + TypeScript + Vite, Redux Toolkit, react-query v3,
#               axios, Tailwind, i18next, Sentry, Google OAuth, GA4, jsPDF
#               -> hosted on AWS S3 + CloudFront
#    Backend  : NestJS 10 (Express platform) behind nginx, JWT bearer auth,
#               Google sign-in, MongoDB (Mongoose), AWS S3
#    Integrations: Stripe, Rainforest (BuddyPay), QuickBooks Online
#
#  Usage (run on the local dev machine, pointing at your own checked-out repos):
#    ./sb-security-scan.sh <path-to-repo-or-monorepo> [more paths...]
#    ./sb-security-scan.sh ~/code/servicebuddy-web ~/code/servicebuddy-api
#
#    # include a PASSIVE, read-only black-box probe of production (safe: it only
#    # makes normal browser-shaped requests and reads the responses - no attacks):
#    LIVE_URL=https://app.servicebuddy.io LIVE_API=https://api.servicebuddy.io \
#      ./sb-security-scan.sh ~/code/servicebuddy-web ~/code/servicebuddy-api
#
#  Outputs (in OUT_DIR, default ./sb-security-report):
#    REPORT.md       Markdown report (gates + grouped findings)
#    REPORT.html     interactive report (severity filter, route table, fixes)
#    findings.sarif  upload to GitHub code scanning
#    findings.tsv    one row per finding; routes.csv  API route inventory
#
#  Options (env vars):
#    LIVE_URL / LIVE_API   passive live probe targets (web app / API)
#    AUTH_TOKEN=<jwt>      decode-only analysis of your own session token (optional)
#    OUT_DIR=./sb-security-report   where reports are written
#    SKIP_TOOLS=1          only run the built-in + deep checks (no semgrep/trivy/...)
#    INSTALL_TOOLS=1       brew-install missing scanners first (macOS)
#    NO_DOCKER=1           don't fall back to Docker images for missing scanners
#
#  Deep backend analysis (lib/deep_scan.py) and the passive live probe
#  (lib/live_probe.py) run automatically when python3 is present.
#
#  Optional external tools (used automatically when installed):
#    semgrep   (brew install semgrep)        - SAST rulesets for TS/JS/Node/React
#    gitleaks  (brew install gitleaks)       - secrets in files AND git history
#    osv-scanner (brew install osv-scanner)  - dependency CVEs (all lockfiles)
#    trivy     (brew install trivy)          - Dockerfiles / IaC misconfig + CVEs
#    npm/yarn/pnpm                           - `audit` on each package
#
#  Security gates (a gate FAILS when it has any HIGH finding):
#    G1 Secrets  G2 Dependencies  G3 Injection & code  G4 AuthN/AuthZ
#    G5 Payments & integrations   G6 Frontend          G7 Config & infra
#    G8 Live (DAST-lite)
#  Exit code: 1 if any gate FAILS, else 0 (usable in CI).
# =============================================================================
set -uo pipefail

if [ $# -lt 1 ]; then
  sed -n '2,40p' "$0"; exit 2
fi

OUT_DIR="${OUT_DIR:-./sb-security-report}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/REPORT.md"
FINDINGS="$OUT_DIR/findings.tsv"
: > "$FINDINGS"

RED=$'\e[31m'; YEL=$'\e[33m'; BLU=$'\e[34m'; GRN=$'\e[32m'; DIM=$'\e[2m'; RST=$'\e[0m'
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="$SCRIPT_DIR/lib"
ROUTES_CSV="$OUT_DIR/routes.csv"
have() { command -v "$1" >/dev/null 2>&1; }
docker_ok() { [ "${NO_DOCKER:-0}" != "1" ] && have docker && docker info >/dev/null 2>&1; }
if [ "${INSTALL_TOOLS:-0}" = "1" ] && have brew; then
  for t in semgrep gitleaks osv-scanner trivy; do have $t || brew install $t; done
fi

EXCLUDES=(--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build
          --exclude-dir=coverage --exclude-dir=.next --exclude-dir=storybook-static
          --exclude-dir=.turbo --exclude-dir=vendor --exclude='*.min.js' --exclude='*.map'
          --exclude='*.lock' --exclude='package-lock.json' --exclude='pnpm-lock.yaml')
CODE_INC=(--include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' --include='*.cjs')

# record <SEVERITY> <ID> <title> <file:line> <snippet>
record() {
  local sev="$1" id="$2" title="$3" loc="$4" snip="${5:-}"
  snip="$(printf '%s' "$snip" | tr '\t\n' '  ' | sed 's/^[[:space:]]*//' | cut -c1-180)"
  local r; for r in "${SCAN_PATHS[@]}"; do case "$loc" in "$r"/*) loc="$(basename "$r")/${loc#"$r"/}";; esac; done
  printf '%s\t%s\t%s\t%s\t%s\n' "$sev" "$id" "$title" "$loc" "$snip" >> "$FINDINGS"
}

# grep_check <SEVERITY> <ID> <title> <regex> [extra grep args...]
# Every line matching <regex> in code files becomes a finding.
grep_check() {
  local sev="$1" id="$2" title="$3" rx="$4"; shift 4
  local line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local loc="${line%%:*}"; local rest="${line#*:}"; local ln="${rest%%:*}"; local code="${rest#*:}"
    # skip test files & obvious comments
    case "$loc" in *.spec.*|*.test.*|*__tests__*|*/test/*|*/e2e/*) continue;; esac
    case "$(printf '%s' "$code" | sed 's/^[[:space:]]*//')" in //*|\**) continue;; esac
    record "$sev" "$id" "$title" "$loc:$ln" "$code"
  done < <(grep -rnE "${EXCLUDES[@]}" "${CODE_INC[@]}" "$@" -e "$rx" "${SCAN_PATHS[@]}" 2>/dev/null)
}

# absent_check <SEVERITY> <ID> <title> <regex> <only-if-regex>
# Raises a finding when <only-if-regex> exists somewhere (e.g. this is a NestJS app)
# but <regex> is found nowhere (e.g. helmet never used).
absent_check() {
  local sev="$1" id="$2" title="$3" rx="$4" cond="$5"
  if grep -rqE "${EXCLUDES[@]}" "${CODE_INC[@]}" -e "$cond" "${SCAN_PATHS[@]}" 2>/dev/null; then
    if ! grep -rqE "${EXCLUDES[@]}" "${CODE_INC[@]}" --include='*.json' -e "$rx" "${SCAN_PATHS[@]}" 2>/dev/null; then
      record "$sev" "$id" "$title" "(project-wide)" "pattern not found: $rx"
    fi
  fi
}

SCAN_PATHS=()
for p in "$@"; do
  [ -d "$p" ] || { echo "${RED}Not a directory: $p${RST}"; exit 2; }
  SCAN_PATHS+=("$(cd "$p" && pwd)")
done

echo "${BLU}== Service Buddy security scan ==${RST}"
echo "${DIM}paths: ${SCAN_PATHS[*]}${RST}"
echo "${DIM}output: $OUT_DIR${RST}"

# -----------------------------------------------------------------------------
echo "${BLU}[1/7] Secrets & sensitive files${RST}"
# -----------------------------------------------------------------------------
for root in "${SCAN_PATHS[@]}"; do
  while IFS= read -r f; do
    case "$f" in *.example|*.sample|*.template|*.dist) continue;; esac
    tracked="untracked"
    if git -C "$root" rev-parse >/dev/null 2>&1 && git -C "$root" ls-files --error-unmatch "$f" >/dev/null 2>&1; then
      tracked="COMMITTED TO GIT"
      record HIGH SEC-ENV "Env file committed to git" "$f" "$tracked"
    fi
  done < <(find "$root" \( -name node_modules -o -name .git \) -prune -o -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.p12' -o -name '*.key' -o -name 'id_rsa*' -o -name '*service-account*.json' \) -print 2>/dev/null)
done

grep_check HIGH SEC-AWS   "AWS access key"            'AKIA[0-9A-Z]{16}'
grep_check HIGH SEC-STRIPE "Stripe secret/restricted key" '(sk|rk)_(live|test)_[0-9A-Za-z]{16,}'
grep_check HIGH SEC-WHSEC "Stripe webhook secret hard-coded" 'whsec_[0-9A-Za-z]{16,}'
grep_check HIGH SEC-GOOG  "Google OAuth client secret" 'GOCSPX-[0-9A-Za-z_-]{20,}'
grep_check HIGH SEC-PK    "Private key in source"     '-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----'
grep_check HIGH SEC-MONGO "DB connection string with credentials" '(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^:/"'"'"' ]+:[^@"'"'"' ]+@'
grep_check HIGH SEC-SENDG "SendGrid / Twilio / Mailgun key" '(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}|SK[0-9a-f]{32}|key-[0-9a-f]{32})'
grep_check MEDIUM SEC-HARD "Hard-coded secret/password assignment" '(secret|password|passwd|api[_-]?key|private[_-]?key|jwt[_-]?secret)[A-Za-z_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'$ {/][^"'"'"'$ {]{7,}["'"'"']' -i
grep_check MEDIUM SEC-VITE "Secret-looking value exposed through VITE_ env (shipped to browser)" 'VITE_[A-Z_]*(SECRET|PRIVATE|PASSWORD|TOKEN)[A-Z_]*'

# -----------------------------------------------------------------------------
echo "${BLU}[2/7] Backend (NestJS / Express / Node) checks${RST}"
# -----------------------------------------------------------------------------
NEST='@nestjs/(core|common)'
IS_BACKEND=0
grep -rqE "${EXCLUDES[@]}" "${CODE_INC[@]}" -e "$NEST|from ['\"]express['\"]" "${SCAN_PATHS[@]}" 2>/dev/null && IS_BACKEND=1
# absent_check, but only meaningful on server code (webhooks never live in the React app)
be_absent_check() { [ "$IS_BACKEND" = 1 ] && absent_check "$@"; return 0; }
absent_check HIGH   BE-RATELIMIT "No rate limiting (no @nestjs/throttler / express-rate-limit). Staging login accepted 10+ rapid bad attempts with no 429" '(ThrottlerModule|ThrottlerGuard|express-rate-limit|rate-limiter-flexible|@Throttle)' "$NEST"
absent_check MEDIUM BE-HELMET    "helmet() not used - API responses have no security headers and leak X-Powered-By: Express" '(helmet|disable\(["'"'"']x-powered-by)' "$NEST"
absent_check MEDIUM BE-VALIDWL   "ValidationPipe without whitelist:true - extra body fields pass through (mass assignment)" 'whitelist[[:space:]]*:[[:space:]]*true' "ValidationPipe"
grep_check MEDIUM BE-CORS   "CORS allows any origin (staging API returns Access-Control-Allow-Origin: *)" '(enableCors\([[:space:]]*\)|origin[[:space:]]*:[[:space:]]*(["'"'"']\*["'"'"']|true)|cors\([[:space:]]*\))'
grep_check HIGH   BE-CORSCR "CORS reflects any origin WITH credentials" 'credentials[[:space:]]*:[[:space:]]*true'
grep_check MEDIUM BE-ENUM   "User enumeration: login reveals whether an account exists (staging returns 404 'don't have an account' vs 401)" "(don't have an account|User not found|user does not exist|Email not registered|NotFoundException\([^)]*(user|account|email))" -i

# Auth / JWT
grep_check HIGH   BE-JWTEXP "JWT expiration ignored" 'ignoreExpiration[[:space:]]*:[[:space:]]*true'
grep_check HIGH   BE-JWTNONE "JWT 'none' algorithm / decode without verify" "(algorithms?[[:space:]]*:[[:space:]]*\[?[[:space:]]*['\"]none|jwt\.decode\(|jwtService\.decode\()"
grep_check MEDIUM BE-JWTLONG "Long-lived JWT (>= 7d) - no refresh/rotation" "expiresIn[[:space:]]*:[[:space:]]*['\"]?([7-9]|[1-9][0-9]+)[[:space:]]*(d|days|w|y)"
grep_check MEDIUM BE-JWTSEC "JWT secret fallback / hard-coded" "secret[[:space:]]*:[[:space:]]*(process\.env\.[A-Z_]+[[:space:]]*(\|\||\?\?)[[:space:]]*['\"]|['\"][^'\"]{4,}['\"])"
grep_check LOW    BE-PUBLIC "Route marked public - verify it really should be unauthenticated" '@(Public|SkipAuth|AllowAnonymous)\(\)'

# Injection
grep_check HIGH BE-SQLI   "Raw SQL built with string interpolation" '(\.query|\.raw|\$queryRawUnsafe|\$executeRawUnsafe|createQueryBuilder[^;]*\.where)\([[:space:]]*`[^`]*\$\{'
grep_check HIGH BE-SQLI2  "Raw SQL built with string concatenation" '(\.query|\.raw)\([[:space:]]*["'"'"'][^"'"'"']*(SELECT|UPDATE|DELETE|INSERT|WHERE)[^"'"'"']*["'"'"'][[:space:]]*\+' -i
grep_check HIGH BE-NOSQL  "NoSQL injection: request object passed directly into a Mongo/Mongoose query" '\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\([[:space:]]*(req\.(body|query|params)|body|query|filter|dto)[[:space:]]*[,)]'
grep_check HIGH BE-WHERE  "Mongo \$where / mapReduce (JS execution)" '\$where|mapReduce\('
grep_check HIGH BE-REGEX  "User input in new RegExp (ReDoS / regex injection) - escape it" 'new RegExp\([^)]*(req\.|query\.|body\.|dto\.|search|keyword|term)' -i
grep_check HIGH BE-RCE    "eval / new Function / vm" '(^|[^.a-zA-Z_])(eval|new Function|vm\.runIn[A-Za-z]*Context)\('
grep_check HIGH BE-CMD    "child_process with possible user input" '(exec|execSync|spawn|spawnSync|execFile)\([^)]*(\$\{|\+|req\.|body|query|params)'
grep_check MEDIUM BE-SSRF "Outbound HTTP to a URL built from input (SSRF)" '(axios|got|fetch|request|http\.get|https\.get|httpService\.(get|post))(\.[a-z]+)?\([[:space:]]*(`[^`]*\$\{|req\.|body\.|query\.|dto\.|url[,)])'
grep_check MEDIUM BE-PATH "File path built from input (path traversal)" '(readFile|readFileSync|createReadStream|sendFile|res\.download|unlink|writeFile)(Sync)?\([^)]*(req\.|params\.|query\.|body\.|dto\.|\$\{)'
grep_check MEDIUM BE-REDIR "Open redirect: redirect target from input" '(res\.redirect|@Redirect)\([^)]*(req\.|query\.|params\.|body\.)'
grep_check MEDIUM BE-PROTO "Prototype pollution sink (deep merge of request data)" '(_\.merge|_\.defaultsDeep|lodash\.merge|deepmerge|Object\.assign)\([^)]*(req\.body|body|dto)'

# Data access / authorization (IDOR) - heuristic, needs manual review
grep_check MEDIUM BE-IDOR "Lookup by id from URL without tenant/company scope - verify ownership check (IDOR)" '\.(findById|findByIdAndUpdate|findByIdAndDelete|findOneBy|findUnique)\([[:space:]]*(id|params\.id|req\.params\.[a-zA-Z]+|[a-zA-Z]+Id)[[:space:]]*[,)]'
grep_check MEDIUM BE-MASS "Mass assignment: whole request body written to the DB" '\.(create|update|findByIdAndUpdate|findOneAndUpdate|updateOne|save|insert)\([^)]*(req\.body|\.\.\.body|\.\.\.dto|,[[:space:]]*body[[:space:]]*[,)]|,[[:space:]]*dto[[:space:]]*[,)])'
grep_check LOW    BE-SELECT "User document returned without excluding password hash - verify select('-password') / @Exclude" 'return[[:space:]]+(await[[:space:]]+)?this\.(userModel|userRepository|usersService)\.find'

# Crypto / tokens
grep_check HIGH   BE-WEAKHASH "Weak hash (md5/sha1) - never for passwords or tokens" "createHash\(['\"](md5|sha1)['\"]\)|md5\("
grep_check MEDIUM BE-BCRYPT "bcrypt cost factor < 10" 'bcrypt[a-zA-Z]*\.(hash|genSalt)(Sync)?\([^)]*,[[:space:]]*[1-9][[:space:]]*\)'
grep_check MEDIUM BE-RAND  "Math.random used for tokens / OTP / ids - use crypto.randomBytes/randomInt" 'Math\.random\(\)'
grep_check MEDIUM BE-TLS   "TLS verification disabled" '(rejectUnauthorized[[:space:]]*:[[:space:]]*false|NODE_TLS_REJECT_UNAUTHORIZED)'

# Payments / webhooks / uploads
grep_check HIGH   BE-WEBHOOK "Webhook handler - verify the provider signature on the RAW body (Stripe: constructEvent; Rainforest: signing secret; Intuit: intuit-signature)" '@Post\([^)]*webhook'
be_absent_check HIGH BE-STRIPESIG "Stripe used but webhook signature never verified" 'constructEvent' "from ['\"]stripe['\"]"
grep_check MEDIUM BE-UPLOAD "File upload interceptor - verify fileFilter (mime/ext) and limits.fileSize are set" '(FileInterceptor|FilesInterceptor|AnyFilesInterceptor|multer\()'
grep_check MEDIUM BE-S3ACL "Public S3 ACL on uploaded objects" "ACL[[:space:]]*:[[:space:]]*['\"]public-read"

# Info leaks / config
grep_check MEDIUM BE-SWAGGER "Swagger docs enabled - make sure it is disabled or auth-protected outside dev" 'SwaggerModule\.setup'
grep_check MEDIUM BE-LOGPII "Logging secrets/PII (password, token, card)" '(console\.(log|info|debug)|logger\.(log|info|debug|warn))\([^)]*(password|token|authorization|cardNumber|cvv|ssn)' -i
grep_check LOW    BE-STACK  "Stack trace / raw error returned to client" '(res\.(send|json)\([^)]*(err|error)\.stack|stack[[:space:]]*:[[:space:]]*(err|error|e)\.stack)'
grep_check LOW    BE-SYNC   "TypeORM synchronize:true (schema auto-alter) - must be off in prod" 'synchronize[[:space:]]*:[[:space:]]*true'

# -----------------------------------------------------------------------------
echo "${BLU}[3/7] MongoDB, S3 & NestJS access-control checks${RST}"
# -----------------------------------------------------------------------------
absent_check HIGH   DB-SANITIZE "No Mongo operator-injection protection (express-mongo-sanitize / mongoose sanitizeFilter). A body like {\"email\":{\"\$ne\":null}} can bypass filters" '(mongo-sanitize|mongoSanitize|sanitizeFilter|@nestjs-mongo-sanitize)' "(mongoose|@nestjs/mongoose)"
grep_check MEDIUM DB-STRICTQ  "Mongoose strictQuery disabled - unknown filter keys reach MongoDB" 'strictQuery["'"'"']?[[:space:]]*[,:][[:space:]]*false'
grep_check HIGH   DB-REGEX    "User input used as \$regex (ReDoS / data scraping) - escape with escape-string-regexp" '\$regex[[:space:]]*:[[:space:]]*(req\.|query\.|body\.|dto\.|params\.|search|keyword|term|filter\.)'
grep_check MEDIUM DB-TLS      "MongoDB connection with TLS disabled" '(tls|ssl)=false|(tls|ssl)[[:space:]]*:[[:space:]]*false'
grep_check LOW    DB-AUTOIDX  "autoIndex enabled - should be off in production" 'autoIndex[[:space:]]*:[[:space:]]*true'
grep_check MEDIUM S3-KEY      "S3 object key built from user input (overwrite / path tricks) - generate keys server-side (uuid)" 'Key[[:space:]]*:[[:space:]]*(`[^`]*\$\{[^}]*(originalname|body|dto|query|params)|file\.originalname|dto\.|body\.)'
grep_check MEDIUM S3-PRESIGN  "Long-lived S3 presigned URL (> 1h) - invoices/attachments stay shareable" 'expiresIn[[:space:]]*:[[:space:]]*([0-9]{5,}|[0-9]+[[:space:]]*\*[[:space:]]*60[[:space:]]*\*[[:space:]]*60[[:space:]]*\*)'
grep_check MEDIUM BE-PORTAL   "Public customer-portal endpoint - verify links use random, expiring, single-tenant tokens (frontend skips auth header for /customer-portal)" '@Controller\([^)]*customer-portal|customer-portal'
# Controllers with no guard, when there is no global guard
if ! grep -rqE "${EXCLUDES[@]}" "${CODE_INC[@]}" -e 'APP_GUARD|useGlobalGuards' "${SCAN_PATHS[@]}" 2>/dev/null; then
  for root in "${SCAN_PATHS[@]}"; do
    while IFS= read -r cf; do
      grep -qE 'UseGuards|@Public|AuthGuard' "$cf" || record HIGH BE-NOGUARD "Controller has no @UseGuards and there is no global APP_GUARD - endpoints may be unauthenticated" "$cf" "$(grep -m1 -oE '@Controller\([^)]*\)' "$cf")"
    done < <(find "$root" -name node_modules -prune -o -type f -name '*.controller.ts' -print 2>/dev/null)
  done
fi
for root in "${SCAN_PATHS[@]}"; do
  while IFS= read -r tc; do
    grep -qE '"strict"[[:space:]]*:[[:space:]]*true' "$tc" || record LOW TS-STRICT "TypeScript strict mode not enabled in this tsconfig" "$tc" ""
  done < <(find "$root" -name node_modules -prune -o -type f -name 'tsconfig*.json' -print 2>/dev/null | grep -vE 'tsconfig\.(node|spec|test)')
done

# -----------------------------------------------------------------------------
echo "${BLU}[4/7] Payments (Stripe, Rainforest) & QuickBooks${RST}"
# -----------------------------------------------------------------------------
grep_check HIGH   PAY-RFKEY   "Rainforest API key hard-coded" '[Rr]ainforest[A-Za-z_]*(Key|KEY|Secret|SECRET)[A-Za-z_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_-]{16,}'
grep_check HIGH   PAY-RFWH    "Rainforest webhook handler - verify the signature with the signing secret on the RAW body and reject replays (timestamp)" '@Post\([^)]*([Rr]ainforest|rf-webhook|buddy-?pay)'
be_absent_check HIGH PAY-RFSIG   "Rainforest used but no webhook signature verification found (svix / signing secret / HMAC compare)" '(svix|[Ww]ebhook[A-Za-z]*\.verify|verifyWebhook|RAINFOREST_WEBHOOK_SECRET|webhookSecret|timingSafeEqual)' '[Rr]ainforest'
grep_check HIGH   PAY-AMOUNT  "Payment amount taken from client request - recompute from the invoice/quote in the DB" '(amount|total|unit_amount)[[:space:]]*:[[:space:]]*(dto|body|req\.body|payload|data)\.(amount|total|price)'
grep_check MEDIUM PAY-IDEMP   "Payment create call - make sure an idempotency key is sent (prevents double charges on retry)" '(paymentIntents|charges|refunds|transfers)\.create\('
grep_check MEDIUM PAY-METADATA "Stripe/Rainforest metadata or account id from request - verify it belongs to the caller's company (connected-account confusion)" '(stripeAccount|merchant_?[Ii]d|merchantId|connectedAccount)[[:space:]]*:[[:space:]]*(dto|body|req\.body|query)\.'
grep_check HIGH   QB-SECRET   "QuickBooks / Intuit client secret hard-coded" '(QB|QUICKBOOKS|INTUIT|[Qq]uickbooks|[Ii]ntuit)[A-Za-z_]*([Ss]ecret|SECRET)[A-Za-z_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_-]{16,}'
grep_check MEDIUM QB-TOKENS   "QuickBooks OAuth tokens persisted - encrypt refresh/access tokens at rest (KMS / AES-GCM), never return them to the client" '(qb|quickbooks|intuit|QB|Quickbooks|Intuit)[A-Za-z]*(RefreshToken|AccessToken|refresh_token|access_token)'
grep_check MEDIUM QB-OAUTH    "OAuth callback - verify the 'state' parameter (CSRF) and bind realmId to the logged-in company" '@Get\([^)]*(callback|oauth|connect)'
be_absent_check MEDIUM QB-WHSIG  "QuickBooks integration found but no intuit-signature verification (needed if QBO webhooks are enabled)" '(intuit-signature|INTUIT_VERIFIER|verifierToken|verifier_token|webhooksVerifier)' '([Qq]uickbooks|[Ii]ntuit|node-quickbooks|intuit-oauth)'
grep_check MEDIUM QB-SANDBOX  "Intuit/Stripe/Rainforest environment hard-coded - should come from config per environment" "(environment[[:space:]]*:[[:space:]]*['\"](production|sandbox)['\"]|useSandbox[[:space:]]*:[[:space:]]*(true|false))"

# -----------------------------------------------------------------------------
echo "${BLU}[5/7] Frontend (React / Vite) checks${RST}"
# -----------------------------------------------------------------------------
grep_check HIGH   FE-SRCMAP "Source maps published to production/staging - full source code is downloadable (confirmed on staging: /assets/index-*.js.map)" 'sourcemap[[:space:]]*:[[:space:]]*(true|["'"'"']inline["'"'"'])'
for root in "${SCAN_PATHS[@]}"; do
  for vc in "$root"/vite.config.* "$root"/*/vite.config.* "$root"/apps/*/vite.config.* "$root"/packages/*/vite.config.*; do
    [ -f "$vc" ] || continue
    if grep -qE 'sentry(VitePlugin|-vite-plugin)' "$vc" && ! grep -qE 'filesToDeleteAfterUpload|deleteAfterUpload|sourcemap[[:space:]]*:[[:space:]]*["'"'"']hidden' "$vc"; then
      record HIGH FE-SRCMAP2 "Sentry plugin uploads source maps but does not delete them from dist (use sourcemaps.filesToDeleteAfterUpload or build.sourcemap:'hidden')" "$vc" ""
    fi
  done
done
grep_check HIGH   FE-XSS    "dangerouslySetInnerHTML - ensure value is sanitized with DOMPurify" 'dangerouslySetInnerHTML'
grep_check HIGH   FE-DOM    "Direct DOM HTML sink" '\.(innerHTML|outerHTML)[[:space:]]*=|insertAdjacentHTML\(|document\.write\('
grep_check MEDIUM FE-TOKEN  "Auth token stored where JS can read it (cookie via document.cookie / localStorage) - stolen by any XSS. Prefer HttpOnly cookie set by API" '(document\.cookie[[:space:]]*=|localStorage\.setItem\([^)]*(token|auth|jwt|key))' -i
grep_check MEDIUM FE-JSURL  "javascript: URL or user-controlled href/src" '(href|src)=\{[^}]*(\.url|link|href|redirect)[^}]*\}|javascript:'
grep_check LOW    FE-BLANK  "target=_blank without rel=noopener" 'target=["'"'"'{]_blank'
grep_check LOW    FE-PII    "PII (email/name) sent to Sentry / analytics - confirm this is allowed by privacy policy" '(Sentry\.setUser|ReactGA\.set|gtag\([^)]*user)'
grep_check LOW    FE-CONSOLE "console.* only disabled when DEBUG=='production' - check this env var is actually set in builds" 'process\.env\.DEBUG[[:space:]]*===?[[:space:]]*["'"'"']production'
grep_check MEDIUM FE-POSTMSG "window.addEventListener('message') handler - verify it checks event.origin before trusting the data (cross-origin message injection)" "addEventListener\(\s*['\"]message['\"]"
grep_check LOW    FE-SRI     "External <script>/<link> to a third-party CDN without an integrity= (SRI) attribute - a compromised CDN could inject code" "<(script|link)[^>]*(src|href)=[\"'](https?:)?//(?!localhost)[^\"']+[\"'][^>]*>"
grep_check MEDIUM FE-WINOPEN "window.open / location assigned from a variable - open-redirect / tabnabbing if the value is user-controlled" "(window\.open\(|location\.(href|assign|replace)\(\s*)[^)'\"]*((req|query|params|search|url|redirect|return|next)\w*)" -i

# -----------------------------------------------------------------------------
echo "${BLU}[6/7] Infra (Docker / nginx / CloudFront / CI)${RST}"
# -----------------------------------------------------------------------------
for root in "${SCAN_PATHS[@]}"; do
  while IFS= read -r df; do
    grep -qE '^[[:space:]]*USER[[:space:]]+' "$df" || record MEDIUM IN-ROOT "Container runs as root (no USER)" "$df" ""
    grep -nE '^[[:space:]]*FROM[[:space:]]+[^ :]+(:latest)?[[:space:]]*($|AS)' "$df" | while IFS= read -r l; do record LOW IN-LATEST "Unpinned base image" "$df:${l%%:*}" "${l#*:}"; done
    grep -nE '^(ENV|ARG)[[:space:]]+[A-Z_]*(SECRET|PASSWORD|TOKEN|KEY)' "$df" | while IFS= read -r l; do record HIGH IN-DSECRET "Secret baked into image via ENV/ARG" "$df:${l%%:*}" "${l#*:}"; done
    grep -nE '^COPY[[:space:]]+\.[[:space:]]' "$df" >/dev/null && [ ! -f "$(dirname "$df")/.dockerignore" ] && record MEDIUM IN-DIGNORE "COPY . without .dockerignore (may ship .env/.git)" "$df" ""
    grep -nE '^[[:space:]]*ADD[[:space:]]+https?://|curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh' "$df" | while IFS= read -r l; do record MEDIUM IN-DADDURL "Dockerfile fetches and runs remote content (ADD url / curl|sh) - pin and verify checksums" "$df:${l%%:*}" "${l#*:}"; done
    grep -nqiE 'NODE_TLS_REJECT_UNAUTHORIZED[[:space:]=]+0|npm[[:space:]]+config[[:space:]]+set[[:space:]]+strict-ssl[[:space:]]+false' "$df" && record HIGH IN-DTLS "Dockerfile disables TLS verification" "$df" ""
  done < <(find "$root" -name node_modules -prune -o -type f \( -name 'Dockerfile*' -o -name '*.dockerfile' \) -print 2>/dev/null)
  while IFS= read -r nf; do
    grep -q 'server_tokens[[:space:]]*off' "$nf" || record LOW IN-NGXVER "nginx server_tokens not off (version disclosure)" "$nf" ""
    grep -qiE 'Strict-Transport-Security' "$nf" || record MEDIUM IN-NGXHSTS "nginx: no HSTS header" "$nf" ""
    grep -qE 'client_max_body_size' "$nf" || record LOW IN-NGXBODY "nginx: no client_max_body_size" "$nf" ""
  done < <(find "$root" -name node_modules -prune -o -type f \( -name 'nginx*.conf' -o -path '*nginx*/*.conf' -o -name '*.nginx' \) -print 2>/dev/null)
  while IFS= read -r wf; do
    grep -nE '(password|secret|token|api_key)[[:space:]]*:[[:space:]]*[^$ {][^[:space:]]{6,}' -i "$wf" | grep -v '\${{' | while IFS= read -r l; do record HIGH IN-CISECRET "Plain-text secret in CI config" "$wf:${l%%:*}" "${l#*:}"; done
    grep -nE 'pull_request_target' "$wf" | while IFS= read -r l; do record MEDIUM IN-PRT "pull_request_target workflow - check it does not checkout PR code" "$wf:${l%%:*}" ""; done
    grep -nE '\$\{\{[[:space:]]*github\.event\.(issue|pull_request|comment|review|head_ref|head_commit|discussion)' "$wf" | while IFS= read -r l; do record HIGH CI-INJECTION "Untrusted GitHub event data interpolated into a workflow - script injection; pass it through an env var instead of inline \${{ }}" "$wf:${l%%:*}" "${l#*:}"; done
    grep -nE 'uses:[[:space:]]*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(main|master|v?[0-9]+)([[:space:]]|$)' "$wf" | grep -v '@[0-9a-f]\{40\}' | head -3 | while IFS= read -r l; do record LOW CI-UNPINNED "Third-party action pinned to a tag/branch, not a commit SHA (supply-chain)" "$wf:${l%%:*}" "${l#*:}"; done
    grep -nE 'aws s3 sync[^#]*dist' "$wf" | grep -v -- '--exclude[^#]*\.map' | while IFS= read -r l; do record HIGH IN-S3MAP "Deploy syncs dist/ to S3 without excluding *.map" "$wf:${l%%:*}" "${l#*:}"; done
  done < <(find "$root" -type f \( -path '*/.github/workflows/*' -o -name 'bitbucket-pipelines.yml' -o -name '.gitlab-ci.yml' -o -name 'buildspec*.yml' -o -name 'Jenkinsfile' \) 2>/dev/null)
done

# -----------------------------------------------------------------------------
echo "${BLU}[6.5/7] Deep backend analysis (routes, tenant isolation, DTOs, schemas, crypto)${RST}"
# -----------------------------------------------------------------------------
# Multi-line parsing that grep cannot do: maps every controller route to its
# guard/role/tenant-context, finds unscoped Mongo queries (IDOR), unvalidated
# DTO fields, unsafe schema fields, auth-flow and crypto weaknesses, exposed
# docker-compose databases, and dependencies pinned to versions with known CVEs.
if have python3 && [ -f "$LIBDIR/deep_scan.py" ]; then
  python3 -I "$LIBDIR/deep_scan.py" "$FINDINGS" "$ROUTES_CSV" "${SCAN_PATHS[@]}" || echo "  ${YEL}deep scan error${RST}"
  [ -f "$ROUTES_CSV" ] && echo "  route inventory -> $ROUTES_CSV"
else
  echo "  ${YEL}skipped (needs python3 and lib/deep_scan.py)${RST}"
fi

# -----------------------------------------------------------------------------
echo "${BLU}[7/7] External scanners (dependencies, SAST, history secrets)${RST}"
# -----------------------------------------------------------------------------
if [ "${SKIP_TOOLS:-0}" != "1" ]; then
  for root in "${SCAN_PATHS[@]}"; do
    name="$(basename "$root")"
    # npm/yarn/pnpm audit for every package with a lockfile
    while IFS= read -r lock; do
      d="$(dirname "$lock")"; tag="$name-$(echo "${d#$root}" | tr '/' '_')"
      case "$lock" in
        *package-lock.json) have npm  && (cd "$d" && npm audit --omit=dev --json > "$OUT_DIR/npm-audit$tag.json" 2>/dev/null) ;;
        *yarn.lock)         have yarn && (cd "$d" && yarn npm audit --json > "$OUT_DIR/yarn-audit$tag.json" 2>/dev/null || yarn audit --json > "$OUT_DIR/yarn-audit$tag.json" 2>/dev/null) ;;
        *pnpm-lock.yaml)    have pnpm && (cd "$d" && pnpm audit --prod --json > "$OUT_DIR/pnpm-audit$tag.json" 2>/dev/null) ;;
      esac
      f="$(ls -t "$OUT_DIR"/*audit"$tag".json 2>/dev/null | head -1)"
      if [ -n "$f" ] && have python3; then
        python3 -I - "$f" "$d" <<'PY' >> "$FINDINGS"
import json,sys
f,d=sys.argv[1],sys.argv[2]
try: j=json.load(open(f))
except Exception: sys.exit()
for name,v in (j.get("vulnerabilities") or {}).items():
    sev=(v.get("severity") or "low").upper()
    sev={"CRITICAL":"HIGH","HIGH":"HIGH","MODERATE":"MEDIUM"}.get(sev,"LOW")
    via=[x.get("title","") for x in v.get("via",[]) if isinstance(x,dict)][:1]
    print(f"{sev}\tDEP-{name}\tVulnerable dependency {name} {v.get('range','')}\t{d}/package.json\t{(via or [''])[0]} fix:{bool(v.get('fixAvailable'))}")
PY
      fi
    done < <(find "$root" -name node_modules -prune -o -type f \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -print 2>/dev/null)

    if ! have osv-scanner && docker_ok; then
      docker run --rm -v "$root:/src:ro" ghcr.io/google/osv-scanner:latest scan source -r /src --format markdown > "$OUT_DIR/osv-$name.md" 2>/dev/null && echo "  osv-scanner (docker) -> $OUT_DIR/osv-$name.md"
    fi
    if have osv-scanner; then
      osv-scanner scan source -r "$root" --format markdown > "$OUT_DIR/osv-$name.md" 2>/dev/null || true
      echo "  osv-scanner -> $OUT_DIR/osv-$name.md"
    fi
    GL=""; have gitleaks && GL="gitleaks"
    if [ -z "$GL" ] && docker_ok; then GL="docker"; fi
    if [ -n "$GL" ]; then
      if [ "$GL" = "gitleaks" ]; then
        gitleaks detect -s "$root" --no-banner -f json -r "$OUT_DIR/gitleaks-$name.json" >/dev/null 2>&1
      else
        docker run --rm -v "$root:/src:ro" -v "$(cd "$OUT_DIR" && pwd):/out" zricethezav/gitleaks:latest detect -s /src --no-banner -f json -r "/out/gitleaks-$name.json" >/dev/null 2>&1
      fi
      if have python3 && [ -s "$OUT_DIR/gitleaks-$name.json" ]; then
        python3 -I -c '
import json,sys
for x in json.load(open(sys.argv[1])):
    print("HIGH\tGITLEAKS-%s\tSecret in repo/git history (%s)\t%s:%s\tcommit %s" % (x.get("RuleID"),x.get("Description"),x.get("File"),x.get("StartLine"),(x.get("Commit") or "")[:10]))
' "$OUT_DIR/gitleaks-$name.json" >> "$FINDINGS"
      fi
      echo "  gitleaks   -> $OUT_DIR/gitleaks-$name.json"
    fi
    SG_CFG="--config p/typescript --config p/javascript --config p/nodejsscan --config p/react --config p/secrets --config p/jwt --config p/expressjs --config p/owasp-top-ten --exclude node_modules --exclude dist"
    SG=""; have semgrep && SG="semgrep"; [ -z "$SG" ] && docker_ok && SG="docker"
    if [ -n "$SG" ]; then
      if [ "$SG" = "semgrep" ]; then
        semgrep scan --quiet $SG_CFG --json -o "$OUT_DIR/semgrep-$name.json" "$root" >/dev/null 2>&1
      else
        docker run --rm -v "$root:/src:ro" -v "$(cd "$OUT_DIR" && pwd):/out" semgrep/semgrep:latest semgrep scan --quiet $SG_CFG --json -o "/out/semgrep-$name.json" /src >/dev/null 2>&1
      fi
      if have python3 && [ -s "$OUT_DIR/semgrep-$name.json" ]; then
        python3 -I -c '
import json,sys
for r in json.load(open(sys.argv[1])).get("results",[]):
    s=r["extra"].get("severity","INFO"); s={"ERROR":"HIGH","WARNING":"MEDIUM"}.get(s,"LOW")
    print("%s\tSG-%s\t%s\t%s:%s\t%s" % (s, r["check_id"].split(".")[-1], r["extra"]["message"].replace("\n"," ")[:150].replace("\t"," "), r["path"], r["start"]["line"], ""))
' "$OUT_DIR/semgrep-$name.json" >> "$FINDINGS"
      fi
      echo "  semgrep    -> $OUT_DIR/semgrep-$name.json"
    fi
    if have trivy; then
      trivy fs --quiet --scanners vuln,misconfig,secret --format table -o "$OUT_DIR/trivy-$name.txt" "$root" 2>/dev/null || true
    elif docker_ok; then
      docker run --rm -v "$root:/src:ro" aquasec/trivy:latest fs --quiet --scanners vuln,misconfig,secret --format table /src > "$OUT_DIR/trivy-$name.txt" 2>/dev/null || true
      echo "  trivy      -> $OUT_DIR/trivy-$name.txt"
    fi
  done
  if ! docker_ok; then
    for t in semgrep gitleaks osv-scanner trivy; do have $t || echo "  ${YEL}skipped $t (not installed: brew install $t, or install Docker)${RST}"; done
  fi
fi

# -----------------------------------------------------------------------------
echo "${BLU}[+] Live checks (passive, read-only)${RST}"
# -----------------------------------------------------------------------------
# The live probe only makes ordinary, well-formed HTTP requests (the same shape
# a browser makes) and reads the responses. It never injects, brute-forces,
# floods, or forges anything, so it is safe against production.
if [ -n "${LIVE_URL:-}${LIVE_API:-}" ] && have python3 && [ -f "$LIBDIR/live_probe.py" ]; then
  APP_URL="${LIVE_URL:-}" API_URL="${LIVE_API:-}" SIGNIN_PATH="${SIGNIN_PATH:-/user/signin}" \
  AUTH_TOKEN="${AUTH_TOKEN:-}" OUT_DIR="$OUT_DIR" \
    python3 -I "$LIBDIR/live_probe.py" "$FINDINGS" || echo "  ${YEL}live probe error${RST}"
else
  echo "  ${DIM}skipped (set LIVE_URL and/or LIVE_API; needs python3)${RST}"
fi

# -----------------------------------------------------------------------------
#  Report
# -----------------------------------------------------------------------------
sort -u -o "$FINDINGS" "$FINDINGS"
gate_of() {
  case "$1" in
    SEC-*|GITLEAKS-*|IN-DSECRET|IN-CISECRET|IN-COMPOSESECRET|PAY-RFKEY|QB-SECRET|AUTH-BACKDOOR) echo G1 ;;
    DEP-*) echo G2 ;;
    BE-SQLI*|BE-NOSQL|BE-WHERE|BE-REGEX|BE-RCE|BE-CMD|BE-SSRF|BE-PATH|BE-REDIR|BE-PROTO|BE-MASS|BE-WEAKHASH|BE-BCRYPT|BE-RAND|BE-TLS|DB-*|SG-*|BE-LOGPII|BE-STACK|LOG-BODY|SSTI|XXE|DESERIALIZE|SANDBOX-VM2|CRYPTO-*|PDF-*|CSV-INJECTION) echo G3 ;;
    BE-JWT*|BE-PUBLIC|BE-IDOR|BE-ENUM|BE-RATELIMIT|BE-NOGUARD|BE-PORTAL|BE-SELECT|FE-TOKEN|ROUTE-*|TENANT-*|DTO-*|AUTH-*|WS-*|SCHEMA-PWSELECT) echo G4 ;;
    PAY-*|QB-*|BE-STRIPE*|BE-WEBHOOK|WEBHOOK-*|BE-UPLOAD|S3-*|BE-S3ACL|SCHEMA-CARD|SCHEMA-PII|SCHEMA-TOKEN|SCHEMA-NOTENANT|MAIL-*) echo G5 ;;
    FE-*) echo G6 ;;
    LV-*) echo G8 ;;
    IN-DBPORT|IN-MONGOAUTH|IN-REDISAUTH|EXPOSE-*|NEST-*|DOS-*|TS-STRICT) echo G7 ;;
    *) echo G7 ;;
  esac
}
gate_name() { case "$1" in G1) echo "Secrets";; G2) echo "Dependencies (CVEs)";; G3) echo "Injection & unsafe code";; G4) echo "AuthN / AuthZ / tenant isolation";; G5) echo "Payments, QuickBooks, files & PII";; G6) echo "Frontend (React/Vite)";; G7) echo "Config & infrastructure";; G8) echo "Live checks (black-box)";; esac; }
GATES_TSV="$OUT_DIR/gates.tsv"; : > "$GATES_TSV"
ANY_FAIL=0
for g in G1 G2 G3 G4 G5 G6 G7 G8; do
  h=0; m=0; l=0
  while IFS=$'\t' read -r sev id _rest; do
    [ "$(gate_of "$id")" = "$g" ] || continue
    case "$sev" in HIGH) h=$((h+1));; MEDIUM) m=$((m+1));; LOW) l=$((l+1));; esac
  done < "$FINDINGS"
  st=PASS; [ $m -gt 0 ] && st=WARN; [ $h -gt 0 ] && { st=FAIL; ANY_FAIL=1; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$g" "$(gate_name $g)" "$st" "$h" "$m" "$l" >> "$GATES_TSV"
done
nH=$(grep -c '^HIGH' "$FINDINGS"); nM=$(grep -c '^MEDIUM' "$FINDINGS"); nL=$(grep -c '^LOW' "$FINDINGS")
{
  echo "# Service Buddy - Security Scan Report"
  echo
  echo "_Generated $(date '+%Y-%m-%d %H:%M')_"
  echo
  echo "- Code scanned: \`${SCAN_PATHS[*]}\`"
  [ -n "${LIVE_URL:-}" ] && echo "- Live web app (passive): ${LIVE_URL}"
  [ -n "${LIVE_API:-}" ] && echo "- Live API (passive): ${LIVE_API}"
  echo "- Open \`REPORT.html\` for the interactive version; \`findings.sarif\` for GitHub code scanning; \`routes.csv\` for the API route inventory."
  echo
  echo "| Severity | Count |"; echo "|---|---|"
  echo "| HIGH | $nH |"; echo "| MEDIUM | $nM |"; echo "| LOW | $nL |"
  echo
  echo "## Security gates"; echo
  echo "| Gate | Area | Result | High | Medium | Low |"; echo "|---|---|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | **%s** | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6}' "$GATES_TSV"
  echo
  echo "> Pattern checks are heuristics: every HIGH/MEDIUM line should be reviewed by a developer."
  echo "> IDOR items list every lookup-by-id; confirm each one also filters by the logged-in user's company/tenant."
  for sev in HIGH MEDIUM LOW; do
    echo; echo "## $sev"; echo
    awk -F'\t' -v s="$sev" '$1==s{print $2"\t"$3}' "$FINDINGS" | sort | uniq -c | sort -rn | while IFS= read -r l; do
      cnt="$(echo "$l" | awk '{print $1}')"; rest="$(echo "$l" | sed -E 's/^ *[0-9]+ //')"
      id="${rest%%	*}"; title="${rest#*	}"
      echo "### [$id] $title  ($cnt)"
      awk -F'\t' -v s="$sev" -v i="$id" '$1==s && $2==i {printf "- `%s` %s\n", $4, ($5!="" ? "— `" $5 "`" : "")}' "$FINDINGS" | head -40
      [ "$cnt" -gt 40 ] && echo "- ... $((cnt-40)) more in findings.tsv"
      echo
    done
  done
  echo
  echo "## Hand-off to Claude Code"
  echo
  echo "Open the API repo in Claude Code and paste the prompt in \`CLAUDE_CODE_PROMPT.md\` (written next to this report). It triages every finding here, verifies the backend route-by-route (auth, roles, tenant isolation/IDOR, payments, QuickBooks, files, secrets) and writes \`BACKEND_RESULTS.md\` with filled gate and issue tables."
  if [ -f "$LIBDIR/claude_code_prompt.md" ]; then
    echo
    echo '<details><summary>Claude Code prompt</summary>'
    echo
    echo '```text'
    cat "$LIBDIR/claude_code_prompt.md"
    echo '```'
    echo
    echo '</details>'
  fi
} > "$REPORT"

# ---- Claude Code hand-off prompt (standalone file) ----
[ -f "$LIBDIR/claude_code_prompt.md" ] && cp "$LIBDIR/claude_code_prompt.md" "$OUT_DIR/CLAUDE_CODE_PROMPT.md" \
  && echo "  Claude Code prompt -> $OUT_DIR/CLAUDE_CODE_PROMPT.md"

# ---- HTML report + SARIF (for GitHub code scanning) ----
if have python3; then
  FINDINGS="$FINDINGS" GATES_TSV="$GATES_TSV" OUT_DIR="$OUT_DIR" ROUTES_CSV="$ROUTES_CSV" \
  TARGET="${LIVE_API:-${LIVE_URL:-local code}}" SCANPATHS="${SCAN_PATHS[*]}" \
    python3 -I "$LIBDIR/report.py" 2>/dev/null \
    && echo "  HTML report -> $OUT_DIR/REPORT.html" \
    && echo "  SARIF       -> $OUT_DIR/findings.sarif"
fi

echo
echo "${BLU}Security gates${RST}"
while IFS=$'\t' read -r g n st h m l; do
  c=$GRN; [ "$st" = WARN ] && c=$YEL; [ "$st" = FAIL ] && c=$RED
  printf '  %s %-32s %s%-4s%s  H:%s M:%s L:%s\n' "$g" "$n" "$c" "$st" "$RST" "$h" "$m" "$l"
done < "$GATES_TSV"
echo "${RED}HIGH: $nH${RST}  ${YEL}MEDIUM: $nM${RST}  ${GRN}LOW: $nL${RST}"
echo "Report:   $REPORT"
echo "Raw TSV:  $FINDINGS"
[ "$ANY_FAIL" -eq 1 ] && exit 1 || exit 0
