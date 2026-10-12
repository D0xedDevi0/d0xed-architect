"""Master polyglot knowledge base: languages, secret rules, per-language risk
packs, manifests/SBOM ecosystems, entrypoints, IaC and supply-chain signals.

Pure DATA. No network, no execution, no credentials. Everything here is a
compiled regex or a small tuple; `devin.analysis` is the engine that applies it.

Rule tuple shapes (identical to `architect.audit` so severity mapping is shared):
    SECRET_RULES: (name, pattern, score)            score>=90 crit, >=70 high, >=30 med
    RISK_RULES  : (name, pattern, score, why)
A score of 0 marks a purely informational signal (reported, never scored).
"""
from __future__ import annotations

import re

# ── languages ──────────────────────────────────────────────────────────────
# Broad on purpose: "any code language" means the scanner must at least name
# and read it. Language is used for the risk pack, entrypoints and stats.

LANG_BY_EXT = {
    # python
    ".py": "Python", ".pyi": "Python", ".pyx": "Cython", ".ipynb": "Notebook",
    # js/ts
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".mts": "TypeScript", ".cts": "TypeScript", ".vue": "Vue",
    ".svelte": "Svelte", ".astro": "Astro",
    # jvm
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".sc": "Scala", ".groovy": "Groovy", ".gradle": "Gradle", ".clj": "Clojure",
    ".cljs": "ClojureScript", ".cljc": "Clojure", ".edn": "Clojure",
    # systems
    ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C", ".cc": "C++",
    ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".cs": "C#",
    ".vb": "VB.NET", ".fs": "F#", ".fsx": "F#", ".swift": "Swift",
    ".m": "Objective-C", ".mm": "Objective-C++", ".zig": "Zig", ".d": "D",
    ".nim": "Nim", ".v": "V", ".ada": "Ada", ".adb": "Ada", ".f90": "Fortran",
    ".f": "Fortran", ".jl": "Julia",
    # scripting
    ".rb": "Ruby", ".rake": "Ruby", ".gemspec": "Ruby", ".php": "PHP",
    ".phtml": "PHP", ".pl": "Perl", ".pm": "Perl", ".t": "Perl",
    ".lua": "Lua", ".r": "R", ".R": "R", ".dart": "Dart", ".tcl": "Tcl",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hrl": "Erlang",
    ".hs": "Haskell", ".lhs": "Haskell", ".ml": "OCaml", ".mli": "OCaml",
    ".nimble": "Nim", ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch",
    # shells
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".fish": "Fish",
    ".ksh": "Shell",
    # data / query
    ".sql": "SQL", ".psql": "SQL", ".mysql": "SQL", ".plsql": "SQL",
    ".tsql": "SQL", ".cypher": "Cypher", ".graphql": "GraphQL",
    ".gql": "GraphQL", ".proto": "Protobuf", ".thrift": "Thrift",
    # chain
    ".sol": "Solidity", ".vy": "Vyper", ".cairo": "Cairo", ".move": "Move",
    ".func": "FunC", ".tact": "Tact", ".teal": "TEAL", ".clar": "Clarity",
    ".sway": "Sway", ".fc": "FunC",
    # config / iac / ci
    ".tf": "Terraform", ".tfvars": "Terraform", ".hcl": "HCL",
    ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".json5": "JSON5",
    ".toml": "TOML", ".ini": "INI", ".cfg": "INI", ".conf": "Config",
    ".env": "Dotenv", ".properties": "Properties", ".xml": "XML",
    ".plist": "Plist", ".nix": "Nix", ".dhall": "Dhall",
    ".dockerfile": "Dockerfile", ".cmake": "CMake", ".mk": "Makefile",
    ".bzl": "Bazel", ".tpl": "Template", ".j2": "Jinja", ".tfstate": "Terraform",
}
CODE_EXTS = frozenset(LANG_BY_EXT)

# Extensionless / dotfile names that are still code or config worth reading.
LANG_BY_NAME = {
    "Dockerfile": "Dockerfile", "dockerfile": "Dockerfile",
    "Containerfile": "Dockerfile", "Makefile": "Makefile",
    "makefile": "Makefile", "GNUmakefile": "Makefile", "CMakeLists.txt": "CMake",
    "Jenkinsfile": "Groovy", "Vagrantfile": "Ruby", "Gemfile": "Ruby",
    "Rakefile": "Ruby", "Brewfile": "Ruby", "Podfile": "Ruby",
    "BUILD": "Bazel", "WORKSPACE": "Bazel", "BUILD.bazel": "Bazel",
    ".env": "Dotenv", ".env.local": "Dotenv", ".env.production": "Dotenv",
    ".env.example": "Dotenv", ".npmrc": "INI", ".pypirc": "INI",
    ".netrc": "Config", ".htpasswd": "Config", ".gitlab-ci.yml": "YAML",
    ".travis.yml": "YAML", "Procfile": "Config", "Justfile": "Makefile",
    "Taskfile.yml": "YAML", "Chart.yaml": "YAML", "Cargo.toml": "TOML",
    "go.mod": "Go", "requirements.txt": "Text",
}
# Extensionless filenames that are ALWAYS read: key material, credential
# stores, and netrc-style files. These carry secrets but have no extension.
SECRET_ONLY_NAMES = frozenset({
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
    "authorized_keys", "known_hosts", ".netrc", ".npmrc", ".pypirc",
    ".htpasswd", ".pgpass", ".my.cnf", ".git-credentials", "credentials",
    "secrets", "secrets.yml", "secrets.yaml", "secrets.json", "kubeconfig",
    ".bash_history", ".zsh_history", ".psql_history", ".mysql_history",
    "terraform.tfstate", "id_rsa_old", "server.key", "server.pem",
})

# Files scanned for secrets even though they are not "code".
SECRET_ONLY_EXTS = frozenset({
    ".md", ".markdown", ".rst", ".txt", ".log", ".pem", ".key", ".crt",
    ".cer", ".p12", ".pfx", ".jks", ".keystore", ".ovpn", ".kdbx", ".sqlite",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".gitconfig", ".bash_history",
})

# ── secrets ────────────────────────────────────────────────────────────────
# Ordered most-specific first so a narrow rule wins over a generic one.

# A credential whose value is an ENVIRONMENT LOOKUP is the correct pattern,
# not a leak. This guard is what keeps `apiKey: process.env.ALCHEMY_KEY` from
# being reported as a hardcoded secret — false positives here are what make a
# scanner untrustworthy.
_ENVREF = (r"(?![\"']?(?:process\.env|import\.meta\.env|os\.environ|os\.getenv"
           r"|getenv|System\.getenv|ENV\[|\$\{|\$[A-Za-z_]|%[A-Za-z_]+%|\{\{|<\?))")

SECRET_RULES = [
    # ── keys & key material ──────────────────────────────────────────────
    ("private_key_pem", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,80}?[A-Za-z0-9+/]{40,}", 99),
    ("openssh_private", r"-----BEGIN OPENSSH PRIVATE KEY-----", 97),
    ("putty_private", r"PuTTY-User-Key-File-\d", 95),
    ("pgp_private", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 97),
    ("ssh_rsa_pubkey_id", r"\bssh-(?:rsa|ed25519|dss)\s+AAAA[A-Za-z0-9+/]{40,}", 25),
    ("age_identity", r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b", 96),
    ("solana_keypair_json", r"\[\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}(?:\s*,\s*\d{1,3}){40,}", 80),
    ("mnemonic_phrase", r"(?i)\b(?:mnemonic|seed[ _-]?phrase|secret[ _-]?phrase)\b\s*[:=]\s*[\"']?(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}", 97),
    ("hex_privkey_ctx", r"(?i)(private[_\- ]?key|privkey|secret[_\- ]?key|signer[_\- ]?key)\s*[:=]\s*[\"']?(?:0x)?[0-9a-fA-F]{64}", 96),
    ("wif_privkey", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", 70),
    # ── cloud / infra ────────────────────────────────────────────────────
    ("aws_access_key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 95),
    ("aws_secret_key", r"(?i)aws[_\- ]?(?:secret|access)[_\- ]?(?:access[_\- ]?)?key\S*\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}", 96),
    ("aws_session_token", r"(?i)aws[_\- ]?session[_\- ]?token\S*\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{100,}", 90),
    ("aws_arn_account", r"\barn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:\d{12}:", 20),
    ("gcp_service_account", r"\"type\"\s*:\s*\"service_account\"(?=[\s\S]{0,400}\"private_key\")", 97),
    ("gcp_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 88),
    ("gcp_oauth_client", r"\bGOCSPX-[A-Za-z0-9_\-]{20,}", 90),
    ("azure_storage_conn", r"DefaultEndpointsProtocol=https;AccountName=[^;]{3,};AccountKey=[A-Za-z0-9+/=]{40,}", 96),
    ("azure_sas", r"(?i)\b(?:sig|sv|se|sp)=\S{20,}&(?:sig|sv|se|sp)=", 75),
    ("azure_client_secret", r"(?i)azure[_\- ]?(?:client|app)[_\- ]?secret\S*\s*[:=]\s*[\"']?[A-Za-z0-9_~.\-]{30,}", 90),
    ("digitalocean_token", r"\bdop_v1_[0-9a-f]{64}\b", 92),
    ("linode_token", r"\b(?:linode|lin)_[A-Za-z0-9]{40,}\b", 85),
    ("vultr_token", r"(?i)vultr[_\- ]?(?:api[_\- ]?)?key\S*\s*[:=]\s*[\"']?[A-Z0-9]{36}", 85),
    ("hetzner_token", r"\b[A-Za-z0-9]{64}\b(?=[^\n]{0,40}hetzner)", 60),
    ("cloudflare_token", r"(?i)cloudflare[_\- ]?(?:api[_\- ]?)?(?:token|key)\S*\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{35,}", 90),
    ("cloudflare_global_key", r"(?i)(?:cf|x-auth)[_\- ]?api[_\- ]?key\S*\s*[:=]\s*[\"']?[0-9a-f]{37}", 88),
    ("vercel_token", r"\bvercel_[A-Za-z0-9]{20,}\b", 88),
    ("netlify_token", r"(?i)netlify[_\- ]?(?:auth|access)[_\- ]?token\S*\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{30,}", 85),
    ("heroku_api_key", r"(?i)heroku[_\- ]?(?:api[_\- ]?)?key\S*\s*[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 85),
    ("firebase_server_key", r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b", 88),
    ("terraform_cloud_token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}", 90),
    # ── ai / dev platforms ───────────────────────────────────────────────
    ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b", 90),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{24,}", 90),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b", 88),
    ("replicate_token", r"\br8_[A-Za-z0-9]{30,}\b", 88),
    ("groq_key", r"\bgsk_[A-Za-z0-9]{40,}\b", 88),
    ("perplexity_key", r"\bpplx-[A-Za-z0-9]{30,}\b", 88),
    ("together_key", r"\b(?:tgp_v1_|[0-9a-f]{64})[A-Za-z0-9_\-]{20,}\b(?=[^\n]{0,40}together)", 60),
    ("elevenlabs_key", r"\bsk_[0-9a-f]{32}[A-Za-z0-9]{16,}\b", 80),
    ("stability_key", r"\bsk-[A-Za-z0-9]{48}\b", 80),
    # ── source control / registries ──────────────────────────────────────
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", 95),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 92),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", 90),
    ("gitlab_pat", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 92),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", 90),
    ("pypi_token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", 90),
    ("rubygems_key", r"\brubygems_[A-Za-z0-9]{48}\b", 88),
    ("nuget_key", r"\boy2[a-z0-9]{43}\b", 85),
    ("dockerhub_pat", r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b", 88),
    ("sonar_token", r"\bsqp_[a-z0-9]{40}\b", 85),
    # ── messaging / comms ────────────────────────────────────────────────
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", 88),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}", 85),
    ("discord_webhook", r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_\-]{50,}", 85),
    ("discord_bot_token", r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b", 88),
    ("telegram_bot_token", r"\b\d{8,12}:AA[A-Za-z0-9_\-]{32,}\b", 88),
    ("twilio_key", r"\bSK[0-9a-fA-F]{32}\b", 85),
    ("twilio_sid", r"\bAC[0-9a-f]{32}\b", 70),
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", 90),
    ("mailgun_key", r"\bkey-[0-9a-f]{32}\b", 80),
    ("mailchimp_key", r"\b[0-9a-f]{32}-us\d{1,2}\b", 85),
    ("postmark_token", r"(?i)postmark[_\- ]?token\S*\s*[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 80),
    ("pushover_token", r"\b[a-zA-Z0-9]{30}\b(?=[^\n]{0,30}pushover)", 55),
    # ── payments / commerce / fintech ────────────────────────────────────
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", 92),
    ("stripe_restricted", r"\brk_live_[A-Za-z0-9]{20,}", 92),
    ("square_token", r"\bEAAA[A-Za-z0-9_\-]{40,}\b", 85),
    ("paypal_client_secret", r"(?i)paypal[_\- ]?(?:client[_\- ]?)?secret\S*\s*[:=]\s*[\"']?E[A-Za-z0-9_\-]{60,}", 88),
    ("braintree_key", r"\baccess_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}\b", 88),
    ("plaid_secret", r"(?i)plaid[_\- ]?secret\S*\s*[:=]\s*[\"']?[a-z0-9]{30,}", 85),
    ("shopify_token", r"\bshpat_[0-9a-f]{32}\b", 88),
    ("shopify_shared", r"\bshpss_[0-9a-f]{32}\b", 85),
    ("coinbase_key", r"(?i)coinbase[_\- ]?(?:api[_\- ]?)?(?:key|secret)\S*\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{30,}", 85),
    ("binance_key", r"(?i)binance[_\- ]?(?:api[_\- ]?)?(?:key|secret)\S*\s*[:=]\s*[\"']?[A-Za-z0-9]{60,}", 85),
    ("kraken_key", r"(?i)kraken[_\- ]?(?:api[_\- ]?)?(?:key|secret)\S*\s*[:=]\s*[\"']?[A-Za-z0-9+/=]{50,}", 85),
    # ── web3 infra ───────────────────────────────────────────────────────
    ("alchemy_key", r"\balch_[A-Za-z0-9_\-]{20,}\b", 80),
    ("infura_key", r"(?i)infura[_\- ]?(?:\w+[_\- ]?){0,2}(?:key|url|project)\S*\s*[:=]\s*[\"']?[0-9a-f]{32}\b", 80),
    ("moralis_key", r"\b[A-Za-z0-9]{60,}\b(?=[^\n]{0,40}moralis)", 55),
    ("etherscan_key", r"\b[A-Z0-9]{34}\b(?=[^\n]{0,40}etherscan)", 55),
    ("walletconnect_id", r"(?i)walletconnect[_\- ]?project[_\- ]?id\S*\s*[:=]\s*[\"']?[0-9a-f]{32}", 60),
    # ── identity / observability / saas ──────────────────────────────────
    ("okta_token", r"\b00[A-Za-z0-9_\-]{40}\b(?=[^\n]{0,30}okta)", 70),
    ("auth0_secret", r"(?i)auth0[_\- ]?(?:client[_\- ]?)?secret\S*\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{30,}", 85),
    ("datadog_key", r"(?i)datadog[_\- ]?(?:api[_\- ]?)?key\S*\s*[:=]\s*[\"']?[0-9a-f]{32}\b", 85),
    ("datadog_app_key", r"(?i)(?:dd|datadog)[_\- ]?application[_\- ]?key\S*\s*[:=]\s*[\"']?[0-9a-f]{40}\b", 85),
    ("newrelic_key", r"\bNRAK-[A-Z0-9]{27}\b", 85),
    ("sentry_dsn", r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/\d+", 70),
    ("sentry_auth_token", r"\bsntrys_[A-Za-z0-9_\-]{30,}\b", 88),
    ("grafana_token", r"\bglc_[A-Za-z0-9_\-]{32,}\b", 85),
    ("algolia_key", r"(?i)algolia[_\- ]?(?:admin[_\- ]?)?(?:api[_\- ]?)?key\S*\s*[:=]\s*[\"']?[0-9a-f]{32}\b", 80),
    ("mapbox_token", r"\bpk\.[A-Za-z0-9._\-]{60,}\b", 75),
    ("segment_write_key", r"(?i)segment[_\- ]?write[_\- ]?key\S*\s*[:=]\s*[\"']?[A-Za-z0-9]{32}", 70),
    ("amplitude_key", r"(?i)amplitude[_\- ]?api[_\- ]?key\S*\s*[:=]\s*[\"']?[a-f0-9]{32}", 65),
    ("contentful_token", r"\bCFPAT-[A-Za-z0-9_\-]{40,}\b", 85),
    ("notion_token", r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b", 88),
    ("airtable_key", r"\bkey[A-Za-z0-9]{14}\b(?=[^\n]{0,30}airtable)", 60),
    ("linear_key", r"\blin_api_[A-Za-z0-9]{40,}\b", 85),
    ("supabase_service", r"\beyJ[A-Za-z0-9_\-]{30,}\.[A-Za-z0-9_\-]{30,}\.[A-Za-z0-9_\-]{20,}\b(?=[^\n]{0,40}supabase)", 70),
    ("planet_scale_pw", r"\bpscale_pw_[A-Za-z0-9_\-]{40,}\b", 85),
    ("neon_key", r"\bnapi_[A-Za-z0-9]{40,}\b", 85),
    ("doppler_token", r"\bdp\.(?:st|pt|sa)\.[A-Za-z0-9_\-]{40,}\b", 88),
    ("hashicorp_vault_token", r"\b(?:hvs|s)\.[A-Za-z0-9_\-]{24,}\b", 85),
    ("doppler_service", r"(?i)doppler[_\- ]?token\S*\s*[:=]\s*[\"']?dp\.\w+\.[A-Za-z0-9_\-]{30,}", 85),
    # ── generic credential shapes ────────────────────────────────────────
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 70),
    ("basic_auth_url", r"\b(?:https?|ftp|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql|clickhouse)://[^\s:/@\"']{1,64}:[^\s:/@\"']{4,64}@", 85),
    ("conn_string_pw", r"(?i)\b(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key)\s*[:=]\s*" + _ENVREF + r"[\"'][^\"'\s]{12,}[\"']", 70),
    ("jdbc_cred", r"jdbc:[a-z]+://[^\s;]{0,60};[^\s;]{0,40}(?:password|pwd)=[^\s;]{4,}", 85),
    ("bearer_literal", r"(?i)authorization\s*[:=]\s*[\"']Bearer\s+[A-Za-z0-9._\-]{20,}", 85),
    ("xml_credential", r"(?i)<(?:password|passwd|secret|apiKey|token)>[^<\s]{8,}</", 85),
    ("yaml_kv_secret", r"(?im)^\s*(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\s*:\s*" + _ENVREF + r"[\"']?[^\s\"'#]{12,}", 65),
    ("docker_env_secret", r"(?im)^\s*ENV\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*\s+\S{12,}", 70),
    ("hardcoded_pw_call", r"(?i)(?:password|passwd|pwd)\s*=\s*" + _ENVREF + r"[\"'][^\"']{8,}[\"']", 60),
    ("webhook_secret", r"(?i)webhook[_\- ]?secret\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}", 75),
    ("slack_signing_secret", r"(?i)slack[_\- ]?signing[_\- ]?secret\S*\s*[:=]\s*[\"']?[0-9a-f]{32}", 80),
    ("encryption_key_32", r"(?i)(?:encryption|aes|cipher|fernet)[_\- ]?key\S*\s*[:=]\s*[\"']?[A-Za-z0-9+/=_\-]{32,}", 70),
    ("totp_seed", r"(?i)(?:totp|otp|mfa)[_\- ]?(?:seed|secret)\S*\s*[:=]\s*[\"']?[A-Z2-7]{16,}", 80),
]

# ── generic risky patterns (every language) ────────────────────────────────

RISK_COMMON = [
    ("eval_use", r"\beval\s*\(", 30, "dynamic code execution surface"),
    ("exec_use", r"\bexec\s*\(", 30, "dynamic code execution surface"),
    ("shell_true", r"shell\s*=\s*True", 35, "command injection risk"),
    ("os_system", r"os\.system\s*\(", 30, "command injection risk"),
    ("os_popen", r"os\.popen\s*\(", 30, "command injection risk"),
    ("subprocess_call", r"subprocess\.(?:call|run|Popen|check_output)\s*\(", 20, "external process invocation"),
    ("innerhtml", r"\.innerHTML\s*=", 25, "DOM XSS risk"),
    ("outerhtml", r"\.outerHTML\s*=", 25, "DOM XSS risk"),
    ("document_write", r"document\.write\s*\(", 25, "DOM XSS risk"),
    ("dangerously_html", r"dangerouslySetInnerHTML", 25, "React XSS risk"),
    ("pickle_load", r"pickle\.loads?\s*\(", 30, "deserialization RCE"),
    ("yaml_load_unsafe", r"yaml\.load\s*\((?![^)]*Safe)[^)]*\)", 25, "unsafe YAML load"),
    ("tls_verify_off", r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|StrictHostKeyChecking\s*=\s*no|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0)", 35, "TLS verification disabled"),
    ("curl_insecure", r"curl\s+[^\n]*-k\b", 25, "TLS verification disabled"),
    ("weak_hash", r"\b(?:md5|sha1|MD5|SHA1)\s*\(", 20, "weak digest"),
    ("md5_ctor", r"(?i)createHash\(\s*[\"'](?:md5|sha1)[\"']", 25, "weak digest"),
    ("math_random_secret", r"(?i)(?:token|password|secret|salt|nonce|key|code).{0,24}(?:Math\.random|rand\(|mt_rand|random\.random|java\.util\.Random|new Random)", 35, "predictable randomness for a secret"),
    ("http_plaintext", r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", 10, "plaintext transport"),
    ("cors_star", r"(?i)access-control-allow-origin['\"]?\s*[:,]\s*['\"]\*", 20, "wildcard CORS"),
    ("cors_star_set", r"(?i)(?:setHeader|header|Headers)\(\s*[\"']Access-Control-Allow-Origin[\"']\s*,\s*[\"']\*[\"']", 20, "wildcard CORS"),
    ("debug_enabled", r"(?i)\b(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)\b", 20, "debug mode in production"),
    ("stack_trace_out", r"(?i)(?:print|echo|printf|console\.log|System\.out)\w*\([^)\n]*(?:stacktrace|stack_trace|traceback|exception)", 20, "stack trace disclosure"),
    ("disable_csrf", r"(?i)(?:@csrf_exempt|csrf_exempt\s*\(|WTF_CSRF_ENABLED\s*[:=]\s*False|csrf\.disable)", 30, "CSRF protection disabled"),
    ("sql_concat", r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\"\n]{0,60}?(?:\"\s*\+|\+\s*\"|\.format\(|%\s*\(|\$\{)", 35, "SQL built by string concatenation"),
    ("sql_format", r"(?i)execute(?:Query)?\s*\(\s*f?[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*\{\w", 35, "f-string SQL (injection)"),
    ("path_join_userinput", r"(?i)(?:open|readfile|sendfile|File\()\s*\([^)\n]*(?:req\.|request\.|params|argv|argv\[)", 25, "path built from user input"),
    ("hardcoded_ip_priv", r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", 5, "internal address hardcoded"),
    ("todo_security", r"(?i)\b(?:TODO|FIXME|HACK|XXX)\b[^\n]{0,80}\b(?:auth|secur|secret|password|token|bypass|unsafe|insecure|vuln)\w*", 15, "unresolved security note"),
    ("disable_ssl_comment", r"(?i)(?:#|//)\s*(?:disable|skip|ignore|bypass)\s+(?:ssl|tls|cert|auth|verif)", 25, "verification bypass marker"),
    ("allow_anonymous", r"(?i)(?:@AllowAnonymous|permitAll\(\)|allowAll\(\)|@PermitAll|\[AllowAnonymous\])", 25, "endpoint allows anonymous access"),
    ("god_mode_flags", r"(?i)(?:--dangerously-skip-permissions|--no-verify|--insecure|--allow-all|privileged\s*[:=]\s*true)", 25, "guard rail disabled"),
]

# ── per-language risk packs ────────────────────────────────────────────────

RISK_LANG = {
    "Python": [
        ("compile_use", r"\bcompile\s*\([^)\n]*[\"']exec[\"']", 30, "dynamic code compilation"),
        ("input_py2", r"(?<!\w)raw_input\s*\(", 25, "py2 input surface"),
        ("marshal_load", r"\bmarshal\.loads?\s*\(", 30, "unsafe deserialization"),
        ("cPickle", r"\bcPickle\.loads?\s*\(", 30, "unsafe deserialization"),
        ("dill_load", r"\bdill\.loads?\s*\(", 30, "unsafe deserialization"),
        ("tempfile_mktemp", r"\btempfile\.mktemp\s*\(", 30, "predictable temp file (race)"),
        ("flask_debug", r"app\.run\s*\([^)]*debug\s*=\s*True", 35, "Flask debug server exposed"),
        ("django_debug", r"DEBUG\s*=\s*True", 30, "Django DEBUG in production"),
        ("django_allowed_hosts_star", r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']", 30, "Django accepts any Host"),
        ("django_raw_sql", r"\.(?:raw|extra)\s*\(|RawSQL\s*\(", 30, "raw SQL surface"),
        ("secret_key_literal", r"SECRET_KEY\s*=\s*[\"'][^\"']{12,}", 45, "hardcoded framework secret"),
        ("assert_guard", r"(?m)^\s*assert\s+(?!.*#)", 5, "assert used as a guard (stripped under -O)"),
        ("requests_no_timeout", r"requests\.(?:get|post|put|delete|patch|request)\s*\((?![^)\n]*timeout)", 15, "HTTP call without timeout"),
        ("tornado_xsrf_off", r"xsrf_cookies\s*=\s*False", 25, "CSRF protection disabled"),
        ("ssl_unverified_ctx", r"ssl\._create_unverified_context|check_hostname\s*=\s*False", 35, "TLS verification disabled"),
        ("subprocess_shell_str", r"subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True", 40, "shell-string subprocess call (command injection)"),
        ("jinja_autoescape_off", r"autoescape\s*=\s*False", 25, "template autoescaping disabled"),
        ("shelve_or_db_pickle", r"\b(?:shelve\.open|cPickle)\b", 25, "pickle-backed store"),
        ("flask_secret_default", r"(?i)app\.config\[(?:\"|')SECRET_KEY(?:\"|')\]\s*=\s*[\"'](?:dev|test|changeme|secret)", 45, "default secret key"),
    ],
    "JavaScript": [
        ("new_function", r"\bnew\s+Function\s*\(", 35, "dynamic code execution"),
        ("vm_run", r"\bvm\.(?:runInNewContext|runInThisContext|runInContext|createScript)\s*\(", 35, "sandbox escape surface"),
        ("child_process", r"child_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(", 35, "command execution surface"),
        ("exec_import", r"require\(\s*[\"']child_process[\"']\)", 30, "command execution surface"),
        ("settimeout_string", r"set(?:Timeout|Interval)\s*\(\s*[\"']", 25, "string-evaluated timer"),
        ("proto_pollution", r"(?:\b__proto__\b|\[\s*[\"']constructor[\"']\s*\]|prototype\s*\[)", 35, "prototype pollution"),
        ("merge_user_input", r"(?i)(?:Object\.assign|_\.merge|_\.extend|deepMerge|merge)\s*\(\s*[^,)]*(?:req\.body|req\.query|body\.|params\.)", 30, "unsafe merge of user input"),
        ("jwt_none", r"(?i)algorithm[s]?\s*[:=]\s*\[?\s*[\"'](?:none|HS256)[\"']", 25, "JWT algorithm not pinned to asymmetric"),
        ("jwt_no_verify", r"(?i)(?:verify\s*:\s*false|ignoreExpiration\s*:\s*true|decode\s*\([^)]*\)\s*$)", 30, "JWT verification disabled"),
        ("cors_any", r"cors\s*\(\s*\)|origin\s*:\s*[\"']\*[\"']", 20, "wildcard CORS"),
        ("helmet_absent_express", r"express\s*\(\s*\)", 5, "verify helmet/security middleware is present"),
        ("express_body_raw", r"(?i)res\.(?:send|json)\s*\(\s*req\.(?:query|params|body)", 15, "reflected user input"),
        ("serialize_insecure", r"node-serialize|unserialize\s*\(", 35, "unsafe deserialization"),
        ("eval_json", r"JSON\.parse\s*\(\s*[^)]*eval|eval\s*\(\s*[\"']\(", 35, "eval on JSON"),
        ("hardcoded_jwt_secret", r"(?i)(?:jwt[_\-]?secret|secretOrPrivateKey|JWT_SECRET)\s*[:=]\s*[\"'][^\"']{8,}", 45, "hardcoded JWT secret"),
        ("react_dangerous_src", r"src=\{\s*[\"']?javascript:", 35, "javascript: URL in React"),
        ("fs_user_path", r"fs\.(?:readFile|readFileSync|writeFile|createReadStream)\s*\(\s*(?:req\.|path\.join\([^)]*req\.)", 30, "filesystem path from user input"),
        ("process_env_leak", r"res\.(?:send|json)\s*\(\s*process\.env", 40, "environment leaked to response"),
        ("insecure_cookie", r"(?i)setCookie\([^)]*secure\s*:\s*false|httpOnly\s*:\s*false", 25, "insecure cookie flags"),
        ("math_random_token", r"(?i)(?:token|otp|code|id)\s*[:=]\s*Math\.random\(\)", 35, "predictable randomness for a secret"),
    ],
    "TypeScript": [],
    "Java": [
        ("runtime_exec", r"Runtime\.getRuntime\(\)\.exec\s*\(", 40, "command execution surface"),
        ("process_builder", r"new\s+ProcessBuilder\s*\(", 35, "command execution surface"),
        ("object_input_stream", r"new\s+ObjectInputStream\s*\(", 40, "Java deserialization RCE"),
        ("readobject_call", r"\.readObject\s*\(\s*\)", 35, "Java deserialization RCE"),
        ("xml_decoder", r"new\s+XMLDecoder\s*\(", 40, "unsafe XML deserialization"),
        ("xxe_unconfigured", r"DocumentBuilderFactory\.newInstance\s*\(\)", 25, "XXE surface unless secured"),
        ("xpath_injection", r"XPath\.(?:compile|evaluate)\s*\([^)]*\+", 30, "XPath injection"),
        ("sql_concat_java", r"(?:createStatement|prepareStatement)\s*\(|\.execute(?:Query|Update)?\s*\(\s*[\"'][^\"']*[\"']\s*\+", 35, "SQL built by concatenation"),
        ("script_engine", r"new\s+ScriptEngineManager|\.eval\s*\(", 35, "script engine execution"),
        ("trust_all_certs", r"TrustAllStrategy|TrustAllCertificates|NullHostnameVerifier|setHostnameVerifier\s*\([^)]*(?:ALLOW_ALL|return\s+true)", 40, "TLS verification disabled"),
        ("permit_all_security", r"(?:permitAll\(\)|\.antMatchers\([^)]*\)\.permitAll|@PermitAll)", 25, "endpoint allows anonymous access"),
        ("crossorigin_star", r"@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?[\"']\*[\"']", 20, "wildcard CORS"),
        ("snakeyaml_load", r"new\s+Yaml\s*\(\s*\)|\.load\s*\(\s*[^)]*\)", 20, "unsafe YAML load"),
        ("log_secret", r"(?i)(?:System\.out\.print|log(?:ger)?\.\w+)\([^)\n]*(?:password|secret|token|apikey)", 30, "credential written to logs"),
        ("hardcoded_jdbc_pw", r"(?i)(?:password|pwd)\s*=\s*[\"'][^\"']{6,}[\"']", 60, "hardcoded database password"),
        ("printStackTrace", r"\.printStackTrace\s*\(", 10, "stack trace disclosure"),
        ("random_for_token", r"new\s+(?:Random|java\.util\.Random)\s*\(", 15, "non-cryptographic randomness"),
    ],
    "Kotlin": [],
    "Go": [
        ("go_exec", r"exec\.Command\s*\(", 30, "command execution surface"),
        ("go_text_template", r"text/template\"", 20, "unescaped template (prefer html/template)"),
        ("go_sprintf_sql", r"(?i)(?:db\.Query|db\.Exec|QueryRow)\s*\(\s*fmt\.Sprintf", 35, "SQL built by Sprintf"),
        ("go_sql_concat", r"(?i)(?:db\.Query|db\.Exec)\s*\(\s*[\"'][^\"']*[\"']\s*\+", 35, "SQL built by concatenation"),
        ("go_bad_tls", r"InsecureSkipVerify\s*:\s*true", 35, "TLS verification disabled"),
        ("go_weak_rand", r"math/rand\"|math\.rand\.", 15, "non-cryptographic randomness"),
        ("go_weak_hash", r"crypto/(?:md5|sha1)\"", 20, "weak digest"),
        ("go_no_timeouts", r"http\.(?:ListenAndServe|Serve)\s*\([^)]*\)", 15, "HTTP server without timeouts"),
        ("go_unbounded_read", r"ioutil\.ReadAll|io\.ReadAll\s*\(", 15, "unbounded read (memory DoS)"),
        ("go_unsafe", r"unsafe\.Pointer|\"unsafe\"", 25, "unsafe pointer arithmetic"),
        ("go_hardcoded_cred", r"(?i)(?:password|token|secret|apikey)\s*(?::=|=)\s*[\"'][^\"']{10,}[\"']", 60, "hardcoded credential"),
        ("go_skipped_err", r",\s*_\s*:?=\s*(?:os\.|db\.|json\.)", 10, "ignored error return"),
        ("go_fmt_log_secret", r"(?i)(?:log|fmt)\.\w+\([^)\n]*(?:password|secret|token|apikey)", 30, "credential written to logs"),
    ],
    "Rust": [
        ("rust_unsafe", r"\bunsafe\s*(?:\{|fn|impl|extern)", 25, "unsafe block"),
        ("rust_transmute", r"\btransmute\b", 30, "transmute (type confusion risk)"),
        ("rust_command", r"std::process::Command|Command::new\s*\(", 25, "command execution surface"),
        ("rust_unwrap", r"\.unwrap\s*\(\)", 10, "panic on error"),
        ("rust_expect", r"\.expect\s*\(", 8, "panic on error"),
        ("rust_unchecked", r"from_utf8_unchecked|get_unchecked|unchecked_", 30, "unchecked operation"),
        ("rust_todo", r"\b(?:todo!|unimplemented!|unreachable!)\s*\(", 10, "unimplemented path"),
        ("rust_panic", r"\bpanic!\s*\(", 15, "explicit panic"),
        ("rust_weak_hash", r"md5::|sha1::", 20, "weak digest"),
        ("rust_thread_rng_secret", r"(?i)(?:key|secret|token|nonce|salt).{0,20}rand::thread_rng", 30, "non-cryptographic RNG for a secret"),
        ("rust_stdout_secret", r"(?i)(?:println!|eprintln!|dbg!)\([^)\n]*(?:password|secret|token|apikey)", 30, "credential written to logs"),
    ],
    "C": [
        ("c_strcpy", r"\bstrcpy\s*\(", 35, "unbounded copy"),
        ("c_strcat", r"\bstrcat\s*\(", 35, "unbounded concat"),
        ("c_sprintf", r"\bsprintf\s*\(", 30, "unbounded format"),
        ("c_gets", r"\bgets\s*\(", 45, "unbounded read"),
        ("c_system", r"\bsystem\s*\(", 35, "command execution surface"),
        ("c_memcpy", r"\bmemcpy\s*\(", 15, "bounds-sensitive copy"),
        ("c_alloca", r"\balloca\s*\(", 25, "stack allocation risk"),
        ("c_scanf_percent_s", r"scanf\s*\(\s*\"[^\"]*%s", 30, "unbounded scanf"),
        ("c_format_string", r"\bprintf\s*\(\s*[a-z_]\w*\s*\)", 30, "format string from variable"),
        ("c_use_after_free", r"\bfree\s*\([^)]*\)\s*;[^;\n]{0,80}\b\w+\s*->", 20, "possible use-after-free"),
        ("c_popen", r"\bpopen\s*\(", 35, "command execution surface"),
        ("c_rand", r"\brand\s*\(\)", 15, "non-cryptographic randomness"),
        ("c_assert_guard", r"\bassert\s*\(", 5, "assert used as a guard"),
    ],
    "C++": [],
    "C#": [
        ("cs_binary_formatter", r"new\s+BinaryFormatter\s*\(", 45, ".NET deserialization RCE"),
        ("cs_object_state", r"ObjectStateFormatter|LosFormatter|NetDataContractSerializer", 40, ".NET deserialization RCE"),
        ("cs_type_name_handling", r"TypeNameHandling\s*[:=]\s*(?:All|Objects|Auto)", 40, "JSON.NET type handling RCE"),
        ("cs_xml_reader_dtd", r"XmlReaderSettings\s*\([^)]*\)|DtdProcessing\s*=\s*DtdProcessing\.Parse", 30, "XXE surface"),
        ("cs_process_start", r"Process\.Start\s*\(", 30, "command execution surface"),
        ("cs_sql_concat", r"(?i)(?:SqlCommand|NpgsqlCommand|MySqlCommand)\s*\([^)]*\+", 35, "SQL built by concatenation"),
        ("cs_viewstate_mac_off", r"EnableViewStateMac\s*=\s*[\"']?false|enableViewStateMac=\"false\"", 35, "ViewState MAC disabled"),
        ("cs_validate_request_off", r"ValidateRequest\s*=\s*[\"']?false", 30, "request validation disabled"),
        ("cs_debug_true", r"compilation[^>]*debug\s*=\s*[\"']true", 25, "debug build flag"),
        ("cs_random_token", r"new\s+Random\s*\(\)", 15, "non-cryptographic randomness"),
        ("cs_weak_hash", r"(?:MD5|SHA1)\.Create\s*\(|new\s+MD5", 20, "weak digest"),
        ("cs_allow_anonymous", r"\[AllowAnonymous\]", 25, "endpoint allows anonymous access"),
        ("cs_hardcoded_pw", r"(?i)(?:Password|Pwd|Secret)\s*=\s*[\"'][^\"']{8,}[\"']", 60, "hardcoded credential"),
    ],
    "PHP": [
        ("php_eval", r"\beval\s*\(", 40, "dynamic code execution"),
        ("php_assert", r"\bassert\s*\(", 30, "assertion with side effects"),
        ("php_system", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", 40, "command execution surface"),
        ("php_include_var", r"\b(?:include|require)(?:_once)?\s*\(?\s*\$", 40, "file inclusion from variable (LFI/RFI)"),
        ("php_unserialize", r"\bunserialize\s*\(", 40, "PHP object injection"),
        ("php_extract", r"\bextract\s*\(", 30, "variable injection"),
        ("php_create_function", r"\bcreate_function\s*\(", 35, "deprecated code execution"),
        ("php_preg_e", r"preg_replace\s*\(\s*[\"'][^\"']*/e", 40, "preg_replace /e code execution"),
        ("php_mysql_query_concat", r"(?:mysql_query|mysqli_query|\$wpdb->query|->query)\s*\([^)]*\.\s*\$", 40, "SQL built by concatenation"),
        ("php_md5_password", r"(?i)(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd)", 45, "weak password hashing"),
        ("php_display_errors", r"display_errors\s*=\s*(?:On|1|true)", 25, "errors displayed to users"),
        ("php_variable_var", r"\$\$\w+", 25, "variable variables"),
        ("php_file_user_input", r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)", 40, "remote file read from user input"),
        ("php_global_backdoor", r"(?i)(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\"'](?:cmd|exec|shell|eval|system)[\"'])", 45, "backdoor-shaped input"),
        ("php_base64_eval", r"base64_decode\s*\([^)]*\)\s*\)?\s*;?", 20, "obfuscation surface"),
        ("php_rand_token", r"(?i)\b(?:rand|mt_rand|uniqid|array_rand)\s*\(", 20, "non-cryptographic randomness"),
        ("php_cookie_httponly_off", r"setcookie\s*\([^)]*\)", 5, "verify cookie flags"),
        ("php_hardcoded_pw", r"(?i)\$(?:password|passwd|pass|db_pass)\s*=\s*[\"'][^\"']{6,}[\"']", 60, "hardcoded credential"),
    ],
    "Ruby": [
        ("rb_eval", r"\beval\s*\(", 35, "dynamic code execution"),
        ("rb_system", r"\b(?:system|exec|spawn)\s*\(|\b`[^`]+`", 30, "command execution surface"),
        ("rb_marshal", r"Marshal\.load\s*\(", 40, "unsafe deserialization"),
        ("rb_yaml_load", r"YAML\.load\s*\(", 30, "unsafe YAML load"),
        ("rb_constantize", r"\.constantize\b", 30, "arbitrary constant resolution"),
        ("rb_send_user", r"\.(?:send|public_send|__send__)\s*\(\s*(?:params|request)", 35, "dynamic dispatch from user input"),
        ("rb_mass_assignment", r"\.permit!\s*\(|\battr_accessible\b", 25, "mass assignment"),
        ("rb_html_safe", r"\.html_safe\b|\braw\s+", 25, "unescaped HTML output"),
        ("rb_sql_interp", r"(?i)(?:where|find_by_sql|execute)\s*\(\s*[\"'][^\"']*#\{", 40, "SQL built by interpolation"),
        ("rb_md5_password", r"(?i)Digest::MD5\.hexdigest\s*\([^)]*password", 45, "weak password hashing"),
        ("rb_rand_token", r"(?i)\b(?:rand|Random\.rand)\s*\(", 15, "non-cryptographic randomness"),
        ("rb_erb_eval", r"ERB\.new\s*\([^)]*\)\.result", 25, "template evaluation surface"),
        ("rb_hardcoded_pw", r"(?i)(?:password|secret|api_key)\s*[:=]\s*[\"'][^\"']{8,}[\"']", 60, "hardcoded credential"),
        ("rb_skip_csrf", r"skip_before_action\s*:verify_authenticity_token", 30, "CSRF protection disabled"),
    ],
    "Solidity": [
        ("sol_tx_origin", r"\btx\.origin\b", 35, "tx.origin authorization bypass"),
        ("sol_delegatecall", r"\bdelegatecall\b", 35, "delegatecall storage/context risk"),
        ("sol_selfdestruct", r"\bselfdestruct\s*\(|\bsuicide\s*\(", 35, "contract kill switch"),
        ("sol_call_value_unchecked", r"\.call\{[^}]*value[^}]*\}\(\s*[\"']{2}\s*\)\s*;", 35, "unchecked low-level value call"),
        ("sol_low_level_call", r"\.(?:call|delegatecall|staticcall)\s*\{?[^;]{0,80}\}\?\.?\s*\(|\.call\s*\(", 20, "low-level call (verify return)"),
        ("sol_timestamp_random", r"(?i)(?:keccak256|sha3)\s*\([^)]*block\.(?:timestamp|number|difficulty|prevrandao)", 40, "weak on-chain randomness"),
        ("sol_blockhash_random", r"\bblockhash\s*\(|\bblock\.prevrandao\b", 25, "weak on-chain randomness"),
        ("sol_assembly", r"\bassembly\s*\{", 25, "inline assembly"),
        ("sol_ecrecover_nocheck", r"ecrecover\s*\((?![^;]{0,200}require)", 30, "ecrecover result not validated"),
        ("sol_approve_race", r"function\s+approve\s*\(", 20, "ERC-20 approve race condition"),
        ("sol_transfer_eth", r"\.transfer\s*\(|\.send\s*\(", 25, "2300-gas transfer (revert risk)"),
        ("sol_unchecked_block", r"\bunchecked\s*\{", 15, "unchecked arithmetic block"),
        ("sol_owner_mint", r"(?i)function\s+mint\w*\s*\([^)]*\)[^{]*onlyOwner", 30, "owner-only mint (centralization)"),
        ("sol_settax", r"(?i)function\s+set(?:Tax|Fee)s?\s*\(", 30, "mutable transfer tax"),
        ("sol_blacklist", r"(?i)(?:blacklist|blocklist|banned|isBot)\b", 30, "blacklist / trade gating"),
        ("sol_trading_toggle", r"(?i)(?:tradingEnabled|tradingActive|enableTrading|startTrading)\b", 30, "trade gating toggle (honeypot shape)"),
        ("sol_pause", r"(?i)function\s+pause\s*\(|whenNotPaused", 15, "pausable (centralization)"),
        ("sol_no_maxsupply", r"(?i)function\s+mint\s*\((?![^)]*onlyOwner)", 25, "unrestricted mint"),
        ("sol_initializer_missing", r"function\s+initialize\s*\(", 15, "verify initializer is protected"),
        ("sol_oracle_spot", r"(?i)(?:getReserves|balanceOf\s*\(\s*pair|slot0)\s*\(", 30, "spot-price oracle (manipulable)"),
        ("sol_flashloan_callback", r"(?i)function\s+(?:flashLoan|executeOperation|uniswapV\d+C?all|pancakeCall)\s*\(", 25, "flash-loan callback surface"),
        ("sol_arbitrary_call", r"(?i)function\s+\w*exec\w*\s*\([^)]*address\s+\w+", 35, "arbitrary external call"),
        ("sol_tx_origin_owner", r"(?i)require\s*\([^)]*tx\.origin", 40, "tx.origin authorization bypass"),
        ("sol_private_data", r"(?i)\bprivate\b\s+(?:bytes|string)\b", 15, "private data is still public on-chain"),
    ],
    "Vyper": [],
    "Move": [
        ("move_public_entry", r"public\s+entry\s+fun", 5, "public entry function"),
        ("move_arbitrary_coin", r"coin::transfer\s*\(", 15, "token transfer surface"),
        ("move_unchecked_cap", r"assert!\s*\(", 5, "assertion-based guard"),
    ],
    "Shell": [
        ("sh_curl_pipe", r"curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", 45, "remote code piped to shell"),
        ("sh_wget_pipe", r"wget\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", 45, "remote code piped to shell"),
        ("sh_eval", r"\beval\s+[\"$']", 35, "dynamic shell evaluation"),
        ("sh_rm_rf_var", r"rm\s+-rf?\s+[\"']?\$(?:\{)?\w+", 35, "recursive delete of a variable path"),
        ("sh_chmod_777", r"chmod\s+(?:-R\s+)?777\b", 30, "world-writable permissions"),
        ("sh_sudo_script", r"(?m)^\s*sudo\s+", 15, "privileged operation in script"),
        ("sh_no_set_e", r"(?m)^\s*#!", 5, "verify set -euo pipefail"),
        ("sh_unquoted_var", r"(?m)^[^#\n]*rm\s+[^\n]*\s\$\w+\s", 15, "unquoted variable expansion"),
        ("sh_export_secret", r"(?i)export\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*=", 40, "secret exported into the environment"),
        ("sh_cred_in_curl", r"(?i)curl[^\n]*(?:-u|--user)\s+\S+:\S+", 35, "credentials on the command line"),
        ("sh_ssh_no_hostkey", r"StrictHostKeyChecking\s*=\s*(?:no|false)", 30, "SSH host key verification disabled"),
        ("sh_history_secret", r"(?i)echo\s+\S*(?:password|secret|token)\S*\s*>", 30, "secret echoed to a file"),
    ],
    "PowerShell": [
        ("ps_iex", r"\bIEX\b|Invoke-Expression", 45, "dynamic code execution"),
        ("ps_downloadstring", r"(?:DownloadString|DownloadFile|Invoke-WebRequest|wget|curl)\s*\(?\s*[\"']https?://", 30, "remote payload fetch"),
        ("ps_bypass", r"-ExecutionPolicy\s+Bypass|-ep\s+bypass", 35, "execution policy bypass"),
        ("ps_encoded", r"-EncodedCommand\b|-enc\s+[A-Za-z0-9+/=]{40,}", 40, "encoded command (obfuscation)"),
        ("ps_securestring_plain", r"ConvertTo-SecureString\s+[^-]", 25, "plaintext SecureString"),
        ("ps_cred_literal", r"ConvertTo-SecureString\s+[\"'][^\"']{6,}", 55, "hardcoded credential"),
        ("ps_noprompt", r"New-Object\s+.*Credential|PSCredential", 15, "credential object handling"),
    ],
    "SQL": [
        ("sql_drop", r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", 20, "destructive DDL"),
        ("sql_truncate", r"(?i)\bTRUNCATE\s+TABLE\b", 15, "destructive DDL"),
        ("sql_grant_all", r"(?i)\bGRANT\s+ALL\b", 30, "excessive privilege grant"),
        ("sql_grant_public", r"(?i)\bTO\s+(?:PUBLIC|ALL)\b", 30, "privilege granted to PUBLIC"),
        ("sql_hardcoded_pw", r"(?i)IDENTIFIED\s+BY\s+[\"'][^\"']{6,}", 60, "hardcoded database password"),
        ("sql_sa_enabled", r"(?i)\bsa\b\s*(?:ENABLE|PASSWORD)", 30, "built-in admin account"),
        ("sql_select_star_auth", r"(?i)\b(?:password|password_hash|token)\b\s*(?:,|FROM)", 20, "credential column selected"),
    ],
    "Dockerfile": [
        ("dk_privileged", r"(?i)privileged\s*[:=]\s*true|--privileged", 35, "privileged container"),
        ("dk_root_user", r"(?i)\bUSER\s+root\b", 20, "container runs as root"),
        ("dk_latest_tag", r"(?im)^\s*FROM\s+\S+:latest\b", 15, "unpinned image tag"),
        ("dk_unpinned_from", r"(?im)^\s*FROM\s+[a-zA-Z0-9._/-]+\s*$", 12, "image without an explicit digest/tag"),
        ("dk_add_remote", r"(?i)^\s*ADD\s+https?://", 30, "remote ADD"),
        ("dk_copy_git", r"(?i)^\s*(?:COPY|ADD)\s+\.\s", 10, "whole-context copy (check .dockerignore)"),
        ("dk_secret_env", r"(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*[=\s]", 40, "secret baked into the image"),
        ("dk_curl_bash", r"(?i)RUN[^\n]*curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 40, "remote script executed at build"),
        ("dk_sudo", r"(?i)^\s*RUN\s+sudo\b", 20, "sudo in build"),
        ("dk_apt_no_recommends_missing", r"(?i)^\s*RUN\s+apt-get\s+install(?![^\n]*--no-install-recommends)", 5, "apt install without --no-install-recommends"),
        ("dk_chmod_777", r"(?i)RUN[^\n]*chmod\s+(?:-R\s+)?777", 30, "world-writable path"),
    ],
    "Terraform": [
        ("tf_open_cidr", r"(?i)cidr_blocks?\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']", 35, "open ingress to the internet"),
        ("tf_open_ipv6", r"(?i)::/0", 25, "open IPv6 ingress"),
        ("tf_publicly_accessible", r"(?i)publicly_accessible\s*=\s*true", 35, "resource exposed publicly"),
        ("tf_public_acl", r"(?i)acl\s*=\s*[\"'](?:public-read|public-read-write)[\"']", 35, "public object ACL"),
        ("tf_encryption_off", r"(?i)(?:encrypted|storage_encrypted|encryption)\s*=\s*false", 30, "encryption disabled at rest"),
        ("tf_hardcoded_cred", r"(?i)(?:access_key|secret_key|password|token)\s*=\s*[\"'][^\"']{8,}[\"']", 70, "hardcoded credential in IaC"),
        ("tf_wildcard_action", r"(?i)actions?\s*=\s*\[\s*[\"']\*[\"']", 30, "wildcard IAM action"),
        ("tf_wildcard_resource", r"(?i)resources?\s*=\s*\[\s*[\"']\*[\"']", 25, "wildcard IAM resource"),
        ("tf_no_mfa_delete", r"(?i)mfa_delete\s*=\s*false", 15, "MFA delete off"),
        ("tf_versioning_off", r"(?i)versioning\s*\{[^}]*enabled\s*=\s*false", 15, "versioning disabled"),
        ("tf_force_destroy", r"(?i)force_destroy\s*=\s*true", 20, "bucket force-destroy"),
        ("tf_lifecycle_prevent_destroy_missing", r"(?i)resource\s+\"aws_db_instance\"", 5, "stateful resource (verify lifecycle)"),
    ],
    "HCL": [],
    "YAML": [
        ("yaml_k8s_privileged", r"(?i)privileged\s*:\s*true", 35, "privileged pod"),
        ("yaml_hostpath", r"(?i)hostPath\s*:", 30, "host filesystem mount"),
        ("yaml_hostnetwork", r"(?i)hostNetwork\s*:\s*true", 30, "host network namespace"),
        ("yaml_hostpid", r"(?i)hostPID\s*:\s*true|hostIPC\s*:\s*true", 30, "host process/ipc namespace"),
        ("yaml_priv_escalation", r"(?i)allowPrivilegeEscalation\s*:\s*true", 30, "privilege escalation allowed"),
        ("yaml_runasroot", r"(?i)runAsUser\s*:\s*0\b", 25, "container runs as root"),
        ("yaml_cap_sysadmin", r"(?i)SYS_ADMIN", 35, "capability SYS_ADMIN"),
        ("yaml_no_seccomp", r"(?i)seccompProfile\s*:\s*[\"']?Unconfined", 30, "seccomp disabled"),
        ("yaml_latest_image", r"(?im)^\s*image\s*:\s*\S+:latest\b", 15, "unpinned image tag"),
        ("yaml_secret_literal", r"(?im)^\s*(?:password|secret|apiKey|token)\s*:\s*[\"']?[^\s\"'#]{12,}", 55, "secret literal in manifest"),
        ("yaml_ci_pull_request_target", r"(?i)pull_request_target\s*:", 30, "pull_request_target (untrusted checkout risk)"),
        ("yaml_ci_script_injection", r"(?i)\$\{\{\s*github\.event\.(?:issue|pull_request|comment)[^}]*\}\}", 35, "untrusted input interpolated into a workflow"),
        ("yaml_ci_write_all", r"(?i)permissions\s*:\s*write-all", 30, "workflow has write-all permissions"),
        ("yaml_ci_secrets_echo", r"(?i)(?:echo|run)\s*:[^\n]*\$\{\{\s*secrets\.", 40, "secret interpolated into a command"),
    ],
    "JSON": [],
    "TOML": [],
    "XML": [
        ("xml_xxe_doctype", r"(?i)<!DOCTYPE[^>]*SYSTEM", 40, "external entity (XXE)"),
        ("xml_entity_expansion", r"(?i)<!ENTITY\s+\w+\s+\"", 30, "custom entity (billion laughs / XXE)"),
    ],
    "INI": [],
    "Dotenv": [
        ("env_secret_literal", r"(?im)^\s*(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*)\s*=\s*" + _ENVREF + r"\S{8,}", 55, "secret committed in a dotenv file"),
        ("env_aws_pair", r"(?im)^\s*AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)\s*=\s*\S{16,}", 70, "AWS credentials committed"),
    ],
    "Erlang": [
        ("erl_os_cmd", r"os:cmd\s*\(", 35, "command execution surface"),
        ("erl_binary_to_term", r"binary_to_term\s*\((?![^)]*safe)", 35, "unsafe deserialization"),
    ],
    "Elixir": [
        ("ex_system_cmd", r"System\.cmd\s*\(|System\.shell\s*\(", 30, "command execution surface"),
        ("ex_binary_to_term", r":erlang\.binary_to_term\s*\(", 35, "unsafe deserialization"),
        ("ex_string_to_atom", r"String\.to_atom\b", 30, "atom-table exhaustion"),
        ("ex_code_eval", r"Code\.eval_", 35, "dynamic code execution"),
        ("ex_eex_html", r"raw\s*\(|\{:safe,", 25, "unescaped HTML output"),
    ],
    "Lua": [
        ("lua_loadstring", r"\bloadstring\s*\(|\bload\s*\(\s*[\"']?", 30, "dynamic code execution"),
        ("lua_os_execute", r"os\.execute\s*\(", 35, "command execution surface"),
        ("lua_io_open_var", r"io\.open\s*\([^)]*\.\.", 25, "path built by concatenation"),
        ("lua_math_random", r"math\.random\s*\(", 10, "non-cryptographic randomness"),
    ],
    "Perl": [
        ("pl_open2arg", r"open\s*\([^)]*,\s*\$", 40, "two-argument open (injection)"),
        ("pl_system_var", r"(?:system|exec)\s*\(?[^;\n]*\$", 30, "command built from a variable"),
        ("pl_eval_string", r"(?m)\beval\s+[\"'$@]", 35, "string eval"),
        ("pl_sql_interp", r"(?i)(?:prepare|do)\s*\(\s*[\"'][^\"']*\$", 35, "SQL built by interpolation"),
        ("pl_rand_token", r"\brand\s*\(", 15, "non-cryptographic randomness"),
    ],
    "Cairo": [
        ("cairo_unsafe", r"unsafe_|assert_le|unwrap\s*\(\)", 15, "unchecked path"),
        ("cairo_invoke", r"\.invoke\s*\(|call_contract_syscall", 20, "arbitrary contract call"),
    ],
    "Nix": [
        ("nix_fetchurl", r"fetchurl|fetchTarball|builtins\.fetchGit", 15, "remote fetch at build"),
        ("nix_impure", r"--impure|builtins\.getEnv", 15, "impure evaluation"),
    ],
    "Julia": [
        ("jl_eval", r"\beval\s*\(|\binclude\s*\(", 25, "dynamic code evaluation"),
        ("jl_run", r"\brun\s*\(`", 25, "command execution surface"),
    ],
    "Objective-C": [],
    "Dart": [
        ("dart_process_run", r"Process\.(?:run|start|runSync)\s*\(", 25, "command execution surface"),
        ("dart_http_plain", r"http://", 10, "plaintext transport"),
    ],
    "Swift": [
        ("swift_process", r"Process\s*\(\s*\)|NSTask\s*\(", 25, "command execution surface"),
        ("swift_force_unwrap", r"!\.|as!\s", 8, "force unwrap"),
    ],
    "Groovy": [
        ("groovy_eval", r"\bevaluate\s*\(|GroovyShell", 35, "dynamic code execution"),
        ("groovy_execute", r"\.execute\s*\(|Runtime\.getRuntime", 35, "command execution surface"),
    ],
    "Notebook": [
        ("nb_curl_bash", r"curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", 45, "remote code piped to shell"),
        ("nb_pip_remote", r"(?i)pip\s+install\s+(?:-U\s+)?https?://", 35, "package installed from a URL"),
    ],
    "Protobuf": [],
    "GraphQL": [],
}

# Languages whose risk pack is inherited from a sibling.
_LANG_ALIAS = {
    "TypeScript": "JavaScript", "Kotlin": "Java", "C++": "C",
    "Cython": "Python", "Objective-C++": "C", "Fortran": "C",
    "VB.NET": "C#", "F#": "C#", "Svelte": "JavaScript", "Vue": "JavaScript",
    "Astro": "JavaScript", "JavaScript": "JavaScript", "Clojure": "Java",
    "ClojureScript": "Java", "Gradle": "Groovy", "Bazel": "Groovy",
    "HCL": "Terraform", "JSON5": "JSON", "Plist": "XML", "Config": "INI",
    "Properties": "INI", "Template": "YAML", "Text": "INI", "Markdown": "INI",
    "Java": "Java", "C": "C", "Go": "Go", "Rust": "Rust", "PHP": "PHP",
    "Ruby": "Ruby", "Solidity": "Solidity", "Python": "Python",
    "Shell": "Shell", "Fish": "Shell", "Makefile": "Shell", "CMake": "Shell",
    "Batch": "Shell", "Dockerfile": "Dockerfile", "Terraform": "Terraform",
    "YAML": "YAML", "XML": "XML", "SQL": "SQL", "Erlang": "Erlang",
    "Elixir": "Elixir", "Lua": "Lua", "Perl": "Perl", "PowerShell": "PowerShell",
    "Nix": "Nix", "Julia": "Julia", "Dart": "Dart", "Swift": "Swift",
    "Groovy": "Groovy", "Notebook": "Notebook", "Move": "Move",
    "Cairo": "Cairo", "Vyper": "Solidity", "FunC": "C", "Tact": "C",
    "TEAL": "Python", "Clarity": "Solidity", "Sway": "Rust",
    "D": "C", "Nim": "Python", "Zig": "C", "V": "C", "Ada": "C",
    "Tcl": "Lua", "Haskell": "Java", "OCaml": "Java", "R": "Python",
    "Scala": "Java", "C#": "C#", "INI": "INI", "Dotenv": "Dotenv",
    "JSON": "JSON", "TOML": "TOML", "Protobuf": "Protobuf",
    "GraphQL": "GraphQL", "Cypher": "SQL", "Thrift": "Protobuf",
    "Dhall": "Nix",
}


def lang_pack(language: str) -> list:
    """Return the risk-rule list for a language, following one alias hop."""
    pack = RISK_LANG.get(language)
    if pack:
        return pack
    alias = _LANG_ALIAS.get(language)
    if alias and alias != language:
        return RISK_LANG.get(alias, [])
    return []


def language_of(path: str) -> str | None:
    """Best-effort language for a repo-relative path."""
    import os
    base = path.rsplit("/", 1)[-1]
    if base in LANG_BY_NAME:
        return LANG_BY_NAME[base]
    lower = base.lower()
    for name, lang in LANG_BY_NAME.items():
        if lower == name.lower():
            return lang
    ext = os.path.splitext(base)[1]
    if not ext:
        return None
    ext = ext.lower() if ext.lower() in LANG_BY_EXT else ext
    return LANG_BY_EXT.get(ext) or LANG_BY_EXT.get(ext.lower())


# ── entrypoints / tests / CI ───────────────────────────────────────────────

ENTRYPOINT_RULES = [
    (r"(?m)^if\s+__name__\s*==\s*[\"']__main__[\"']", "Python"),
    (r"(?:createServer|app\.listen|export\s+default\s+async\s+function\s+(?:GET|POST)|Deno\.serve|Bun\.serve)", "JavaScript"),
    (r"(?:public\s+static\s+void\s+main\s*\(|fun\s+main\s*\()", "Java"),
    (r"(?m)^\s*func\s+main\s*\(", "Go"),
    (r"(?m)^\s*fn\s+main\s*\(", "Rust"),
    (r"(?m)^\s*int\s+main\s*\(", "C"),
    (r"(?:static\s+(?:async\s+)?(?:Task|void)\s+Main\s*\()", "C#"),
    (r"(?m)^\s*<\?php|\brequire_once\b", "PHP"),
    (r"(?m)^\s*#!\s*/(?:usr/)?bin/env\s+(?:python|node|ruby|bash|sh)", "Shell"),
    (r"(?m)^\s*#!\s*/(?:usr/)?bin/(?:python|node|ruby|bash|sh|perl)", "Shell"),
    (r"(?m)^\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE)\b", "SQL"),
    (r"(?:^|\s)(?:contract|interface|library)\s+\w+", "Solidity"),
    (r"(?m)^\s*FROM\s+\S+", "Dockerfile"),
    (r"(?m)^\s*resource\s+\"", "Terraform"),
    (r"(?m)^\s*apiVersion\s*:", "YAML"),
    (r"(?m)^\s*@(?:app|api)\.(?:route|get|post|put|delete)", "Python"),
    (r"(?:express\(\)|fastify\(\)|new\s+Hono\(\))", "JavaScript"),
    (r"(?m)^\s*#include\s*[<\"]", "C"),
]

TEST_PATTERNS = [
    re.compile(r"(^|/)(tests?|__tests__|spec|specs|test)(/|$)", re.I),
    re.compile(r"^(?:test_|spec_|it_|check_)|(?:_test|-test|\.test|\.spec|Test|Tests|Spec)\.(?:[a-zA-Z0-9]+)$"),
    re.compile(r"(?:^|/)(?:conftest|pytest|tox|jest|vitest|karma|cypress|playwright|robot)\.[a-zA-Z0-9]+$", re.I),
]

CI_PATTERNS = [
    re.compile(r"^\.github/workflows/.*\.ya?ml$", re.I),
    re.compile(r"^\.gitlab-ci\.ya?ml$", re.I),
    re.compile(r"^\.circleci/config\.ya?ml$", re.I),
    re.compile(r"^(?:\.travis\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|Jenkinsfile|\.drone\.ya?ml|buildkite.*\.ya?ml)$", re.I),
    re.compile(r"^(?:\.teamcity|\.woodpecker|\.buildkite)/", re.I),
]

IAC_PATTERNS = [
    re.compile(r"\.tf$|\.tfvars$", re.I),
    re.compile(r"(?:^|/)(?:Dockerfile|Containerfile|docker-compose\.ya?ml|compose\.ya?ml)$", re.I),
    re.compile(r"(?:^|/)(?:Chart\.yaml|values\.ya?ml|kustomization\.ya?ml|.*\.k8s\.ya?ml)$", re.I),
    re.compile(r"(?:^|/)(?:serverless\.ya?ml|sam\.ya?ml|template\.ya?ml|pulumi\.ya?ml|cdk\.json)$", re.I),
    re.compile(r"(?:^|/)(?:ansible\.cfg|playbook\.ya?ml|Vagrantfile|Procfile|\.terraform\.lock\.hcl)$", re.I),
    re.compile(r"(?:^|/)\.(?:env|envrc)|(?:^|/)\.github/dependabot\.ya?ml$", re.I),
]

# ── manifests / SBOM ecosystems ────────────────────────────────────────────
# filename -> (ecosystem, format parser key in devin.analysis)

MANIFESTS = {
    # python
    "requirements.txt": "pypi", "requirements-dev.txt": "pypi",
    "requirements.in": "pypi", "constraints.txt": "pypi",
    "Pipfile": "pypi", "Pipfile.lock": "pypi", "pyproject.toml": "pypi",
    "poetry.lock": "pypi", "setup.py": "pypi", "setup.cfg": "pypi",
    "environment.yml": "conda", "environment.yaml": "conda",
    "uv.lock": "pypi", "pdm.lock": "pypi",
    # node
    "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "bun.lockb": "npm",
    "deno.json": "deno", "deno.jsonc": "deno",
    # go / rust
    "go.mod": "go", "go.sum": "go", "go.work": "go",
    "Cargo.toml": "cargo", "Cargo.lock": "cargo",
    # jvm
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "settings.gradle": "gradle", "gradle.lockfile": "gradle",
    "build.sbt": "sbt", "project.clj": "clojure",
    # ruby / php
    "Gemfile": "rubygems", "Gemfile.lock": "rubygems", "*.gemspec": "rubygems",
    "composer.json": "composer", "composer.lock": "composer",
    # .net / swift / dart / elixir
    "packages.config": "nuget", "packages.lock.json": "nuget",
    "Package.swift": "swift", "podspec.json": "cocoapods", "Podfile": "cocoapods",
    "pubspec.yaml": "pub", "mix.exs": "hex", "rebar.config": "hex",
    # c/c++ / other
    "CMakeLists.txt": "cmake", "conanfile.txt": "conan",
    "conanfile.py": "conan", "vcpkg.json": "vcpkg",
    "Project.toml": "julia", "Manifest.toml": "julia",
    "*.cabal": "hackage", "stack.yaml": "hackage",
    "package.yaml": "hackage", "cpanfile": "cpan",
    # ui / mobile
    "package.swift": "swift", ".nvmrc": "runtime", ".python-version": "runtime",
    ".ruby-version": "runtime", ".tool-versions": "runtime",
    "rust-toolchain": "runtime", "rust-toolchain.toml": "runtime",
}

# Lower-case: membership is always tested against a lower-cased basename.
LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pnpm-lock.yml", "bun.lockb", "poetry.lock", "pipfile.lock", "uv.lock",
    "pdm.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock",
    "packages.lock.json", "gradle.lockfile", "mix.lock", "flake.lock",
    "pubspec.lock", "packages.lock", "podfile.lock", "berksfile.lock",
})

# ── licenses ───────────────────────────────────────────────────────────────

LICENSE_FILES = re.compile(r"^(?:LICEN[CS]E|COPYING|NOTICE|UNLICENSE)(?:\.\w+)?$", re.I)
LICENSE_SPDX_HINTS = [
    (re.compile(r"MIT License", re.I), "MIT"),
    (re.compile(r"Apache License,?\s+Version 2\.0", re.I), "Apache-2.0"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.I), "GPL-3.0"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 2", re.I), "GPL-2.0"),
    (re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I), "AGPL-3.0"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE", re.I), "LGPL"),
    (re.compile(r"BSD (?:2|3)-Clause", re.I), "BSD"),
    (re.compile(r"Mozilla Public License,?\s+Version 2\.0", re.I), "MPL-2.0"),
    (re.compile(r"Business Source License", re.I), "BSL"),
    (re.compile(r"The Unlicense", re.I), "Unlicense"),
    (re.compile(r"ISC License", re.I), "ISC"),
    (re.compile(r"Do What The F\*ck You Want", re.I), "WTFPL"),
]

# ── supply chain ───────────────────────────────────────────────────────────

SUPPLY_CHAIN_HINTS = [
    (re.compile(r"(?i)\bcur[l|]\s+\S*\|\s*(?:sudo\s+)?(?:ba)?sh"), 45, "remote script executed at install/build"),
    (re.compile(r"(?i)(?:preinstall|postinstall|prepare)\s*\"?\s*:"), 25, "npm lifecycle script (runs on install)"),
    (re.compile(r"(?i)--(?:no-)?verify|--ignore-scripts\s+false"), 20, "verification disabled"),
    (re.compile(r"(?i)\bpip\s+install\s+--trusted-host\b"), 30, "TLS trust bypass on install"),
    (re.compile(r"(?i)\bnpm\s+(?:i|install)\s+[^\n]*--unsafe-perm\b"), 25, "unsafe npm permissions"),
    (re.compile(r"(?i)\bgit\s+clone\s+[^\n]*\s-d\s|--depth\s+1"), 5, "shallow clone (unpinned)"),
    (re.compile(r"(?i)\bgo\s+get\s+[^\s@]+\s*$", re.M), 15, "unpinned go dependency"),
    (re.compile(r"(?i)\bfrom\s+[\w./-]+\s+import\b.*#\s*type:\s*ignore"), 5, "suppressed type error"),
    (re.compile(r"(?i)\bnoqa\b|\beslint-disable\b|@ts-ignore|@ts-nocheck|# type: ignore"), 8, "lint/type suppression"),
    (re.compile(r"(?i)\.npmrc[^\n]*\b_authToken\b"), 55, "npm auth token in .npmrc"),
]
