import base64
import html
import re
from urllib.parse import unquote

ATTACK_PATTERNS = {
    # ---------------------------------------------------------------
    # Injection
    # ---------------------------------------------------------------
    "SQLi": [
        r"union\s+select",
        r"select\s+.*\s+from",
        r"or\s+1=1",
        r"drop\s+table",
        r"insert\s+into",

        # expanded
        r"update\s+.*\s+set",
        r"delete\s+from",
        r"alter\s+table",
        r"create\s+table",
        r"--",
        r"#",
        r"/\*.*\*/",
        r"'\s*or\s*'",
        r"or\s+'.*'='.*'",
        r"having\s+1=1",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"information_schema",
        r"load_file\s*\(",
        r"into\s+outfile",

        # time-based / blind
        r"waitfor\s+delay",
        r"pg_sleep\s*\(",
        r"dbms_pipe\.receive_message",
        r"or\s+sleep\s*\(",
        r";\s*select\s+sleep",

        # stacked queries / error-based
        r";\s*select\s+",
        r"extractvalue\s*\(",
        r"updatexml\s*\(",
        r"cast\s*\(.*\s+as\s+",
        r"convert\s*\(",

        # MSSQL specific
        r"xp_cmdshell",
        r"sp_executesql",
        r"openrowset",
    ],

    "NoSQLi": [
        # MongoDB-style operators
        r"\$ne\b",
        r"\$gt\b",
        r"\$gte\b",
        r"\$lt\b",
        r"\$lte\b",
        r"\$in\b",
        r"\$nin\b",
        r"\$regex\b",
        r"\$where\b",
        r"\$exists\b",
        r"\$elemMatch\b",

        # Injection attempts via JSON in query params
        r"\{\s*\"\$ne\"",
        r"\{\s*'\$ne'",
        r"\{\s*\"\$gt\"",
        r"\{\s*\"\$regex\"",

        # CouchDB / Elasticsearch style
        r"_all_docs",
        r"_find\b",
        r"_search\b",
    ],

    "LDAP_Injection": [
        r"\*\)\(uid=",
        r"\*\)\(objectClass=",
        r"\)\(cn=",
        r"\)\(&",
        r"\)\|",
        r"objectClass=\*",
        r"cn=\*",
        r"uid=\*",
        r"\(&\(.*\)\(.*\)\)",
        r"admin\)\(",
    ],

    "XPath_Injection": [
        r"'\]\s*\|\s*//",
        r"\]\s*//\*",
        r"'\s*or\s*'1'='1",
        r"xpath\s*\(",
        r"//\*\[",
        r"\[\s*count\s*\(",
    ],

    "SSTI": [
        # Generic template delimiters
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",     # {{7*7}}
        r"\{\{\s*'.*'\s*\}\}",
        r"\$\{\s*\d+\s*\*\s*\d+\s*\}",       # ${7*7}
        r"#\{\s*\d+\s*\*\s*\d+\s*\}",         # #{7*7}
        r"<%=\s*\d+\s*\*\s*\d+\s*%>",         # <%= 7*7 %>

        # Language-specific SSTI gadgets
        r"\{\{\s*config\b",
        r"\{\{\s*self\b",
        r"\{\{\s*request\b",
        r"\{\{\s*__class__",
        r"\{\{\s*__mro__",
        r"\{\{\s*__subclasses__",
        r"\{\{\s*lipsum",
        r"\{%\s*for\s",
        r"__globals__",
        r"__builtins__",
        r"\.__init__\.__globals__",
    ],

    "JNDI_Injection": [
        # Log4Shell and related
        r"\$\{jndi:",
        r"\$\{jndi:ldap:",
        r"\$\{jndi:ldaps:",
        r"\$\{jndi:rmi:",
        r"\$\{jndi:dns:",
        r"\$\{jndi:http:",
        r"\$\{\$\{lower:",
        r"\$\{\$\{upper:",
        r"\$\{\$\{env:",
        r"ldap://[^\s]+\.[a-z]{2,}",
        r"rmi://[^\s]+",
    ],

    "XSS": [
        r"<script.*?>",
        r"javascript:",
        r"onerror=",
        r"alert\(",

        # expanded
        r"onload=",
        r"onmouseover=",
        r"onfocus=",
        r"onmouseenter=",
        r"document\.cookie",
        r"document\.location",
        r"window\.location",
        r"<img.*?src=",
        r"<svg.*?>",
        r"<iframe.*?>",
        r"eval\(",
        r"settimeout\(",
        r"setinterval\(",
        r"fromcharcode",

        # more event handlers
        r"onclick=",
        r"onchange=",
        r"onsubmit=",
        r"oninput=",
        r"onanimationstart=",
        r"ontoggle=",

        # more sinks
        r"expression\s*\(",
        r"javascript\s*:",
        r"data:text/html",
        r"vbscript:",
        r"document\.write",
        r"innerhtml\s*=",
        r"\.insertadjacenthtml",
        r"srcdoc=",
        r"formaction=",
    ],

    "Command_Injection": [
        r";\s*ls",
        r";\s*cat",
        r";\s*whoami",
        r"&&\s*",
        r"\|\s*",

        # expanded
        r"`.*`",
        r"\$\(",
        r";\s*id",
        r";\s*pwd",
        r";\s*uname",
        r";\s*ps",
        r";\s*netstat",
        r";\s*curl",
        r";\s*wget",
        r";\s*bash",
        r";\s*sh",

        # Windows command injection
        r"&\s*dir\b",
        r"&\s*type\b",
        r"&\s*whoami",
        r"\|\s*dir\b",
        r"%comspec%",
        r"%systemroot%",

        # newline injection into shell context
        r"\n\s*(?:ls|cat|id|whoami|sh|bash|cmd)\b",
        r"\r\n\s*(?:ls|cat|id|whoami|sh|bash|cmd)\b",
    ],

    "Code_Injection": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bassert\s*\(",
        r"\bsystem\s*\(",
        r"\bpopen\s*\(",
        r"\bpassthru\s*\(",
        r"\bshell_exec\s*\(",
        r"\bproc_open\s*\(",
        r"\bcreate_function\s*\(",
        r"\bcall_user_func",
        r"\bpreg_replace\s*\(.*/e",
    ],

    "Path_Traversal": [
        r"\.\./\.\./",
        r"/etc/passwd",
        r"/windows/system32",

        # expanded
        r"\.\.\\",
        r"\.\./",
        r"\.\.\/",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"%252e%252e",
        r"/proc/self/environ",
        r"/boot.ini",
        r"c:\\windows",
        r"\.\.%2f",

        # additional sensitive files
        r"/etc/shadow",
        r"/etc/hosts",
        r"/root/\.ssh",
        r"\.ssh/id_rsa",
        r"/proc/self/cmdline",
        r"/var/log/auth\.log",
        r"win\.ini",
        r"boot\.ini",
    ],

    "File_Inclusion": [
        r"php://",
        r"file://",
        r"include\(",

        # expanded
        r"require\(",
        r"include_once\(",
        r"require_once\(",
        r"data://",
        r"expect://",
        r"zip://",
        r"phar://",
        r"php:\/\/input",

        # wrappers
        r"php:\/\/filter",
        r"php:\/\/data",
        r"compress\.zlib://",
        r"glob://",
        r"ssh2://",
        r"ogg://",
    ],

    "SSRF": [
        r"http://127\.0\.0\.1",
        r"localhost",
        r"169\.254\.169\.254",

        # expanded
        r"0\.0\.0\.0",
        r"http://0\.0\.0\.0",
        r"127\.0\.0\.1",
        r"http://localhost",
        r"http://\[::1\]",
        r"metadata",
        r"internal",

        # cloud metadata endpoints
        r"169\.254\.169\.254/latest/meta-data",
        r"metadata\.google\.internal",
        r"169\.254\.169\.254/metadata",
        r"100\.100\.100\.200",
        r"metadata\.azure\.com",

        # URL schemes that reach internal services
        r"gopher://",
        r"dict://",
        r"ftp://127",
        r"sftp://127",
    ],

    "Open_Redirect": [
        r"[?&]url=https?://",
        r"[?&]redirect=https?://",
        r"[?&]next=https?://",
        r"[?&]return=https?://",
        r"[?&]returnurl=https?://",
        r"[?&]return_url=https?://",
        r"[?&]continue=https?://",
        r"[?&]dest=https?://",
        r"[?&]destination=https?://",
        r"[?&]goto=https?://",
        r"[?&]target=https?://",
        r"[?&]redir=https?://",
        r"[?&]callback=https?://",
    ],

    "CRLF_Injection": [
        r"%0d%0a",
        r"%0D%0A",
        r"\r\n(?:set-cookie|location|content-length|transfer-encoding)\s*:",
        r"\n(?:set-cookie|location)\s*:",
        r"%0a(?:set-cookie|location)",
        r"%0d(?:set-cookie|location)",
        r"\\r\\n",
    ],

    "Header_Injection": [
        r"content-length:\s*\d+",
        r"transfer-encoding:\s*chunked",
        r"x-forwarded-for:",
        r"x-originating-ip:",
        r"x-remote-ip:",
        r"x-rewrite-url:",
        r"x-forwarded-host:",
        r"x-host:",
    ],

    "Deserialization": [
        # Java serialization magic bytes (base64-encoded: rO0AB...)
        r"rO0AB[A-Za-z0-9+/]",
        r"\xac\xed\x00\x05",
        r"java\.io\.Serializable",
        r"java\.lang\.Runtime",
        r"java\.lang\.ProcessBuilder",

        # PHP serialization
        r"O:\d+:\"[A-Za-z_]+",
        r"a:\d+:\{",

        # Python pickle
        r"__reduce__",
        r"cos\nsystem",
        r"c__builtin__\neval",
        r"\(lp\d+",
        r"\x80\x04\x95",

        # .NET
        r"System\.Windows\.Data\.Object",
        r"System\.Data\.DataSet",
        r"ObjectStateFormatter",
        r"TypeConfuseDelegate",
        r"BinaryFormatter",

        # Ruby
        r"Marshal\.load",
        r"\!ruby/object",
    ],

    "Prototype_Pollution": [
        r"__proto__",
        r"__proto__\[",
        r"constructor\.prototype",
        r"prototype\[",
        r"\[__proto__\]",
        r"\bconstructor\b.*\bprototype\b",
        r"\$\{.*constructor.*prototype.*\}",
    ],

    "XXE": [
        r"<!doctype\s+\w+\s+\[",
        r"<!entity\s+\w+\s+system",
        r"<!entity\s+\w+\s+public",
        r"<!entity\s+%\s+\w+\s+system",
        r"<!entity\s+\w+\s+\"file://",
        r"<!entity\s+\w+\s+\"http://",
        r"<!entity\s+\w+\s+\"php://",
        r"<!entity\s+\w+\s+\"expect://",
        r"<!entity\s+\w+\s+\"gopher://",
        r"system\s+\"file://",
        r"<!doctype\s+\w+\s+system",
        r"external\s+entity",
    ],

    "XML_Bomb": [
        r"<!entity\s+lol\s+\"&\w+;",
        r"<!entity\s+\w+\s+\"&\w+;&\w+;",
        r"<!entity\s+\w+\s+\"&\w+;&\w+;&\w+;",
        r"<!entity\s+%\s+\w+\s+\"&\w+;",
    ],

    "GraphQL_Injection": [
        r"__schema\s*\{",
        r"__type\s*\(",
        r"__typename\s*\{",
        r"\{__schema",
        r"\{__type",
        r"introspectionquery",
        r"query\s+\w+\s*\{.*__schema",
    ],

    "JWT_Abuse": [
        r"\"alg\"\s*:\s*\"none\"",
        r"\"alg\"\s*:\s*\"none\"",
        r"alg=none",
        r"alg:none",
        r"\"typ\"\s*:\s*\"jwt\"\s*,\s*\"alg\"\s*:\s*\"none\"",
        r"eyj[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.",
    ],

    "Credential_Leak": [
        r"password=",
        r"passwd=",
        r"authorization:",

        # expanded
        r"api_key=",
        r"apikey=",
        r"secret=",
        r"token=",
        r"bearer\s+[a-z0-9\-\._]+",
        r"client_secret",
        r"aws_access_key",
        r"private_key",

        # more
        r"aws_secret",
        r"aws_session_token",
        r"github_token",
        r"gitlab_token",
        r"slack_token",
        r"stripe_key",
        r"twilio_",
        r"sendgrid_",
        r"-----begin\s+(?:rsa\s+)?private\s+key-----",
        r"-----begin\s+openssh\s+private\s+key-----",
        r"-----begin\s+ec\s+private\s+key-----",
    ],

    "Malware_Indicators": [
        r"powershell\s+-enc",
        r"base64,",
        r"wget\s+http",
        r"curl\s+http",

        # expanded
        r"Invoke-Expression",
        r"iex\s*\(",
        r"cmd\.exe",
        r"mshta",
        r"certutil",
        r"bitsadmin",
        r"nc\s+-e",
        r"reverse\s+shell",

        # webshell markers
        r"eval\s*\(\s*\$_POST",
        r"eval\s*\(\s*\$_GET",
        r"eval\s*\(\s*\$_REQUEST",
        r"system\s*\(\s*\$_",
        r"passthru\s*\(\s*\$_",
        r"shell_exec\s*\(\s*\$_",
        r"assert\s*\(\s*\$_",
        r"base64_decode\s*\(\s*\$_",
        r"<\?php.*eval",
        r"c99shell",
        r"r57shell",
        r"b374k",
        r"weevely",
    ],

    "Cryptomining": [
        r"stratum\+tcp://",
        r"stratum\+ssl://",
        r"xmrig",
        r"minerd",
        r"coinhive",
        r"cryptonight",
        r"monero",
        r"nicehash",
        r"minergate",
        r"supportxmr",
        r"minexmr",
        r"nanopool",
    ],

    "Phishing_Indicators": [
        r"paypal.*login",
        r"apple.*verify",
        r"microsoft.*account.*verify",
        r"secure.*update.*account",
        r"bit\.ly/",
        r"tinyurl\.com/",
        r"t\.co/",
        r"goo\.gl/",
        r"ow\.ly/",
        r"is\.gd/",
        r"buff\.ly/",
        r"rebrand\.ly/",
    ],

    "Scanning": [
        r"nmap",
        r"masscan",
        r"zmap",

        # expanded
        r"nikto",
        r"sqlmap",
        r"dirbuster",
        r"gobuster",
        r"wfuzz",
        r"whatweb",
        r"hydra",

        # more tools
        r"nuclei",
        r"ffuf",
        r"feroxbuster",
        r"wpscan",
        r"joomscan",
        r"acunetix",
        r"burpsuite",
        r"zaproxy",
        r"arachni",
    ],

    "Source_Disclosure": [
        r"\.git/config",
        r"\.git/HEAD",
        r"\.git/refs",
        r"\.svn/entries",
        r"\.svn/wc\.db",
        r"\.hg/",
        r"\.bzr/",
        r"\.DS_Store",
        r"\.env\b",
        r"\.env\.local",
        r"\.env\.production",
        r"\.env\.development",
        r"\.aws/credentials",
        r"\.npmrc",
        r"\.dockercfg",
        r"\.htpasswd",
        r"web\.config",
        r"phpinfo\.php",
        r"\.php\.bak",
        r"\.php\.old",
        r"\.php\.swp",
        r"\.sql\.gz",
        r"\.tar\.gz",
        r"database\.yml",
        r"database\.php",
        r"config\.php\.bak",
        r"backup\.sql",
        r"dump\.sql",
    ],

    "Enumeration": [
        r"/admin\b",
        r"/wp-admin",
        r"/wp-login\.php",
        r"/wp-content",
        r"/phpmyadmin",
        r"/pma/",
        r"/cpanel",
        r"/webmail",
        r"/manager/html",
        r"/solr/admin",
        r"/actuator",
        r"/actuator/env",
        r"/actuator/health",
        r"/api/v1/users",
        r"/api/v2/users",
        r"/swagger-ui",
        r"/api-docs",
        r"/v2/api-docs",
        r"/server-status",
        r"/server-info",
        r"/console",
        r"/jmx-console",
    ],

    "CSV_Injection": [
        r"^=\s*[\"']?cmd",
        r"^=\s*[\"']?HYPERLINK",
        r"^\+cmd",
        r"^-cmd",
        r"^@cmd",
        r"=cmd\|",
        r"=DDE\(",
        r"=IMPORTXML\(",
        r"=WEBSERVICE\(",
    ],

    "Binary_Exploit": [
        r"\x90\x90\x90",
        r"\xcc",

        # expanded
        r"\x41\x41\x41",
        r"A{100,}",
        r"\x90{10,}",
        r"\x00{2,}",
        r"\\x90",
        r"segfault",

        # format strings
        r"%n%n%n",
        r"%s%s%s%s%s",
        r"%x%x%x%x%x",

        # ROP / shellcode markers
        r"\\x90\\x90\\x90",
        r"\\x41\\x41\\x41",
    ],

    "Cloud_Metadata": [
        r"169\.254\.169\.254/latest/meta-data",
        r"169\.254\.169\.254/user-data",
        r"metadata\.google\.internal",
        r"metadata\.goog",
        r"metadata\.azure\.com",
        r"100\.100\.100\.200",
        r"169\.254\.170\.2",
    ],
}

compiled_patterns = {
    category: [re.compile(p, re.I) for p in patterns]
    for category, patterns in ATTACK_PATTERNS.items()
}

def recursive_url_decode(data, max_rounds=5):
    current = data

    for _ in range(max_rounds):
        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    return current


def decode_unicode_escapes(data):
    if "\\u" not in data and "\\x" not in data:
        return data
    try:
        return data.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except Exception:
        return data


def decode_base64(data):
    try:
        text = re.sub(r"\s+", "", data)

        if len(text) < 8:
            return data

        if len(text) % 4 != 0:
            return data

        decoded = base64.b64decode(text, validate=True)

        decoded_text = decoded.decode("utf-8", errors="ignore")

        printable = sum(c.isprintable() for c in decoded_text)

        if printable / max(len(decoded_text), 1) > 0.85:
            return decoded_text

    except Exception:
        pass

    return data


_MAX_PAYLOAD_VARIANTS = 64


def normalize_payload(payload):
    versions = set()
    queue = [payload]

    while queue and len(versions) < _MAX_PAYLOAD_VARIANTS:
        current = queue.pop()
        if current in versions:
            continue
        versions.add(current)
        candidates = [
            recursive_url_decode(current),
            html.unescape(current),
            decode_unicode_escapes(current),
            decode_base64(current),
        ]
        for candidate in candidates:
            if candidate not in versions and len(versions) < _MAX_PAYLOAD_VARIANTS:
                queue.append(candidate)

    return versions

def analyze_payload(payload):
    findings = set()

    if not payload:
        return []

    payload_versions = normalize_payload(payload)

    for decoded_payload in payload_versions:

        for category, patterns in compiled_patterns.items():

            for pattern in patterns:

                if pattern.search(decoded_payload):
                    findings.add(category)
                    break

    return sorted(findings)
