import re

ATTACK_PATTERNS = {
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
    ]
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
    try:
        return data.encode("utf-8").decode("unicode_escape")
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


def normalize_payload(payload):

    versions = set()
    queue = [payload]

    while queue:
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
            if candidate not in versions:
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
