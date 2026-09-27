import re
from urllib.parse import urlparse


# ============================================================
# SUSPICIOUS URL TOKENS
# ============================================================

SUSPICIOUS_TOKENS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "password",
    "credential",
    "update",
    "confirm",
    "authentication",
    "reset",
    "unlock",
]


# ============================================================
# URL SHORTENERS
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
}


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".shop",
    ".work",
    ".live",
    ".support",
    ".country",
}


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(hostname: str) -> bool:
    """
    Determine whether the URL hostname is an IPv4 address.
    """

    if not hostname:
        return False

    ipv4_pattern = (
        r"^(25[0-5]|"
        r"2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|"
        r"2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|"
        r"2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|"
        r"2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)$"
    )

    return bool(
        re.match(
            ipv4_pattern,
            hostname
        )
    )


# ============================================================
# PUNYCODE DETECTION
# ============================================================

def contains_punycode(hostname: str) -> bool:
    """
    Detect internationalized domain labels
    represented using xn--.
    """

    if not hostname:
        return False

    return any(
        label.startswith("xn--")
        for label in hostname.lower().split(".")
    )


# ============================================================
# SUBDOMAIN DEPTH
# ============================================================

def calculate_subdomain_depth(
    hostname: str
) -> int:
    """
    Estimate subdomain depth.

    Example:

    login.security.example.com

    returns 2.
    """

    if not hostname:
        return 0

    labels = hostname.split(".")

    if len(labels) <= 2:
        return 0

    return len(labels) - 2


# ============================================================
# SUSPICIOUS TOKEN DETECTION
# ============================================================

def detect_suspicious_tokens(
    url: str
) -> list[str]:
    """
    Detect phishing-related tokens in the
    URL itself.
    """

    url_lower = url.lower()

    return [
        token
        for token in SUSPICIOUS_TOKENS
        if token in url_lower
    ]


# ============================================================
# ENCODED CHARACTER DETECTION
# ============================================================

def detect_encoded_characters(
    url: str
) -> bool:
    """
    Detect percent-encoded characters.

    Example:

    %2F
    %3D
    %40
    """

    return bool(
        re.search(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )


# ============================================================
# MULTIPLE @ DETECTION
# ============================================================

def detect_at_symbol(
    url: str
) -> bool:
    """
    Detect an @ symbol in a URL.

    Attackers can sometimes abuse this
    to obscure the actual destination.
    """

    return "@" in url


# ============================================================
# URL SHORTENER DETECTION
# ============================================================

def detect_url_shortener(
    hostname: str
) -> bool:
    """
    Detect common URL shortening services.
    """

    if not hostname:
        return False

    hostname = hostname.lower()

    return hostname in URL_SHORTENERS


# ============================================================
# SUSPICIOUS TLD DETECTION
# ============================================================

def detect_suspicious_tld(
    hostname: str
) -> bool:
    """
    Detect selected TLDs that may warrant
    additional investigation.

    This is only a heuristic.
    A suspicious TLD does NOT mean
    the domain is malicious.
    """

    if not hostname:
        return False

    hostname = hostname.lower()

    return any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )


# ============================================================
# URL PARSING
# ============================================================

def parse_url(url: str) -> dict:
    """
    Parse a URL safely without making a network request.
    """

    if not url:
        return {
            "url": "",
            "valid": False
        }

    url = url.strip()

    try:

        parsed = urlparse(url)

    except ValueError:

        return {
            "url": url,
            "valid": False
        }

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    try:
        port = parsed.port

    except ValueError:
        port = None

    return {
        "url": url,

        "valid": bool(
            parsed.scheme
            and hostname
        ),

        "scheme": (
            parsed.scheme.lower()
            if parsed.scheme
            else ""
        ),

        "hostname": hostname,

        "port": port,

        "path": parsed.path,

        "query": parsed.query,

        "fragment": parsed.fragment
    }


# ============================================================
# SINGLE URL ANALYSIS
# ============================================================

def analyze_url(
    url: str
) -> dict:
    """
    Perform static URL intelligence analysis.

    No network request is made.
    """

    parsed = parse_url(url)

    if not parsed.get("valid"):

        return {
            **parsed,
            "url_length": len(url),
            "is_ip_address": False,
            "punycode_detected": False,
            "subdomain_depth": 0,
            "suspicious_tokens": [],
            "encoded_characters": False,
            "at_symbol": False,
            "url_shortener": False,
            "suspicious_tld": False,
            "risk_indicators": []
        }

    hostname = parsed["hostname"]

    suspicious_tokens = (
        detect_suspicious_tokens(
            url
        )
    )

    ip_based = is_ip_address(
        hostname
    )

    punycode = contains_punycode(
        hostname
    )

    subdomain_depth = (
        calculate_subdomain_depth(
            hostname
        )
    )

    encoded = (
        detect_encoded_characters(
            url
        )
    )

    at_symbol = (
        detect_at_symbol(
            url
        )
    )

    shortener = (
        detect_url_shortener(
            hostname
        )
    )

    suspicious_tld = (
        detect_suspicious_tld(
            hostname
        )
    )

    # --------------------------------------------------------
    # Risk indicators
    # --------------------------------------------------------

    risk_indicators = []

    if parsed["scheme"] == "http":

        risk_indicators.append(
            "Unencrypted HTTP URL"
        )

    if ip_based:

        risk_indicators.append(
            "IP-based URL"
        )

    if punycode:

        risk_indicators.append(
            "Punycode domain"
        )

    if subdomain_depth >= 3:

        risk_indicators.append(
            f"Deep subdomain structure ({subdomain_depth})"
        )

    if suspicious_tokens:

        risk_indicators.append(
            "Suspicious URL keywords: "
            + ", ".join(
                suspicious_tokens
            )
        )

    if encoded:

        risk_indicators.append(
            "Percent-encoded characters detected"
        )

    if at_symbol:

        risk_indicators.append(
            "URL contains @ symbol"
        )

    if shortener:

        risk_indicators.append(
            "URL shortener detected"
        )

    if suspicious_tld:

        risk_indicators.append(
            "Potentially suspicious TLD"
        )

    # --------------------------------------------------------
    # Static risk score
    # --------------------------------------------------------

    score = 0

    if parsed["scheme"] == "http":
        score += 10

    if ip_based:
        score += 20

    if punycode:
        score += 20

    if subdomain_depth >= 3:
        score += 10

    if suspicious_tokens:
        score += min(
            20,
            len(suspicious_tokens) * 5
        )

    if encoded:
        score += 10

    if at_symbol:
        score += 15

    if shortener:
        score += 10

    if suspicious_tld:
        score += 5

    score = min(
        score,
        100
    )

    if score >= 60:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    elif score > 0:

        risk = "LOW"

    else:

        risk = "MINIMAL"

    # --------------------------------------------------------
    # Return intelligence
    # --------------------------------------------------------

    return {
        **parsed,

        "url_length": len(url),

        "is_ip_address": ip_based,

        "punycode_detected": punycode,

        "subdomain_depth": subdomain_depth,

        "suspicious_tokens": suspicious_tokens,

        "encoded_characters": encoded,

        "at_symbol": at_symbol,

        "url_shortener": shortener,

        "suspicious_tld": suspicious_tld,

        "risk_score": score,

        "risk": risk,

        "risk_indicators": risk_indicators
    }


# ============================================================
# ANALYZE ALL URLS
# ============================================================

def analyze_urls(
    urls: list[str]
) -> list[dict]:
    """
    Analyze every extracted URL.
    """

    if not urls:
        return []

    return [
        analyze_url(url)
        for url in urls
    ]