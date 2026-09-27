import re


# ============================================================
# COMMON CHARACTER SUBSTITUTIONS
# ============================================================

HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "@": "a",
}


# ============================================================
# SUSPICIOUS DOMAIN TOKENS
# ============================================================

SUSPICIOUS_TOKENS = [
    "login",
    "signin",
    "sign-in",
    "secure",
    "security",
    "verify",
    "verification",
    "account",
    "update",
    "support",
    "alert",
    "authentication",
    "confirm",
    "confirmation",
]


# ============================================================
# DOMAIN NORMALIZATION
# ============================================================

def normalize_domain(domain: str) -> str:
    """
    Normalize a domain before analysis.
    """

    if not domain:
        return ""

    domain = domain.strip().lower()

    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.rstrip(".")

    return domain


# ============================================================
# EMAIL DOMAIN EXTRACTION
# ============================================================

def extract_email_domain(email_address: str) -> str:
    """
    Extract the domain from an email address.

    Supports:

    security@example.com

    Display Name <security@example.com>
    """

    if not email_address:
        return ""

    match = re.search(
        r"@([A-Za-z0-9.-]+)",
        email_address
    )

    if not match:
        return ""

    return normalize_domain(
        match.group(1)
    )


# ============================================================
# DOMAIN LABELS
# ============================================================

def get_domain_labels(domain: str) -> list[str]:
    """
    Split a domain into labels.

    Example:

    mail.example.com

    ->
    ['mail', 'example', 'com']
    """

    domain = normalize_domain(domain)

    if not domain:
        return []

    return domain.split(".")


# ============================================================
# PRIMARY DOMAIN LABEL
# ============================================================

def get_brand_label(domain: str) -> str:
    """
    Extract the registrable-domain label.

    Example:

    micros0ft-security.example

    ->
    micros0ft-security
    """

    labels = get_domain_labels(domain)

    if len(labels) < 2:
        return labels[0] if labels else ""

    return labels[-2]


# ============================================================
# DOMAIN TOKENIZATION
# ============================================================

def tokenize_domain_label(
    domain_label: str
) -> list[str]:
    """
    Split a domain label into meaningful tokens.

    Example:

    micros0ft-security-alert

    ->
    ['micros0ft', 'security', 'alert']
    """

    if not domain_label:
        return []

    return [
        token
        for token in re.split(
            r"[-_.]+",
            domain_label.lower()
        )
        if token
    ]


# ============================================================
# LEVENSHTEIN DISTANCE
# ============================================================

def levenshtein_distance(
    a: str,
    b: str
) -> int:
    """
    Calculate Levenshtein edit distance.
    """

    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    previous_row = list(
        range(len(b) + 1)
    )

    for i, char_a in enumerate(
        a,
        start=1
    ):

        current_row = [i]

        for j, char_b in enumerate(
            b,
            start=1
        ):

            insertion = (
                current_row[j - 1] + 1
            )

            deletion = (
                previous_row[j] + 1
            )

            substitution = (
                previous_row[j - 1]
                + (char_a != char_b)
            )

            current_row.append(
                min(
                    insertion,
                    deletion,
                    substitution
                )
            )

        previous_row = current_row

    return previous_row[-1]


# ============================================================
# SIMILARITY
# ============================================================

def similarity_percentage(
    a: str,
    b: str
) -> float:
    """
    Convert Levenshtein distance into
    a normalized similarity percentage.
    """

    if not a or not b:
        return 0.0

    distance = levenshtein_distance(
        a,
        b
    )

    max_length = max(
        len(a),
        len(b)
    )

    similarity = (
        1 - distance / max_length
    ) * 100

    return round(
        max(0.0, similarity),
        2
    )


# ============================================================
# HOMOGLYPH NORMALIZATION
# ============================================================

def normalize_homoglyph_characters(
    value: str
) -> str:
    """
    Replace common character substitutions.

    Example:

    micros0ft

    becomes:

    microsoft
    """

    if not value:
        return ""

    normalized = []

    for character in value.lower():

        normalized.append(
            HOMOGLYPH_MAP.get(
                character,
                character
            )
        )

    return "".join(
        normalized
    )


# ============================================================
# HOMOGLYPH DETECTION
# ============================================================

def detect_homoglyphs(
    domain: str
) -> list[dict]:
    """
    Detect common character substitutions.
    """

    findings = []

    domain = normalize_domain(
        domain
    )

    for character in domain:

        if character in HOMOGLYPH_MAP:

            findings.append(
                {
                    "character": character,
                    "possible_original": (
                        HOMOGLYPH_MAP[
                            character
                        ]
                    ),
                    "type": "character_substitution"
                }
            )

    return findings


# ============================================================
# PUNYCODE DETECTION
# ============================================================

def detect_punycode(
    domain: str
) -> bool:
    """
    Detect IDN/Punycode labels.
    """

    labels = get_domain_labels(
        domain
    )

    return any(
        label.startswith("xn--")
        for label in labels
    )


# ============================================================
# SUSPICIOUS TOKEN DETECTION
# ============================================================

def detect_suspicious_tokens(
    domain: str
) -> list[str]:
    """
    Detect impersonation-related tokens.
    """

    domain = normalize_domain(
        domain
    )

    findings = []

    for token in SUSPICIOUS_TOKENS:

        if token in domain:

            findings.append(
                token
            )

    return findings


# ============================================================
# BRAND TOKEN COMPARISON
# ============================================================

def compare_brand_tokens(
    domain_label: str,
    legitimate_label: str
) -> dict:
    """
    Compare individual domain tokens against
    a legitimate brand.

    Example:

    domain:
        micros0ft-security

    legitimate:
        microsoft

    token:
        micros0ft

    normalized:
        microsoft

    result:
        100% similarity
    """

    domain_tokens = tokenize_domain_label(
        domain_label
    )

    legitimate_label = (
        legitimate_label.lower()
    )

    best_token = None
    best_similarity = 0.0
    best_normalized_similarity = 0.0
    substitution_detected = False

    for token in domain_tokens:

        direct_similarity = (
            similarity_percentage(
                token,
                legitimate_label
            )
        )

        normalized_token = (
            normalize_homoglyph_characters(
                token
            )
        )

        normalized_brand = (
            normalize_homoglyph_characters(
                legitimate_label
            )
        )

        normalized_similarity = (
            similarity_percentage(
                normalized_token,
                normalized_brand
            )
        )

        effective_similarity = max(
            direct_similarity,
            normalized_similarity
        )

        if effective_similarity > best_similarity:

            best_similarity = (
                effective_similarity
            )

            best_token = token

            best_normalized_similarity = (
                normalized_similarity
            )

            substitution_detected = (
                normalized_token
                == normalized_brand
                and token != legitimate_label
            )

    return {
        "best_token": best_token,
        "similarity": best_similarity,
        "normalized_similarity": (
            best_normalized_similarity
        ),
        "substitution_detected": (
            substitution_detected
        )
    }


# ============================================================
# BRAND EMBEDDING
# ============================================================

def detect_brand_embedding(
    domain_label: str,
    legitimate_label: str
) -> dict:
    """
    Detect a legitimate brand embedded in
    an extended domain label.

    Example:

    microsoft-security

    contains:

    microsoft
    """

    domain_label = domain_label.lower()
    legitimate_label = legitimate_label.lower()

    if (
        legitimate_label
        and legitimate_label != domain_label
        and legitimate_label in domain_label
    ):

        return {
            "detected": True,
            "type": "brand_embedded_in_extended_label"
        }

    return {
        "detected": False,
        "type": None
    }


# ============================================================
# MAIN LOOKALIKE ANALYZER
# ============================================================

def analyze_lookalike_domain(
    domain: str,
    legitimate_domains: list[str]
) -> dict:
    """
    Analyze a domain against legitimate reference
    domains.

    This is a heuristic assessment and does not
    prove malicious ownership.
    """

    domain = normalize_domain(
        domain
    )

    if not domain:

        return {
            "domain": "",
            "is_lookalike": False,
            "risk": "UNKNOWN",
            "similarity": 0.0,
            "matched_domain": None,
            "matched_brand": None,
            "matched_token": None,
            "domain_label": "",
            "homoglyph_findings": [],
            "punycode_detected": False,
            "suspicious_tokens": [],
            "substitution_detected": False,
            "brand_embedding": {
                "detected": False,
                "type": None
            }
        }

    domain_label = get_brand_label(
        domain
    )

    best_match = None
    best_brand = None
    best_token = None

    best_similarity = 0.0
    best_normalized_similarity = 0.0

    substitution_detected = False

    # --------------------------------------------------------
    # Compare against legitimate domains
    # --------------------------------------------------------

    for legitimate_domain in legitimate_domains:

        legitimate_domain = normalize_domain(
            legitimate_domain
        )

        legitimate_brand = get_brand_label(
            legitimate_domain
        )

        comparison = compare_brand_tokens(
            domain_label,
            legitimate_brand
        )

        similarity = comparison[
            "similarity"
        ]

        if similarity > best_similarity:

            best_similarity = similarity

            best_normalized_similarity = (
                comparison[
                    "normalized_similarity"
                ]
            )

            best_match = (
                legitimate_domain
            )

            best_brand = (
                legitimate_brand
            )

            best_token = (
                comparison[
                    "best_token"
                ]
            )

            substitution_detected = (
                comparison[
                    "substitution_detected"
                ]
            )

    # --------------------------------------------------------
    # Additional indicators
    # --------------------------------------------------------

    homoglyph_findings = (
        detect_homoglyphs(
            domain
        )
    )

    punycode_detected = (
        detect_punycode(
            domain
        )
    )

    suspicious_tokens = (
        detect_suspicious_tokens(
            domain
        )
    )

    brand_embedding = (
        detect_brand_embedding(
            domain_label,
            best_brand or ""
        )
    )

    # --------------------------------------------------------
    # Determine lookalike
    # --------------------------------------------------------

    exact_domain_match = (
        domain == best_match
    )

    high_similarity = (
        best_similarity >= 80
    )

    strong_substitution = (
        substitution_detected
        and best_normalized_similarity >= 90
    )

    suspicious_structure = (
        len(suspicious_tokens) > 0
        or brand_embedding["detected"]
        or len(homoglyph_findings) > 0
        or punycode_detected
    )

    is_lookalike = (
        not exact_domain_match
        and (
            high_similarity
            or strong_substitution
            or (
                brand_embedding["detected"]
                and suspicious_structure
            )
        )
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if is_lookalike:

        if (
            punycode_detected
            or substitution_detected
        ):
            risk = "HIGH"

        elif (
            brand_embedding["detected"]
            and suspicious_tokens
        ):
            risk = "HIGH"

        else:
            risk = "MEDIUM"

    else:

        risk = "LOW"

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {
        "domain": domain,

        "is_lookalike": is_lookalike,

        "risk": risk,

        "similarity": best_similarity,

        "homoglyph_similarity": (
            best_normalized_similarity
        ),

        "matched_domain": best_match,

        "matched_brand": best_brand,

        "matched_token": best_token,

        "domain_label": domain_label,

        "homoglyph_findings": (
            homoglyph_findings
        ),

        "punycode_detected": (
            punycode_detected
        ),

        "suspicious_tokens": (
            suspicious_tokens
        ),

        "substitution_detected": (
            substitution_detected
        ),

        "brand_embedding": (
            brand_embedding
        )
    }