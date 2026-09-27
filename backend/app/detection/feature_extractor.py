import re


URGENT_WORDS = [
    "urgent",
    "immediately",
    "as soon as possible",
    "action required",
    "important",
    "suspended",
    "suspension",
    "within",
    "deadline"
]

CREDENTIAL_WORDS = [
    "password",
    "verify your password",
    "login",
    "log in",
    "credential",
    "username",
    "account verification",
    "verify your account"
]

FINANCIAL_WORDS = [
    "payment",
    "invoice",
    "bank",
    "transfer",
    "wire",
    "money",
    "refund",
    "transaction"
]

THREAT_WORDS = [
    "suspended",
    "blocked",
    "terminated",
    "locked",
    "security alert",
    "unauthorized",
    "unusual activity"
]


def count_keywords(text: str, keywords: list[str]) -> int:
    """
    Count how many different suspicious keywords
    appear in the supplied text.
    """

    if not text:
        return 0

    text = text.lower()

    return sum(
        1 for keyword in keywords
        if keyword.lower() in text
    )


def extract_feature_vector(
    parsed_email: dict,
    header_evidence: dict,
    authentication_analysis: dict,
    received_chain: list,
    urls: list[str]
) -> dict:
    """
    Convert parsed email evidence into a structured
    feature vector for later threat scoring.
    """

    body = parsed_email.get("body", "")
    html_body = parsed_email.get("html_body", "")

    combined_text = f"{body}\n{html_body}"

    sender = header_evidence.get("sender") or ""
    reply_to = header_evidence.get("reply_to") or ""
    return_path = header_evidence.get("return_path") or ""
    subject = header_evidence.get("subject") or ""

    # --------------------------------------------------
    # AUTHENTICATION FEATURES
    # --------------------------------------------------

    spf_result = authentication_analysis["spf"]["result"]
    dkim_result = authentication_analysis["dkim"]["result"]
    dmarc_result = authentication_analysis["dmarc"]["result"]

    spf_fail = int(
        spf_result in ["fail", "softfail", "permerror"]
    )

    dkim_fail = int(
        dkim_result in ["fail", "permerror"]
    )

    dmarc_fail = int(
        dmarc_result in ["fail", "permerror"]
    )

    # --------------------------------------------------
    # SENDER FEATURES
    # --------------------------------------------------

    reply_to_present = int(bool(reply_to))

    return_path_present = int(bool(return_path))

    sender_reply_to_mismatch = 0

    if sender and reply_to:

        sender_domain = sender.split("@")[-1].strip(" >")
        reply_domain = reply_to.split("@")[-1].strip(" >")

        if sender_domain and reply_domain:
            sender_reply_to_mismatch = int(
                sender_domain.lower() != reply_domain.lower()
            )

    # --------------------------------------------------
    # CONTENT FEATURES
    # --------------------------------------------------

    urgency_count = count_keywords(
        combined_text,
        URGENT_WORDS
    )

    credential_request_count = count_keywords(
        combined_text,
        CREDENTIAL_WORDS
    )

    financial_request_count = count_keywords(
        combined_text,
        FINANCIAL_WORDS
    )

    threat_language_count = count_keywords(
        combined_text,
        THREAT_WORDS
    )

    # --------------------------------------------------
    # URL FEATURES
    # --------------------------------------------------

    url_count = len(urls)

    unique_url_count = len(set(urls))

    https_url_count = sum(
        1 for url in urls
        if url.lower().startswith("https://")
    )

    http_url_count = sum(
        1 for url in urls
        if url.lower().startswith("http://")
    )

    # --------------------------------------------------
    # ATTACHMENT FEATURES
    # --------------------------------------------------

    attachments = parsed_email.get(
        "attachments",
        []
    )

    attachment_count = len(attachments)

    executable_extensions = {
        ".exe",
        ".scr",
        ".js",
        ".vbs",
        ".ps1",
        ".bat",
        ".cmd",
        ".com",
        ".lnk",
        ".iso"
    }

    executable_attachment_count = 0

    for attachment in attachments:

        filename = (
            attachment.get("filename")
            or ""
        ).lower()

        if any(
            filename.endswith(extension)
            for extension in executable_extensions
        ):
            executable_attachment_count += 1

    # --------------------------------------------------
    # SMTP / INFRASTRUCTURE FEATURES
    # --------------------------------------------------

    received_hop_count = len(received_chain)

    ip_addresses = [
        hop.get("ip")
        for hop in received_chain
        if hop.get("ip")
    ]

    unique_ip_count = len(set(ip_addresses))

    # --------------------------------------------------
    # TEXT FEATURES
    # --------------------------------------------------

    text_length = len(combined_text)

    uppercase_characters = sum(
        1
        for character in combined_text
        if character.isupper()
    )

    alphabetic_characters = sum(
        1
        for character in combined_text
        if character.isalpha()
    )

    uppercase_ratio = 0.0

    if alphabetic_characters > 0:
        uppercase_ratio = round(
            uppercase_characters
            / alphabetic_characters,
            4
        )

    exclamation_count = combined_text.count("!")

    # --------------------------------------------------
    # FEATURE VECTOR
    # --------------------------------------------------

    features = {
        # Authentication
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,

        # Sender
        "reply_to_present": reply_to_present,
        "return_path_present": return_path_present,
        "sender_reply_to_mismatch": sender_reply_to_mismatch,

        # Content
        "urgency_count": urgency_count,
        "credential_request_count": credential_request_count,
        "financial_request_count": financial_request_count,
        "threat_language_count": threat_language_count,

        # URLs
        "url_count": url_count,
        "unique_url_count": unique_url_count,
        "https_url_count": https_url_count,
        "http_url_count": http_url_count,

        # Attachments
        "attachment_count": attachment_count,
        "executable_attachment_count": executable_attachment_count,

        # SMTP
        "received_hop_count": received_hop_count,
        "unique_ip_count": unique_ip_count,

        # Text
        "text_length": text_length,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count
    }

    return features