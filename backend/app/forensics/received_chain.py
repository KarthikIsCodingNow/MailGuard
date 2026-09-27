import ipaddress
import re
from email.utils import parsedate_to_datetime


# ============================================================
# IP EXTRACTION
# ============================================================

IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"\b"
)


# ============================================================
# EXTRACT IPS
# ============================================================

def extract_ips(text: str) -> list[str]:
    """
    Extract IPv4 addresses from a Received header.
    """

    if not text:
        return []

    return IP_PATTERN.findall(text)


# ============================================================
# CLASSIFY IP
# ============================================================

def classify_ip(ip: str) -> dict:
    """
    Classify an IP address as public/private/reserved/etc.
    """

    try:

        address = ipaddress.ip_address(ip)

        return {
            "ip": ip,
            "version": address.version,
            "private": address.is_private,
            "public": address.is_global,
            "reserved": address.is_reserved,
            "loopback": address.is_loopback,
            "multicast": address.is_multicast,
            "type": (
                "PRIVATE"
                if address.is_private
                else "PUBLIC"
                if address.is_global
                else "RESERVED"
                if address.is_reserved
                else "SPECIAL"
            )
        }

    except ValueError:

        return {
            "ip": ip,
            "version": None,
            "private": False,
            "public": False,
            "reserved": False,
            "loopback": False,
            "multicast": False,
            "type": "INVALID"
        }


# ============================================================
# PARSE RECEIVED HEADER
# ============================================================

def parse_received_header(
    received_header: str,
    index: int
) -> dict:
    """
    Parse one SMTP Received header.

    Example:

    from unknown (192.0.2.55)
    by mail.example.org with ESMTP;
    Mon, 31 Aug 2026 10:19:40 +0530
    """

    text = (
        received_header
        or ""
    ).strip()

    # --------------------------------------------------------
    # Extract IPs
    # --------------------------------------------------------

    ips = extract_ips(text)

    ip = (
        ips[0]
        if ips
        else None
    )

    # --------------------------------------------------------
    # Extract FROM host
    # --------------------------------------------------------

    from_match = re.search(
        r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s*;|$)",
        text,
        flags=re.IGNORECASE
    )

    from_host = (
        from_match.group(1).strip()
        if from_match
        else None
    )

    # --------------------------------------------------------
    # Extract BY host
    # --------------------------------------------------------

    by_match = re.search(
        r"\bby\s+(.+?)(?=\s+with\s+|\s+via\s+|\s+id\s+|\s*;|$)",
        text,
        flags=re.IGNORECASE
    )

    by_host = (
        by_match.group(1).strip()
        if by_match
        else None
    )

    # --------------------------------------------------------
    # Remove IP from host display where useful
    # --------------------------------------------------------

    if from_host:

        from_host = re.sub(
            r"\s*\(\s*\d{1,3}(?:\.\d{1,3}){3}\s*\)",
            "",
            from_host
        ).strip()

    # --------------------------------------------------------
    # Extract timestamp
    # --------------------------------------------------------

    timestamp = None

    if ";" in text:

        date_part = text.split(
            ";",
            1
        )[1].strip()

        try:

            timestamp = (
                parsedate_to_datetime(
                    date_part
                ).isoformat()
            )

        except Exception:

            timestamp = date_part

    # --------------------------------------------------------
    # IP classification
    # --------------------------------------------------------

    ip_info = (
        classify_ip(ip)
        if ip
        else None
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "hop": index,
        "raw": text,
        "from": from_host,
        "by": by_host,
        "ip": ip,
        "timestamp": timestamp,
        "ip_classification": ip_info
    }


# ============================================================
# NORMALIZE INPUT
# ============================================================

def normalize_received_headers(
    received_headers
) -> list[str]:
    """
    Normalize Received headers.

    Supports:

    1. list[str]
    2. single str
    3. None
    """

    if not received_headers:
        return []

    # --------------------------------------------------------
    # Already a list
    # --------------------------------------------------------

    if isinstance(
        received_headers,
        list
    ):

        return [
            str(header).strip()
            for header in received_headers
            if str(header).strip()
        ]

    # --------------------------------------------------------
    # Single string
    # --------------------------------------------------------

    if isinstance(
        received_headers,
        str
    ):

        text = received_headers.strip()

        if not text:
            return []

        # ----------------------------------------------------
        # Handle multiple Received headers concatenated
        # together.
        #
        # Split when a new "from" sequence begins.
        # ----------------------------------------------------

        parts = re.split(
            r"(?=\bfrom\s+)",
            text,
            flags=re.IGNORECASE
        )

        return [
            part.strip()
            for part in parts
            if part.strip()
        ]

    return []


# ============================================================
# RECONSTRUCT RECEIVED CHAIN
# ============================================================

def reconstruct_received_chain(
    received_headers
) -> list[dict]:
    """
    Reconstruct the SMTP/Received path.

    The Received header order in an email normally represents
    the most recent hop first. Therefore the returned list
    preserves the original header order while assigning
    sequential hop numbers.

    IMPORTANT:
    Received headers can contain attacker-controlled data.
    This function extracts evidence; it does NOT establish
    attacker identity or physical origin.
    """

    headers = normalize_received_headers(
        received_headers
    )

    if not headers:
        return []

    chain = []

    for index, header in enumerate(
        headers,
        start=1
    ):

        hop = parse_received_header(
            header,
            index
        )

        chain.append(hop)

    return chain


# ============================================================
# GET UNIQUE IPS
# ============================================================

def get_unique_ips(
    received_chain: list[dict]
) -> list[str]:
    """
    Return unique IP addresses from the
    reconstructed Received chain.
    """

    ips = []

    for hop in received_chain:

        ip = hop.get("ip")

        if ip and ip not in ips:

            ips.append(ip)

    return ips