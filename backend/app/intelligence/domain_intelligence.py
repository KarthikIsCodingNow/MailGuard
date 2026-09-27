from __future__ import annotations
import socket
import ipaddress
import dns.resolver
from datetime import datetime, timezone

import requests


# ============================================================
# RDAP
# ============================================================

RDAP_BOOTSTRAP_URL = (
    "https://rdap.org/domain/"
)


def query_rdap(domain: str) -> dict:
    """
    Query RDAP for domain registration information.

    RDAP is used instead of relying on legacy WHOIS parsing.
    """

    result = {
        "available": False,
        "domain": domain,
        "registrar": None,
        "registration_date": None,
        "expiration_date": None,
        "status": [],
        "nameservers": [],
        "error": None
    }

    if not domain:
        result["error"] = "No domain supplied"
        return result

    try:

        response = requests.get(
            f"{RDAP_BOOTSTRAP_URL}{domain}",
            timeout=8,
            headers={
                "Accept": "application/rdap+json"
            }
        )

        if response.status_code != 200:

            result["error"] = (
                f"RDAP returned HTTP "
                f"{response.status_code}"
            )

            return result

        data = response.json()

        result["available"] = True

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        result["status"] = data.get(
            "status",
            []
        )

        # ----------------------------------------------------
        # Nameservers
        # ----------------------------------------------------

        nameservers = []

        for nameserver in data.get(
            "nameservers",
            []
        ):

            ldh_name = nameserver.get(
                "ldhName"
            )

            if ldh_name:
                nameservers.append(
                    ldh_name.lower()
                )

        result["nameservers"] = nameservers

        # ----------------------------------------------------
        # Events
        # ----------------------------------------------------

        for event in data.get(
            "events",
            []
        ):

            action = event.get(
                "eventAction"
            )

            event_date = event.get(
                "eventDate"
            )

            if not event_date:
                continue

            if action == "registration":
                result["registration_date"] = event_date

            elif action == "expiration":
                result["expiration_date"] = event_date

        # ----------------------------------------------------
        # Registrar
        # ----------------------------------------------------

        for entity in data.get(
            "entities",
            []
        ):

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" not in roles:
                continue

            vcard = entity.get(
                "vcardArray"
            )

            if not vcard:
                continue

            try:

                properties = vcard[1]

                for prop in properties:

                    if (
                        len(prop) >= 4
                        and prop[0] == "fn"
                    ):

                        result["registrar"] = (
                            prop[3]
                        )

                        break

            except (
                IndexError,
                TypeError
            ):
                pass

            break

    except requests.RequestException as exc:

        result["error"] = (
            f"RDAP request failed: {exc}"
        )

    except ValueError as exc:

        result["error"] = (
            f"Invalid RDAP response: {exc}"
        )

    except Exception as exc:

        result["error"] = (
            f"RDAP analysis error: {exc}"
        )

    return result


# ============================================================
# DOMAIN AGE
# ============================================================

def calculate_domain_age(
    registration_date: str | None
) -> dict:
    """
    Calculate approximate domain age from
    an RDAP registration timestamp.
    """

    if not registration_date:

        return {
            "available": False,
            "age_days": None,
            "age_category": "UNKNOWN"
        }

    try:

        registration = datetime.fromisoformat(
            registration_date.replace(
                "Z",
                "+00:00"
            )
        )

        now = datetime.now(
            timezone.utc
        )

        age_days = (
            now - registration
        ).days

        if age_days < 30:
            category = "VERY_NEW"

        elif age_days < 90:
            category = "NEW"

        elif age_days < 365:
            category = "LESS_THAN_ONE_YEAR"

        else:
            category = "ESTABLISHED"

        return {
            "available": True,
            "age_days": max(
                age_days,
                0
            ),
            "age_category": category
        }

    except (
        ValueError,
        TypeError
    ):

        return {
            "available": False,
            "age_days": None,
            "age_category": "UNKNOWN"
        }


# ============================================================
# DNS RESOLUTION
# ============================================================

def resolve_domain(
    domain: str
) -> dict:
    """
    Resolve a domain to IPv4/IPv6 addresses.

    Uses the local operating-system resolver.
    """

    result = {
        "available": False,
        "a_records": [],
        "aaaa_records": [],
        "error": None
    }

    if not domain:

        result["error"] = (
            "No domain supplied"
        )

        return result

    try:

        addresses = socket.getaddrinfo(
            domain,
            None
        )

        ipv4 = set()
        ipv6 = set()

        for entry in addresses:

            address = entry[4][0]

            try:

                parsed_ip = ipaddress.ip_address(
                    address
                )

                if parsed_ip.version == 4:
                    ipv4.add(address)

                elif parsed_ip.version == 6:
                    ipv6.add(address)

            except ValueError:
                continue

        result["a_records"] = sorted(
            ipv4
        )

        result["aaaa_records"] = sorted(
            ipv6
        )

        result["available"] = True

    except socket.gaierror as exc:

        result["error"] = (
            f"DNS resolution failed: {exc}"
        )

    except Exception as exc:

        result["error"] = (
            f"DNS analysis error: {exc}"
        )

    return result


# ============================================================
# MX RECORD
# ============================================================

def resolve_mx(
    domain: str
) -> dict:
    """
    Resolve MX records.

    dnspython is used if installed.
    """

    result = {
        "available": False,
        "records": [],
        "error": None
    }

    try:

        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=5
        )

        records = []

        for answer in answers:

            records.append(
                {
                    "priority": answer.preference,
                    "exchange": str(
                        answer.exchange
                    ).rstrip(".")
                }
            )

        result["records"] = records
        result["available"] = True

    except ImportError:

        result["error"] = (
            "dnspython is not installed"
        )

    except Exception as exc:

        result["error"] = (
            f"MX lookup failed: {exc}"
        )

    return result


# ============================================================
# NS RECORD
# ============================================================

def resolve_ns(
    domain: str
) -> dict:
    """
    Resolve authoritative nameservers.
    """

    result = {
        "available": False,
        "records": [],
        "error": None
    }

    try:
        answers = dns.resolver.resolve(
            domain,
            "NS",
            lifetime=5
        )

        records = []

        for answer in answers:

            records.append(
                str(answer)
                .rstrip(".")
                .lower()
            )

        result["records"] = records
        result["available"] = True

    except ImportError:

        result["error"] = (
            "dnspython is not installed"
        )

    except Exception as exc:

        result["error"] = (
            f"NS lookup failed: {exc}"
        )

    return result


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def analyze_domain(
    domain: str
) -> dict:
    """
    Perform complete domain intelligence analysis.

    External enrichment failures are returned as
    unavailable rather than stopping the investigation.
    """

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if not domain:

        return {
            "domain": "",
            "status": "NO_DOMAIN"
        }

    # --------------------------------------------------------
    # RDAP
    # --------------------------------------------------------

    rdap = query_rdap(
        domain
    )

    # --------------------------------------------------------
    # Domain age
    # --------------------------------------------------------

    age = calculate_domain_age(
        rdap.get(
            "registration_date"
        )
    )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    dns = resolve_domain(
        domain
    )

    mx = resolve_mx(
        domain
    )

    ns = resolve_ns(
        domain
    )

    # --------------------------------------------------------
    # Combine IPs
    # --------------------------------------------------------

    ips = sorted(
        set(
            dns.get("a_records", [])
            + dns.get("aaaa_records", [])
        )
    )

    # --------------------------------------------------------
    # Basic infrastructure indicators
    # --------------------------------------------------------

    infrastructure_indicators = []

    if age["age_category"] == "VERY_NEW":

        infrastructure_indicators.append(
            "Domain registered less than 30 days ago"
        )

    elif age["age_category"] == "NEW":

        infrastructure_indicators.append(
            "Recently registered domain"
        )

    if not mx["records"]:

        infrastructure_indicators.append(
            "No MX records observed"
        )

    if not ips:

        infrastructure_indicators.append(
            "No A/AAAA resolution observed"
        )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    rdap_available = rdap.get(
        "available",
        False
    )

    dns_available = dns.get(
        "available",
        False
    )

    if rdap_available or dns_available:

        status = "ENRICHED"

    else:

        status = "PARTIAL"

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return {
        "domain": domain,

        "status": status,

        "rdap": rdap,

        "domain_age": age,

        "dns": dns,

        "mx": mx,

        "nameservers": ns,

        "resolved_ips": ips,

        "infrastructure_indicators": (
            infrastructure_indicators
        )
    }